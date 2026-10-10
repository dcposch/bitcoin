// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/slhdsa.h>

#include <crypto/common.h>
#include <crypto/hmac_sha256.h>

#include <algorithm>
#include <cassert>
#include <cstring>

using namespace slhdsa;

namespace slhdsa_test {
namespace {

using Node = std::array<unsigned char, N>;

/** PRF(PK.seed, SK.seed, ADRS). It has the same form as F. */
Node Prf(const HashContext& ctx, const Address& adrs, const Seed& sk_seed)
{
    Node out;
    ctx.Hash(adrs, sk_seed, out);
    return out;
}

/** Algorithm 5: chain(X, i, s, PK.seed, ADRS). */
Node Chain(const HashContext& ctx, Address& adrs, Node x, uint32_t start, uint32_t steps)
{
    for (uint32_t j = start; j < start + steps; ++j) {
        adrs.SetHashAddress(j);
        ctx.Hash(adrs, x, x);
    }
    return x;
}

Node WotsSecret(const HashContext& ctx, const Address& adrs, const Seed& sk_seed, uint32_t chain)
{
    Address sk_adrs{adrs};
    sk_adrs.SetTypeAndClear(Address::WOTS_PRF);
    sk_adrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
    sk_adrs.SetChainAddress(chain);
    return Prf(ctx, sk_adrs, sk_seed);
}

/** Algorithm 6: wots_pkGen. */
Node WotsPkGen(const HashContext& ctx, Address& adrs, const Seed& sk_seed)
{
    unsigned char tmp[LEN * N];
    for (uint32_t i = 0; i < LEN; ++i) {
        adrs.SetChainAddress(i);
        const Node pk_i{Chain(ctx, adrs, WotsSecret(ctx, adrs, sk_seed, i), 0, W - 1)};
        std::memcpy(tmp + i * N, pk_i.data(), N);
    }
    Address pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(Address::WOTS_PK);
    pk_adrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
    Node pk;
    ctx.Hash(pk_adrs, tmp, pk);
    return pk;
}

Node HashPair(const HashContext& ctx, const Address& adrs, const Node& left, const Node& right)
{
    unsigned char buf[2 * N];
    std::memcpy(buf, left.data(), N);
    std::memcpy(buf + N, right.data(), N);
    Node out;
    ctx.Hash(adrs, buf, out);
    return out;
}

/** Algorithm 9: xmss_node. The recursion depth is at most HP. */
// NOLINTNEXTLINE(misc-no-recursion)
Node XmssNode(const HashContext& ctx, Address& adrs, const Seed& sk_seed, uint32_t i, uint32_t z)
{
    if (z == 0) {
        adrs.SetTypeAndClear(Address::WOTS_HASH);
        adrs.SetKeyPairAddress(i);
        return WotsPkGen(ctx, adrs, sk_seed);
    }
    const Node left{XmssNode(ctx, adrs, sk_seed, 2 * i, z - 1)};
    const Node right{XmssNode(ctx, adrs, sk_seed, 2 * i + 1, z - 1)};
    adrs.SetTypeAndClear(Address::TREE);
    adrs.SetTreeHeight(z);
    adrs.SetTreeIndex(i);
    return HashPair(ctx, adrs, left, right);
}

/** Algorithm 10: xmss_sign. */
void XmssSign(const HashContext& ctx, Address& adrs, const Seed& sk_seed, const Node& msg, uint32_t idx, unsigned char* out)
{
    for (uint32_t j = 0; j < HP; ++j) {
        const Node auth{XmssNode(ctx, adrs, sk_seed, (idx >> j) ^ 1, j)};
        std::memcpy(out + (LEN + j) * N, auth.data(), N);
    }
    adrs.SetTypeAndClear(Address::WOTS_HASH);
    adrs.SetKeyPairAddress(idx);
    // Algorithm 7: wots_sign.
    const auto digits{detail::WotsDigits(msg)};
    for (uint32_t i = 0; i < LEN; ++i) {
        adrs.SetChainAddress(i);
        const Node s{Chain(ctx, adrs, WotsSecret(ctx, adrs, sk_seed, i), 0, digits[i])};
        std::memcpy(out + i * N, s.data(), N);
    }
}

Node ForsSecret(const HashContext& ctx, const Address& adrs, const Seed& sk_seed, uint32_t idx)
{
    Address sk_adrs{adrs};
    sk_adrs.SetTypeAndClear(Address::FORS_PRF);
    sk_adrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
    sk_adrs.SetTreeIndex(idx);
    return Prf(ctx, sk_adrs, sk_seed);
}

/** Algorithm 15: fors_node. The recursion depth is at most A. */
// NOLINTNEXTLINE(misc-no-recursion)
Node ForsNode(const HashContext& ctx, Address& adrs, const Seed& sk_seed, uint32_t i, uint32_t z)
{
    if (z == 0) {
        const Node sk{ForsSecret(ctx, adrs, sk_seed, i)};
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex(i);
        Node out;
        ctx.Hash(adrs, sk, out);
        return out;
    }
    const Node left{ForsNode(ctx, adrs, sk_seed, 2 * i, z - 1)};
    const Node right{ForsNode(ctx, adrs, sk_seed, 2 * i + 1, z - 1)};
    adrs.SetTreeHeight(z);
    adrs.SetTreeIndex(i);
    return HashPair(ctx, adrs, left, right);
}

uint32_t ChainSteps(std::span<const unsigned char, N> msg)
{
    uint32_t steps{0};
    for (uint32_t d : detail::WotsDigits(msg)) steps += W - 1 - d;
    return steps;
}

std::vector<unsigned char> PureMessage(std::span<const unsigned char> msg, std::span<const unsigned char> ctx)
{
    assert(ctx.size() <= MAX_CONTEXT_SIZE);
    std::vector<unsigned char> out{0, static_cast<unsigned char>(ctx.size())};
    out.insert(out.end(), ctx.begin(), ctx.end());
    out.insert(out.end(), msg.begin(), msg.end());
    return out;
}

} // namespace

std::array<unsigned char, PUBLIC_KEY_SIZE> SecretKey::PubKey() const
{
    std::array<unsigned char, PUBLIC_KEY_SIZE> pk;
    std::copy(pk_seed.begin(), pk_seed.end(), pk.begin());
    std::copy(pk_root.begin(), pk_root.end(), pk.begin() + N);
    return pk;
}

SecretKey KeyGen(const Seed& sk_seed, const Seed& sk_prf, const Seed& pk_seed)
{
    SecretKey key{sk_seed, sk_prf, pk_seed, {}};
    const HashContext ctx{pk_seed};
    Address adrs;
    adrs.SetLayerAddress(D - 1);
    key.pk_root = XmssNode(ctx, adrs, sk_seed, 0, HP);
    return key;
}

std::vector<unsigned char> SignInternal(const SecretKey& key, std::span<const unsigned char> msg, const std::optional<Seed>& addrnd)
{
    std::vector<unsigned char> sig(SIGNATURE_SIZE);
    const auto pk{key.PubKey()};
    const Seed& opt_rand{addrnd ? *addrnd : key.pk_seed};

    // R = PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))
    unsigned char hmac[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256(key.sk_prf.data(), N).Write(opt_rand.data(), N).Write(msg.data(), msg.size()).Finalize(hmac);
    std::memcpy(sig.data(), hmac, N);

    const auto digest{detail::HashMessage(std::span{sig}.first<N>(), pk, {}, msg)};
    uint64_t idx_tree;
    uint32_t idx_leaf;
    detail::SplitDigest(digest, idx_tree, idx_leaf);

    const HashContext ctx{key.pk_seed};
    Address adrs;
    adrs.SetTreeAddress(idx_tree);
    adrs.SetTypeAndClear(Address::FORS_TREE);
    adrs.SetKeyPairAddress(idx_leaf);

    // Algorithm 16: fors_sign.
    const auto md{std::span{digest}.first<(K * A + 7) / 8>()};
    uint32_t indices[K];
    detail::Base2b(md, A, indices);
    unsigned char* fors{sig.data() + N};
    for (uint32_t i = 0; i < K; ++i) {
        const Node sk{ForsSecret(ctx, adrs, key.sk_seed, (i << A) + indices[i])};
        std::memcpy(fors + i * (A + 1) * N, sk.data(), N);
        for (uint32_t j = 0; j < A; ++j) {
            const uint32_t s{(indices[i] >> j) ^ 1};
            const Node auth{ForsNode(ctx, adrs, key.sk_seed, (i << (A - j)) + s, j)};
            std::memcpy(fors + (i * (A + 1) + 1 + j) * N, auth.data(), N);
        }
    }
    Node node;
    detail::ForsPkFromSig(ctx, adrs, std::span<const unsigned char>{fors, K * (A + 1) * N}.first<K * (A + 1) * N>(), md, node);

    // Algorithm 12: ht_sign.
    unsigned char* ht{fors + K * (A + 1) * N};
    adrs = Address{};
    adrs.SetTreeAddress(idx_tree);
    for (uint32_t j = 0; j < D; ++j) {
        if (j > 0) {
            idx_leaf = idx_tree & ((uint32_t{1} << HP) - 1);
            idx_tree >>= HP;
            adrs.SetLayerAddress(j);
            adrs.SetTreeAddress(idx_tree);
        }
        unsigned char* xmss{ht + j * (LEN + HP) * N};
        XmssSign(ctx, adrs, key.sk_seed, node, idx_leaf, xmss);
        if (j + 1 < D) {
            detail::XmssPkFromSig(ctx, adrs, idx_leaf, std::span<const unsigned char>{xmss, (LEN + HP) * N}.first<(LEN + HP) * N>(), node, node);
        }
    }
    return sig;
}

std::vector<unsigned char> Sign(const SecretKey& key, std::span<const unsigned char> msg, std::span<const unsigned char> ctx, const std::optional<Seed>& addrnd)
{
    return SignInternal(key, PureMessage(msg, ctx), addrnd);
}

std::array<uint32_t, D> WotsChainSteps(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> ctx_str)
{
    assert(pubkey.size() == PUBLIC_KEY_SIZE && sig.size() == SIGNATURE_SIZE);
    const auto pk{pubkey.first<PUBLIC_KEY_SIZE>()};
    const auto prefix{PureMessage({}, ctx_str)};
    const auto digest{detail::HashMessage(sig.first<N>(), pk, prefix, msg)};
    uint64_t idx_tree;
    uint32_t idx_leaf;
    detail::SplitDigest(digest, idx_tree, idx_leaf);
    const HashContext ctx{pk.first<N>()};
    Address adrs;
    adrs.SetTreeAddress(idx_tree);
    adrs.SetTypeAndClear(Address::FORS_TREE);
    adrs.SetKeyPairAddress(idx_leaf);
    Node node;
    detail::ForsPkFromSig(ctx, adrs, sig.subspan<N, K * (A + 1) * N>(), std::span{digest}.first<(K * A + 7) / 8>(), node);

    std::array<uint32_t, D> steps;
    adrs = Address{};
    adrs.SetTreeAddress(idx_tree);
    for (uint32_t j = 0; j < D; ++j) {
        if (j > 0) {
            idx_leaf = idx_tree & ((uint32_t{1} << HP) - 1);
            idx_tree >>= HP;
            adrs.SetLayerAddress(j);
            adrs.SetTreeAddress(idx_tree);
        }
        steps[j] = ChainSteps(node);
        const auto xmss{sig.subspan((1 + K * (A + 1) + j * (LEN + HP)) * N).first<(LEN + HP) * N>()};
        detail::XmssPkFromSig(ctx, adrs, idx_leaf, xmss, node, node);
    }
    return steps;
}

std::vector<unsigned char> GrindHighWorkSignature(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::vector<unsigned char> sig, unsigned int grind_bits, std::span<const unsigned char> ctx_str)
{
    assert(pubkey.size() == PUBLIC_KEY_SIZE && sig.size() == SIGNATURE_SIZE);
    assert(grind_bits <= 32);
    const auto pk{pubkey.first<PUBLIC_KEY_SIZE>()};
    const auto prefix{PureMessage({}, ctx_str)};
    const auto digest{detail::HashMessage(std::span{sig}.first<N>(), pk, prefix, msg)};
    uint64_t idx_tree;
    uint32_t idx_leaf;
    detail::SplitDigest(digest, idx_tree, idx_leaf);
    const HashContext ctx{pk.first<N>()};
    const uint64_t tries{uint64_t{1} << grind_bits};

    // Layer 0. Its WOTS+ message is the FORS public key. Change the top
    // authentication node of the last FORS tree.
    Address adrs;
    adrs.SetTreeAddress(idx_tree);
    adrs.SetTypeAndClear(Address::FORS_TREE);
    adrs.SetKeyPairAddress(idx_leaf);
    uint32_t indices[K];
    detail::Base2b(std::span{digest}.first<(K * A + 7) / 8>(), A, indices);
    unsigned char* fors{sig.data() + N};
    unsigned char roots[K * N];
    Node top_child;
    for (uint32_t i = 0; i < K; ++i) {
        const uint32_t idx{(i << A) + indices[i]};
        Node node;
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex(idx);
        ctx.Hash(adrs, std::span<const unsigned char>{fors + i * (A + 1) * N, N}, node);
        const uint32_t levels{i + 1 < K ? uint32_t{A} : uint32_t{A - 1}};
        for (uint32_t j = 0; j < levels; ++j) {
            Node auth;
            std::memcpy(auth.data(), fors + (i * (A + 1) + 1 + j) * N, N);
            adrs.SetTreeHeight(j + 1);
            adrs.SetTreeIndex(idx >> (j + 1));
            node = ((indices[i] >> j) & 1) == 0 ? HashPair(ctx, adrs, node, auth) : HashPair(ctx, adrs, auth, node);
        }
        if (i + 1 < K) {
            std::memcpy(roots + i * N, node.data(), N);
        } else {
            top_child = node;
        }
    }
    Address roots_adrs{adrs};
    roots_adrs.SetTypeAndClear(Address::FORS_ROOTS);
    roots_adrs.SetKeyPairAddress(idx_leaf);
    adrs.SetTreeHeight(A);
    adrs.SetTreeIndex(K - 1);
    const bool top_left{((indices[K - 1] >> (A - 1)) & 1) == 0};
    unsigned char* fors_top_auth{fors + ((K - 1) * (A + 1) + A) * N};

    Node best_auth{};
    uint32_t best_steps{0};
    Node msg_node;
    for (uint64_t t = 0; t < tries; ++t) {
        Node auth{};
        WriteLE64(auth.data(), t);
        const Node root{top_left ? HashPair(ctx, adrs, top_child, auth) : HashPair(ctx, adrs, auth, top_child)};
        std::memcpy(roots + (K - 1) * N, root.data(), N);
        Node fors_pk;
        ctx.Hash(roots_adrs, roots, fors_pk);
        const uint32_t steps{ChainSteps(fors_pk)};
        if (t == 0 || steps > best_steps) {
            best_steps = steps;
            best_auth = auth;
            msg_node = fors_pk;
        }
    }
    std::memcpy(fors_top_auth, best_auth.data(), N);

    // Layers 1 to D - 1. The WOTS+ message of layer j is the XMSS root of
    // layer j - 1. Change the top authentication node of layer j - 1.
    unsigned char* ht{fors + K * (A + 1) * N};
    adrs = Address{};
    for (uint32_t j = 0; j + 1 < D; ++j) {
        if (j > 0) {
            idx_leaf = idx_tree & ((uint32_t{1} << HP) - 1);
            idx_tree >>= HP;
        }
        adrs.SetLayerAddress(j);
        adrs.SetTreeAddress(idx_tree);
        unsigned char* xmss{ht + j * (LEN + HP) * N};
        adrs.SetTypeAndClear(Address::WOTS_HASH);
        adrs.SetKeyPairAddress(idx_leaf);
        Node node;
        detail::WotsPkFromSig(ctx, adrs, std::span<const unsigned char>{xmss, LEN * N}.first<LEN * N>(), msg_node, node);
        adrs.SetTypeAndClear(Address::TREE);
        for (uint32_t k = 0; k + 1 < HP; ++k) {
            Node auth;
            std::memcpy(auth.data(), xmss + (LEN + k) * N, N);
            adrs.SetTreeHeight(k + 1);
            adrs.SetTreeIndex(idx_leaf >> (k + 1));
            node = ((idx_leaf >> k) & 1) == 0 ? HashPair(ctx, adrs, node, auth) : HashPair(ctx, adrs, auth, node);
        }
        adrs.SetTreeHeight(HP);
        adrs.SetTreeIndex(idx_leaf >> HP);
        const bool left{((idx_leaf >> (HP - 1)) & 1) == 0};
        best_steps = 0;
        for (uint64_t t = 0; t < tries; ++t) {
            Node auth{};
            WriteLE64(auth.data(), t);
            const Node root{left ? HashPair(ctx, adrs, node, auth) : HashPair(ctx, adrs, auth, node)};
            const uint32_t steps{ChainSteps(root)};
            if (t == 0 || steps > best_steps) {
                best_steps = steps;
                best_auth = auth;
                msg_node = root;
            }
        }
        std::memcpy(xmss + (LEN + HP - 1) * N, best_auth.data(), N);
    }
    return sig;
}

} // namespace slhdsa_test
