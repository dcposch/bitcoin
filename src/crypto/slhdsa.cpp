// Copyright (c) The slhdsa-c project authors
// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa.h>

#include <crypto/sha256.h>

#include <algorithm>
#include <cassert>
#include <cstring>

namespace slhdsa {

HashContext::HashContext(std::span<const unsigned char, N> pk_seed)
{
    static constexpr unsigned char ZEROS[64 - N]{};
    m_seeded.Write(pk_seed.data(), N).Write(ZEROS, sizeof(ZEROS));
}

void HashContext::Hash(const Address& adrs, std::span<const unsigned char> in, std::span<unsigned char, N> out) const
{
    CSHA256 hasher{m_seeded};
    unsigned char buf[CSHA256::OUTPUT_SIZE];
    hasher.Write(adrs.data(), adrs.size()).Write(in.data(), in.size()).Finalize(buf);
    std::memcpy(out.data(), buf, N);
}

namespace detail {

void Base2b(std::span<const unsigned char> in, unsigned int b, std::span<uint32_t> out)
{
    size_t pos{0};
    unsigned int bits{0};
    uint32_t total{0};
    const uint32_t mask{(uint32_t{1} << b) - 1};
    for (uint32_t& digit : out) {
        while (bits < b) {
            assert(pos < in.size());
            total = (total << 8) + in[pos++];
            bits += 8;
        }
        bits -= b;
        digit = (total >> bits) & mask;
    }
}

std::array<uint32_t, LEN> WotsDigits(std::span<const unsigned char, N> msg)
{
    std::array<uint32_t, LEN> digits;
    Base2b(msg, LG_W, std::span{digits}.first<LEN1>());
    uint32_t csum{0};
    for (size_t i = 0; i < LEN1; ++i) {
        csum += W - 1 - digits[i];
    }
    // Left shift so that the checksum fills whole bytes. For these parameters
    // the checksum has LEN2 * LG_W = 12 bits, so it is shifted by 4 bits.
    static_assert((LEN2 * LG_W + 7) / 8 == 2);
    csum <<= (8 - ((LEN2 * LG_W) % 8)) % 8;
    const unsigned char csum_bytes[2]{static_cast<unsigned char>(csum >> 8), static_cast<unsigned char>(csum)};
    Base2b(csum_bytes, LG_W, std::span{digits}.last<LEN2>());
    return digits;
}

void WotsPkFromSig(const HashContext& ctx, Address& adrs, std::span<const unsigned char, LEN * N> sig, std::span<const unsigned char, N> msg, std::span<unsigned char, N> pk_out)
{
    const auto digits{WotsDigits(msg)};
    unsigned char tmp[LEN * N];
    for (size_t i = 0; i < LEN; ++i) {
        // Algorithm 5: chain(X, i, s, PK.seed, ADRS), from digits[i] to W - 1.
        adrs.SetChainAddress(i);
        std::span<unsigned char, N> node{tmp + i * N, N};
        std::memcpy(node.data(), sig.data() + i * N, N);
        for (uint32_t j = digits[i]; j < W - 1; ++j) {
            adrs.SetHashAddress(j);
            ctx.Hash(adrs, node, node);
        }
    }
    Address pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(Address::WOTS_PK);
    pk_adrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
    ctx.Hash(pk_adrs, tmp, pk_out);
}

void XmssPkFromSig(const HashContext& ctx, Address& adrs, uint32_t idx, std::span<const unsigned char, (LEN + HP) * N> sig, std::span<const unsigned char, N> msg, std::span<unsigned char, N> root_out)
{
    adrs.SetTypeAndClear(Address::WOTS_HASH);
    adrs.SetKeyPairAddress(idx);
    unsigned char node[2 * N];
    WotsPkFromSig(ctx, adrs, sig.first<LEN * N>(), msg, std::span{node}.first<N>());

    adrs.SetTypeAndClear(Address::TREE);
    for (size_t k = 0; k < HP; ++k) {
        const unsigned char* auth{sig.data() + (LEN + k) * N};
        adrs.SetTreeHeight(k + 1);
        adrs.SetTreeIndex(idx >> (k + 1));
        if (((idx >> k) & 1) == 0) {
            std::memcpy(node + N, auth, N);
        } else {
            std::memcpy(node + N, node, N);
            std::memcpy(node, auth, N);
        }
        ctx.Hash(adrs, node, std::span{node}.first<N>());
    }
    std::memcpy(root_out.data(), node, N);
}

void ForsPkFromSig(const HashContext& ctx, Address& adrs, std::span<const unsigned char, K * (A + 1) * N> sig, std::span<const unsigned char> md, std::span<unsigned char, N> pk_out)
{
    uint32_t indices[K];
    Base2b(md, A, indices);

    unsigned char roots[K * N];
    for (size_t i = 0; i < K; ++i) {
        const unsigned char* sk{sig.data() + i * (A + 1) * N};
        const uint32_t idx{(uint32_t(i) << A) + indices[i]};
        unsigned char node[2 * N];
        adrs.SetTreeHeight(0);
        adrs.SetTreeIndex(idx);
        ctx.Hash(adrs, std::span<const unsigned char>{sk, N}, std::span{node}.first<N>());
        for (size_t j = 0; j < A; ++j) {
            const unsigned char* auth{sk + (1 + j) * N};
            adrs.SetTreeHeight(j + 1);
            adrs.SetTreeIndex(idx >> (j + 1));
            if (((indices[i] >> j) & 1) == 0) {
                std::memcpy(node + N, auth, N);
            } else {
                std::memcpy(node + N, node, N);
                std::memcpy(node, auth, N);
            }
            ctx.Hash(adrs, node, std::span{node}.first<N>());
        }
        std::memcpy(roots + i * N, node, N);
    }
    Address pk_adrs{adrs};
    pk_adrs.SetTypeAndClear(Address::FORS_ROOTS);
    pk_adrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
    ctx.Hash(pk_adrs, roots, pk_out);
}

std::array<unsigned char, M> HashMessage(std::span<const unsigned char, N> r, std::span<const unsigned char, PUBLIC_KEY_SIZE> pubkey, std::span<const unsigned char> prefix, std::span<const unsigned char> msg)
{
    // MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    unsigned char seed[2 * N + CSHA256::OUTPUT_SIZE + 4];
    std::memcpy(seed, r.data(), N);
    std::memcpy(seed + N, pubkey.data(), N);
    CSHA256()
        .Write(r.data(), N)
        .Write(pubkey.data(), PUBLIC_KEY_SIZE)
        .Write(prefix.data(), prefix.size())
        .Write(msg.data(), msg.size())
        .Finalize(seed + 2 * N);
    // MGF1 with a 4-byte big-endian counter. One block is enough for m = 30.
    static_assert(M <= CSHA256::OUTPUT_SIZE);
    std::memset(seed + 2 * N + CSHA256::OUTPUT_SIZE, 0, 4);
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(seed, sizeof(seed)).Finalize(out);
    std::array<unsigned char, M> digest;
    std::memcpy(digest.data(), out, M);
    return digest;
}

void SplitDigest(std::span<const unsigned char, M> digest, uint64_t& idx_tree, uint32_t& idx_leaf)
{
    static constexpr size_t MD_SIZE{(K * A + 7) / 8};
    static constexpr size_t TREE_SIZE{(H - HP + 7) / 8};
    static constexpr size_t LEAF_SIZE{(HP + 7) / 8};
    static_assert(MD_SIZE + TREE_SIZE + LEAF_SIZE == M);
    idx_tree = 0;
    for (size_t i = 0; i < TREE_SIZE; ++i) idx_tree = (idx_tree << 8) | digest[MD_SIZE + i];
    idx_leaf = 0;
    for (size_t i = 0; i < LEAF_SIZE; ++i) idx_leaf = (idx_leaf << 8) | digest[MD_SIZE + TREE_SIZE + i];
    idx_tree &= (uint64_t{1} << (H - HP)) - 1;
    idx_leaf &= (uint32_t{1} << HP) - 1;
}

} // namespace detail

namespace {

/** Algorithm 20 (slh_verify_internal), with the message given as prefix || msg. */
bool VerifyWithPrefix(std::span<const unsigned char> pubkey, std::span<const unsigned char> prefix, std::span<const unsigned char> msg, std::span<const unsigned char> sig)
{
    if (pubkey.size() != PUBLIC_KEY_SIZE) return false;
    if (sig.size() != SIGNATURE_SIZE) return false;
    const auto pk{pubkey.first<PUBLIC_KEY_SIZE>()};
    const auto pk_seed{pk.first<N>()};
    const auto pk_root{pk.last<N>()};

    const auto r{sig.first<N>()};
    const auto sig_fors{sig.subspan<N, K * (A + 1) * N>()};
    const auto sig_ht{sig.last<D * (LEN + HP) * N>()};

    const auto digest{detail::HashMessage(r, pk, prefix, msg)};
    uint64_t idx_tree;
    uint32_t idx_leaf;
    detail::SplitDigest(digest, idx_tree, idx_leaf);

    const HashContext ctx{pk_seed};
    Address adrs;
    adrs.SetTreeAddress(idx_tree);
    adrs.SetTypeAndClear(Address::FORS_TREE);
    adrs.SetKeyPairAddress(idx_leaf);
    unsigned char node[N];
    detail::ForsPkFromSig(ctx, adrs, sig_fors, std::span{digest}.first<(K * A + 7) / 8>(), node);

    // Algorithm 13: ht_verify.
    adrs = Address{};
    adrs.SetTreeAddress(idx_tree);
    for (size_t j = 0; j < D; ++j) {
        if (j > 0) {
            idx_leaf = idx_tree & ((uint32_t{1} << HP) - 1);
            idx_tree >>= HP;
            adrs.SetLayerAddress(j);
            adrs.SetTreeAddress(idx_tree);
        }
        const auto sig_xmss{sig_ht.subspan(j * (LEN + HP) * N).first<(LEN + HP) * N>()};
        detail::XmssPkFromSig(ctx, adrs, idx_leaf, sig_xmss, node, node);
    }
    return std::equal(pk_root.begin(), pk_root.end(), node);
}

} // namespace

bool Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> ctx)
{
    if (ctx.size() > MAX_CONTEXT_SIZE) return false;
    // M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
    unsigned char prefix[2 + MAX_CONTEXT_SIZE];
    prefix[0] = 0;
    prefix[1] = ctx.size();
    std::copy(ctx.begin(), ctx.end(), prefix + 2);
    return VerifyWithPrefix(pubkey, std::span{prefix, 2 + ctx.size()}, msg, sig);
}

bool VerifyInternal(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig)
{
    return VerifyWithPrefix(pubkey, {}, msg, sig);
}

} // namespace slhdsa
