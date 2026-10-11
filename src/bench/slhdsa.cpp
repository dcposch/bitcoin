// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa.h>

#include <bench/bench.h>
#include <crypto/sha256.h>
#include <key.h>
#include <policy/policy.h>
#include <prevector.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/verify_flags.h>
#include <test/util/slhdsa.h>
#include <tinyformat.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace {

/** Length of the message M of OP_CHECKSIGPQADD for a spend with SIGHASH_DEFAULT and no annex. */
constexpr size_t TAPSCRIPT_MESSAGE_SIZE{64 + 1 + 174 + 37};

slhdsa_test::SecretKey MakeKey(FastRandomContext& rng)
{
    slhdsa_test::Seed sk_seed, sk_prf, pk_seed;
    rng.fillrand(std::as_writable_bytes(std::span{sk_seed}));
    rng.fillrand(std::as_writable_bytes(std::span{sk_prf}));
    rng.fillrand(std::as_writable_bytes(std::span{pk_seed}));
    return slhdsa_test::KeyGen(sk_seed, sk_prf, pk_seed);
}

} // namespace

/** One SLH-DSA-SHA2-128s verification of a valid signature on a random message. */
static void SLHDSAVerify(benchmark::Bench& bench)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto key{MakeKey(rng)};
    const auto pk{key.PubKey()};
    const auto msg{rng.randbytes<unsigned char>(TAPSCRIPT_MESSAGE_SIZE)};
    const auto sig{slhdsa_test::Sign(key, msg)};
    const bool valid{slhdsa::Verify(pk, msg, sig)};
    assert(valid);

    bench.unit("verify").run([&] {
        const bool ok{slhdsa::Verify(pk, msg, sig)};
        assert(ok);
    });
}

/** One SLH-DSA-SHA2-128s verification of a signature with a high number of WOTS+ chain steps.
 *
 * The worst case for the verifier is when every WOTS+ message digit is 0. Then each of
 * the 7 WOTS+ public key computations does 32 * 15 + 30 = 510 chain steps (3,570 in total).
 * No input reaches it, because the WOTS+ messages are hash outputs. An attacker can
 * increase the steps by trying many values for authentication path nodes. This benchmark
 * does the same with 2^16 tries for each layer. The signature is not valid, but the
 * verifier does all hash computations before it compares the root. The ratio of chain
 * steps to the maximum is in the notes of this branch, so that the cost of the maximum
 * can be extrapolated.
 */
static void SLHDSAVerifyHighWorkImpl(benchmark::Bench& bench)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto key{MakeKey(rng)};
    const auto pk{key.PubKey()};
    const auto msg{rng.randbytes<unsigned char>(TAPSCRIPT_MESSAGE_SIZE)};
    const auto sig{slhdsa_test::GrindHighWorkSignature(pk, msg, slhdsa_test::Sign(key, msg), /*grind_bits=*/16)};

    bench.unit("verify").run([&] {
        const bool ok{slhdsa::Verify(pk, msg, sig)};
        assert(!ok);
    });
}

static void SLHDSAVerifyHighWork(benchmark::Bench& bench)
{
    SLHDSAVerifyHighWorkImpl(bench);
}

/** The same as SLHDSAVerifyHighWork, with the portable C++ SHA-256 code (no SHA-NI, ARMv8, SSE4, or AVX2). */
static void SLHDSAVerifyHighWorkStandardSHA256(benchmark::Bench& bench)
{
    bench.name(strprintf("%s using the '%s' SHA256 implementation", __func__, SHA256AutoDetect(sha256_implementation::STANDARD)));
    SLHDSAVerifyHighWorkImpl(bench);
    SHA256AutoDetect();
}

/** One BIP 340 Schnorr verification, for comparison with the benchmarks above. */
static void SchnorrVerify(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};
    FastRandomContext rng{/*fDeterministic=*/true};
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const uint256 msg{rng.rand256()};
    std::vector<unsigned char> sig(64);
    const uint256 aux{rng.rand256()};
    const bool signed_ok{key.SignSchnorr(msg, sig, nullptr, aux)};
    assert(signed_ok);

    bench.unit("verify").run([&] {
        const bool ok{pubkey.VerifySchnorr(msg, sig)};
        assert(ok);
    });
}

/** VerifyScript of a P2MR spend with the leaf OP_0 <pk> OP_CHECKSIGPQADD.
 *  Compare with VerifyScriptP2TR_ScriptPath. */
static void VerifyScriptP2MR_SLHDSA(benchmark::Bench& bench)
{
    FastRandomContext rng{/*fDeterministic=*/true};
    const auto key{MakeKey(rng)};
    std::vector<unsigned char> pk_bytes{SLHDSA_KEY_TYPE_SHA2_128S};
    const auto pk{key.PubKey()};
    pk_bytes.insert(pk_bytes.end(), pk.begin(), pk.end());
    const CScript leaf{CScript() << OP_0 << pk_bytes << OP_CHECKSIGPQADD};

    // A tree of depth one with a fixed sibling hash.
    const uint256 sibling{uint256::ONE};
    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf)};
    const CScript spk{CScript() << OP_2 << ToByteVector(ComputeTapbranchHash(leaf_hash, sibling))};
    std::vector<unsigned char> control{TAPROOT_LEAF_TAPSCRIPT | 1};
    control.insert(control.end(), sibling.begin(), sibling.end());

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256::ONE), 0};
    tx.vout.emplace_back(90'000, CScript() << OP_RETURN);
    const CTxOut spent{100'000, spk};

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {spent}, /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    std::vector<unsigned char> msg;
    const bool msg_ok{SignatureMessageSLHDSA(msg, execdata, tx, 0, txdata, MissingDataBehavior::ASSERT_FAIL)};
    assert(msg_ok);
    const auto sig{slhdsa_test::Sign(key, msg)};

    auto& stack{tx.vin[0].scriptWitness.stack};
    for (size_t pos = 0; pos < sig.size(); pos += MAX_SCRIPT_ELEMENT_SIZE) {
        stack.emplace_back(sig.begin() + pos, sig.begin() + std::min(pos + MAX_SCRIPT_ELEMENT_SIZE, sig.size()));
    }
    stack.push_back({0x10});
    stack.emplace_back(leaf.begin(), leaf.end());
    stack.push_back(control);
    txdata = PrecomputedTransactionData{};
    txdata.Init(tx, {spent});

    bench.unit("script").run([&] {
        ScriptError err;
        const bool ok{VerifyScript(tx.vin[0].scriptSig, spk, &tx.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS,
                                   MutableTransactionSignatureChecker(&tx, 0, spent.nValue, txdata, MissingDataBehavior::ASSERT_FAIL), &err)};
        assert(ok && err == SCRIPT_ERR_OK);
    });
}

BENCHMARK(SLHDSAVerify);
BENCHMARK(SLHDSAVerifyHighWork);
BENCHMARK(SLHDSAVerifyHighWorkStandardSHA256);
BENCHMARK(SchnorrVerify);
BENCHMARK(VerifyScriptP2MR_SLHDSA);
