// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <crypto/slhdsa.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/data/slhdsa_acvp.json.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/slhdsa.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using valtype = std::vector<unsigned char>;

namespace {

slhdsa_test::Seed SeedFromHex(const std::string& hex)
{
    const auto bytes{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), slhdsa::N);
    slhdsa_test::Seed seed{};
    std::copy(bytes.begin(), bytes.end(), seed.begin());
    return seed;
}

slhdsa_test::SecretKey SecretKeyFromHex(const std::string& hex)
{
    const auto bytes{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(bytes.size(), 4 * slhdsa::N);
    slhdsa_test::SecretKey key{};
    std::copy_n(bytes.begin(), slhdsa::N, key.sk_seed.begin());
    std::copy_n(bytes.begin() + slhdsa::N, slhdsa::N, key.sk_prf.begin());
    std::copy_n(bytes.begin() + 2 * slhdsa::N, slhdsa::N, key.pk_seed.begin());
    std::copy_n(bytes.begin() + 3 * slhdsa::N, slhdsa::N, key.pk_root.begin());
    return key;
}

slhdsa_test::SecretKey KeyFromByte(uint8_t b)
{
    slhdsa_test::Seed sk_seed, sk_prf, pk_seed;
    sk_seed.fill(b);
    sk_prf.fill(b ^ 0x5a);
    pk_seed.fill(b ^ 0xa5);
    return slhdsa_test::KeyGen(sk_seed, sk_prf, pk_seed);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(slhdsa_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(slhdsa_acvp_sigver)
{
    const UniValue tests{read_json(json_tests::slhdsa_acvp)[0]};
    const UniValue& sigver{tests["sigVer"]};
    BOOST_REQUIRE(sigver.size() > 0);
    for (size_t i = 0; i < sigver.size(); ++i) {
        const UniValue& t{sigver[i]};
        const auto pk{ParseHex(t["pk"].get_str())};
        const auto msg{ParseHex(t["message"].get_str())};
        const auto ctx{ParseHex(t["context"].get_str())};
        const auto sig{ParseHex(t["signature"].get_str())};
        const bool expected{t["testPassed"].get_bool()};
        const bool internal{t["interface"].get_str() == "internal"};
        const bool result{internal ? slhdsa::VerifyInternal(pk, msg, sig) : slhdsa::Verify(pk, msg, sig, ctx)};
        BOOST_CHECK_MESSAGE(result == expected, "ACVP tcId " << t["tcId"].getInt<int>() << ": " << t["reason"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(slhdsa_acvp_keygen_siggen)
{
    // These vectors test the test-only signer, which other tests use.
    const UniValue tests{read_json(json_tests::slhdsa_acvp)[0]};
    const UniValue& keygen{tests["keyGen"]};
    for (size_t i = 0; i < keygen.size(); ++i) {
        const UniValue& t{keygen[i]};
        const auto key{slhdsa_test::KeyGen(SeedFromHex(t["skSeed"].get_str()), SeedFromHex(t["skPrf"].get_str()), SeedFromHex(t["pkSeed"].get_str()))};
        BOOST_CHECK_EQUAL(HexStr(key.PubKey()), t["pk"].get_str());
    }
    const UniValue& siggen{tests["sigGen"]};
    for (size_t i = 0; i < siggen.size(); ++i) {
        const UniValue& t{siggen[i]};
        const auto key{SecretKeyFromHex(t["sk"].get_str())};
        BOOST_CHECK_EQUAL(HexStr(key.PubKey()), t["pk"].get_str());
        const auto msg{ParseHex(t["message"].get_str())};
        const auto ctx{ParseHex(t["context"].get_str())};
        std::optional<slhdsa_test::Seed> addrnd;
        if (!t["deterministic"].get_bool()) addrnd = SeedFromHex(t["additionalRandomness"].get_str());
        const bool internal{t["interface"].get_str() == "internal"};
        const auto sig{internal ? slhdsa_test::SignInternal(key, msg, addrnd) : slhdsa_test::Sign(key, msg, ctx, addrnd)};
        BOOST_CHECK_MESSAGE(HexStr(sig) == t["signature"].get_str(), "ACVP sigGen tcId " << t["tcId"].getInt<int>());
        BOOST_CHECK(internal ? slhdsa::VerifyInternal(key.PubKey(), msg, sig) : slhdsa::Verify(key.PubKey(), msg, sig, ctx));
    }
}

BOOST_AUTO_TEST_CASE(slhdsa_verify_basic)
{
    const auto key{KeyFromByte(1)};
    const auto pk{key.PubKey()};
    const std::vector<unsigned char> msg{'m', 's', 'g'};
    const auto sig{slhdsa_test::Sign(key, msg)};
    BOOST_CHECK_EQUAL(sig.size(), slhdsa::SIGNATURE_SIZE);
    BOOST_CHECK(slhdsa::Verify(pk, msg, sig));

    // A signature is bound to the message, the context, and the public key.
    BOOST_CHECK(!slhdsa::Verify(pk, std::vector<unsigned char>{'m', 's', 'h'}, sig));
    BOOST_CHECK(!slhdsa::Verify(pk, msg, sig, std::vector<unsigned char>{0}));
    BOOST_CHECK(!slhdsa::VerifyInternal(pk, msg, sig));
    auto bad_pk{pk};
    bad_pk[31] ^= 1;
    BOOST_CHECK(!slhdsa::Verify(bad_pk, msg, sig));

    // Wrong sizes fail.
    BOOST_CHECK(!slhdsa::Verify(std::span{pk}.first(31), msg, sig));
    BOOST_CHECK(!slhdsa::Verify(std::span{sig}.first(slhdsa::PUBLIC_KEY_SIZE), msg, sig));
    BOOST_CHECK(!slhdsa::Verify(pk, msg, std::span{sig}.first(slhdsa::SIGNATURE_SIZE - 1)));
    auto long_sig{sig};
    long_sig.push_back(0);
    BOOST_CHECK(!slhdsa::Verify(pk, msg, long_sig));
    BOOST_CHECK(!slhdsa::Verify(pk, msg, sig, std::vector<unsigned char>(256)));

    // Flip one bit in a sample of positions in each part of the signature.
    for (size_t pos : {size_t{0}, size_t{15}, size_t{16}, size_t{100}, size_t{2928}, size_t{2929}, size_t{5000}, slhdsa::SIGNATURE_SIZE - 1}) {
        auto bad_sig{sig};
        bad_sig[pos] ^= 0x10;
        BOOST_CHECK_MESSAGE(!slhdsa::Verify(pk, msg, bad_sig), "position " << pos);
    }

    // A signature with a context string.
    const std::vector<unsigned char> ctx(255, 0x42);
    const auto sig_ctx{slhdsa_test::Sign(key, msg, ctx)};
    BOOST_CHECK(slhdsa::Verify(pk, msg, sig_ctx, ctx));
    BOOST_CHECK(!slhdsa::Verify(pk, msg, sig_ctx));

    // The high work signature from the benchmark does more WOTS+ chain steps, and is not valid.
    const auto steps{slhdsa_test::WotsChainSteps(pk, msg, sig)};
    const auto ground{slhdsa_test::GrindHighWorkSignature(pk, msg, sig, 8)};
    const auto ground_steps{slhdsa_test::WotsChainSteps(pk, msg, ground)};
    uint32_t total{0}, ground_total{0};
    for (size_t j = 0; j < slhdsa::D; ++j) {
        total += steps[j];
        ground_total += ground_steps[j];
        BOOST_CHECK(ground_steps[j] <= 32 * 15 + 30);
    }
    BOOST_CHECK(ground_total > total);
    BOOST_CHECK(!slhdsa::Verify(pk, msg, ground));
}

/** Helpers to build and verify P2MR spends that use OP_CHECKSIGPQADD. */
struct SLHScriptTest {
    CMutableTransaction m_tx;
    std::vector<CTxOut> m_spent;
    CScript m_leaf;
    CScript m_spk;
    std::vector<unsigned char> m_control;
    bool m_p2tr{false};

    static constexpr uint8_t CONTROL_P2MR{TAPROOT_LEAF_TAPSCRIPT | 1};

    explicit SLHScriptTest(const CScript& leaf, bool p2tr = false) : m_leaf{leaf}, m_p2tr{p2tr}
    {
        // A tree of depth one. The sibling is a fixed hash.
        const uint256 sibling{uint256::ONE};
        const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, m_leaf)};
        const uint256 root{ComputeTapbranchHash(leaf_hash, sibling)};
        if (!p2tr) {
            m_spk = CScript() << OP_2 << ToByteVector(root);
            m_control = {CONTROL_P2MR};
        } else {
            // P2TR with the NUMS internal key of BIP 341.
            const XOnlyPubKey internal{XOnlyPubKey::NUMS_H};
            const auto tweaked{internal.CreateTapTweak(&root)};
            BOOST_REQUIRE(tweaked);
            m_spk = CScript() << OP_1 << ToByteVector(tweaked->first);
            m_control = {static_cast<unsigned char>(TAPROOT_LEAF_TAPSCRIPT | (tweaked->second ? 1 : 0))};
            m_control.insert(m_control.end(), internal.begin(), internal.end());
        }
        m_control.insert(m_control.end(), sibling.begin(), sibling.end());

        m_tx.version = 2;
        m_tx.vin.resize(1);
        m_tx.vin[0].prevout = COutPoint{Txid::FromUint256(uint256{7}), 0};
        m_tx.vout.resize(1);
        m_tx.vout[0].nValue = 90'000;
        m_tx.vout[0].scriptPubKey = CScript() << OP_RETURN;
        m_spent.emplace_back(100'000, m_spk);
    }

    /** The message M that a key type 0x01 signature signs. */
    std::vector<unsigned char> Message() const
    {
        PrecomputedTransactionData txdata;
        txdata.Init(m_tx, std::vector<CTxOut>{m_spent}, /*force=*/true);
        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, m_leaf);
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        std::vector<unsigned char> msg;
        BOOST_REQUIRE(SignatureMessageSLHDSA(msg, execdata, m_tx, 0, txdata, MissingDataBehavior::FAIL));
        return msg;
    }

    /** Verify with the given initial stack (without script and control block). */
    bool Verify(std::vector<valtype> stack, script_verify_flags flags, ScriptError& err) const
    {
        CMutableTransaction tx{m_tx};
        stack.emplace_back(m_leaf.begin(), m_leaf.end());
        stack.push_back(m_control);
        tx.vin[0].scriptWitness.stack = std::move(stack);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>{m_spent});
        MutableTransactionSignatureChecker checker{&tx, 0, m_spent[0].nValue, txdata, MissingDataBehavior::ASSERT_FAIL};
        return VerifyScript(tx.vin[0].scriptSig, m_spk, &tx.vin[0].scriptWitness, flags, checker, &err);
    }
};

/** Witness elements of a key type 0x01 signature: 16 chunks, then the count 0x10. */
std::vector<valtype> SigElements(const std::vector<unsigned char>& sig)
{
    BOOST_REQUIRE_EQUAL(sig.size(), slhdsa::SIGNATURE_SIZE);
    std::vector<valtype> out;
    for (size_t pos = 0; pos < sig.size(); pos += MAX_SCRIPT_ELEMENT_SIZE) {
        const size_t len{std::min<size_t>(MAX_SCRIPT_ELEMENT_SIZE, sig.size() - pos)};
        out.emplace_back(sig.begin() + pos, sig.begin() + pos + len);
    }
    BOOST_REQUIRE_EQUAL(out.size(), 16U);
    BOOST_REQUIRE_EQUAL(out.back().size(), 56U);
    out.push_back({0x10});
    return out;
}

valtype KeyBytes(const slhdsa_test::SecretKey& key)
{
    valtype out{SLHDSA_KEY_TYPE_SHA2_128S};
    const auto pk{key.PubKey()};
    out.insert(out.end(), pk.begin(), pk.end());
    return out;
}

void Append(std::vector<valtype>& stack, const std::vector<valtype>& items)
{
    stack.insert(stack.end(), items.begin(), items.end());
}

static const script_verify_flags CONSENSUS_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR | SCRIPT_VERIFY_PQSIG};
static const script_verify_flags POLICY_FLAGS{CONSENSUS_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE | SCRIPT_VERIFY_MINIMALDATA};

BOOST_AUTO_TEST_CASE(slhdsa_signature_message)
{
    // M = ser_tag("SLHSighash") || 0x00 || SigMsg(0x00, 1) || tapleaf_hash || 0x01 || codesep_pos.
    // Compare it to the BIP 342 signature hash, which has the same fields with key_version 0x00.
    const CScript leaf{CScript() << OP_0 << valtype(33, 1) << OP_CHECKSIGPQADD};
    const SLHScriptTest t{leaf};
    const auto msg{t.Message()};

    uint256 tag;
    CSHA256().Write(UCharCast("SLHSighash"), 10).Finalize(tag.begin());
    BOOST_REQUIRE(msg.size() > 64 + 2 + 37);
    BOOST_CHECK(std::equal(tag.begin(), tag.end(), msg.begin()));
    BOOST_CHECK(std::equal(tag.begin(), tag.end(), msg.begin() + 32));
    BOOST_CHECK_EQUAL(msg[64], 0x00); // epoch
    BOOST_CHECK_EQUAL(msg[65], 0x00); // hash_type
    const uint256 leaf_hash{ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, leaf)};
    BOOST_CHECK(std::equal(leaf_hash.begin(), leaf_hash.end(), msg.end() - 37));
    BOOST_CHECK_EQUAL(msg[msg.size() - 5], 0x01); // key_version
    BOOST_CHECK(std::all_of(msg.end() - 4, msg.end(), [](unsigned char c) { return c == 0xff; }));

    PrecomputedTransactionData txdata;
    txdata.Init(t.m_tx, std::vector<CTxOut>{t.m_spent}, /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_hash;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    uint256 sighash;
    BOOST_REQUIRE(SignatureHashSchnorr(sighash, execdata, t.m_tx, 0, SIGHASH_DEFAULT, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));
    std::vector<unsigned char> body{msg.begin() + 64, msg.end()};
    body[body.size() - 5] = 0x00;
    HashWriter hasher{HASHER_TAPSIGHASH};
    hasher.write(MakeByteSpan(body));
    BOOST_CHECK_EQUAL(hasher.GetSHA256().ToString(), sighash.ToString());
    // SigMsg(0x00, 1) without annex has 174 bytes, so M has 64 + 1 + 174 + 37 bytes.
    BOOST_CHECK_EQUAL(msg.size(), 64U + 1 + 174 + 37);
}

BOOST_AUTO_TEST_CASE(checksigpqadd_multisig)
{
    const auto key_a{KeyFromByte(0xa)}, key_b{KeyFromByte(0xb)}, key_c{KeyFromByte(0xc)};
    const CScript leaf{CScript() << OP_0 << KeyBytes(key_a) << OP_CHECKSIGPQADD << KeyBytes(key_b) << OP_CHECKSIGPQADD
                                 << KeyBytes(key_c) << OP_CHECKSIGPQADD << OP_2 << OP_NUMEQUAL};
    const SLHScriptTest t{leaf};
    const auto msg{t.Message()};
    const auto sig_a{slhdsa_test::Sign(key_a, msg)};
    const auto sig_c{slhdsa_test::Sign(key_c, msg)};
    const valtype empty;

    ScriptError err;
    // Valid 2-of-3: <sig_C> <0> <sig_A>.
    std::vector<valtype> good;
    Append(good, SigElements(sig_c));
    good.push_back(empty);
    Append(good, SigElements(sig_a));
    BOOST_CHECK(t.Verify(good, POLICY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

    // Without SCRIPT_VERIFY_PQSIG, opcode 0xca is OP_SUCCESS202.
    std::vector<valtype> garbage{valtype{1, 2, 3}};
    BOOST_CHECK(t.Verify(garbage, CONSENSUS_FLAGS & ~SCRIPT_VERIFY_PQSIG, err));
    BOOST_CHECK(!t.Verify(garbage, POLICY_FLAGS & ~SCRIPT_VERIFY_PQSIG, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
    // With SCRIPT_VERIFY_PQSIG, it is not.
    BOOST_CHECK(!t.Verify(garbage, CONSENSUS_FLAGS, err));

    // Only one signature.
    std::vector<valtype> one_sig{empty, empty};
    Append(one_sig, SigElements(sig_a));
    BOOST_CHECK(!t.Verify(one_sig, CONSENSUS_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EVAL_FALSE);

    // A signature for the wrong key.
    std::vector<valtype> swapped;
    Append(swapped, SigElements(sig_a));
    swapped.push_back(empty);
    Append(swapped, SigElements(sig_c));
    BOOST_CHECK(!t.Verify(swapped, CONSENSUS_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG);

    // A changed bit in any chunk.
    for (size_t chunk : {0, 7, 15}) {
        auto bad{good};
        bad[chunk][0] ^= 1;
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG);
    }

    // The same bytes with other chunk sizes fail, so the encoding is unique.
    {
        auto bad{good};
        bad[15].insert(bad[15].begin(), bad[14].back());
        bad[14].pop_back();
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG_SIZE);
    }
    {
        // 17 chunks: split the last chunk.
        std::vector<valtype> bad;
        auto elems{SigElements(sig_c)};
        elems.pop_back();
        valtype last{elems.back()};
        elems.back() = valtype(last.begin(), last.begin() + 28);
        elems.emplace_back(last.begin() + 28, last.end());
        elems.push_back({17});
        Append(bad, elems);
        bad.push_back(empty);
        Append(bad, SigElements(sig_a));
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG_SIZE);
    }
    {
        // A count of 15 with 16 chunks.
        auto bad{good};
        bad.back() = {15};
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG_SIZE);
    }

    // Count encodings.
    for (const valtype& count : {valtype{0x00}, valtype{0x80}, valtype{0xff}, valtype{0x10, 0x00}, valtype{0x81}}) {
        auto bad{good};
        bad.back() = count;
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_CHUNK_COUNT);
    }

    // Fewer stack elements than the count.
    {
        std::vector<valtype> bad{std::vector<valtype>(good.begin() + 17 + 1 + 1, good.end())};
        BOOST_CHECK(!t.Verify(bad, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // The same leaf in P2TR: opcode 0xca stays OP_SUCCESS202, also with SCRIPT_VERIFY_PQSIG.
    const SLHScriptTest t_p2tr{leaf, /*p2tr=*/true};
    BOOST_CHECK(t_p2tr.Verify(garbage, CONSENSUS_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(!t_p2tr.Verify(good, POLICY_FLAGS, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);
}

BOOST_AUTO_TEST_CASE(checksigpqadd_rules)
{
    ScriptError err;
    const valtype empty;
    const valtype unknown_key{0x02, 0x03};

    // An unknown key type succeeds without verification. Policy discourages it.
    {
        const SLHScriptTest t{CScript() << OP_0 << unknown_key << OP_CHECKSIGPQADD << OP_1 << OP_NUMEQUAL};
        std::vector<valtype> stack{valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x55), valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x55), valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x55), valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x55), valtype{4}};
        BOOST_CHECK(t.Verify(stack, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(!t.Verify(stack, POLICY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);

        // An unknown key type costs 50 budget units, so a small witness pays for one check.
        std::vector<valtype> small{valtype{0x55}, valtype{1}};
        BOOST_CHECK(t.Verify(small, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

        // c = 0 uses no budget and pushes n.
        const SLHScriptTest t0{CScript() << OP_5 << unknown_key << OP_CHECKSIGPQADD << OP_5 << OP_NUMEQUAL};
        BOOST_CHECK(t0.Verify({empty}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    // Budget: 50 units per check with c > 0 for an unknown key type, and 2,000 units for key type
    // 0x01. The witness has one 520-byte element that the leaf drops. Each check of the leaf
    // pushes its own 1-byte chunk.
    {
        const auto checks_leaf{[&](int checks, const valtype& key) {
            CScript leaf{CScript() << OP_DROP << OP_0};
            for (int i = 0; i < checks; ++i) {
                leaf << valtype{0x55} << OP_1 << OP_ROT << key << OP_CHECKSIGPQADD;
            }
            leaf << checks << OP_NUMEQUAL;
            return SLHScriptTest{leaf};
        }};
        const std::vector<valtype> stack{valtype(MAX_SCRIPT_ELEMENT_SIZE, 0x55)};
        BOOST_CHECK(checks_leaf(3, unknown_key).Verify(stack, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(!checks_leaf(40, unknown_key).Verify(stack, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
        // One check with key type 0x01 does not fit the same budget (step 7 comes before step 9).
        BOOST_CHECK(!checks_leaf(1, valtype(33, 0x01)).Verify(stack, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
    }

    // Empty public key fails, also with c = 0.
    {
        const SLHScriptTest t{CScript() << OP_0 << OP_0 << OP_CHECKSIGPQADD};
        BOOST_CHECK(!t.Verify({empty}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
        // Step 4 (count encoding) comes before step 6 (empty public key).
        BOOST_CHECK(!t.Verify({valtype{0x80}}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_CHUNK_COUNT);
        // Step 5 (enough chunks) comes before step 6.
        BOOST_CHECK(!t.Verify({valtype{2}}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // Key type 0x01 with a wrong public key size fails, also with c = 0.
    {
        const SLHScriptTest t{CScript() << OP_0 << valtype(32, 0x01) << OP_CHECKSIGPQADD << OP_0 << OP_NUMEQUAL};
        BOOST_CHECK(!t.Verify({empty}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_PUBKEY_SIZE);
        // Step 7 (budget) comes before step 8.
        BOOST_CHECK(!t.Verify({valtype{1}, valtype{1}}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT);
    }

    // Key type 0x01 with c = 0 pushes n without verification.
    {
        const SLHScriptTest t{CScript() << OP_3 << valtype(33, 0x01) << OP_CHECKSIGPQADD << OP_3 << OP_NUMEQUAL};
        BOOST_CHECK(t.Verify({empty}, POLICY_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    }

    // Key type 0x01 with c that is not 16.
    {
        const SLHScriptTest t{CScript() << OP_0 << valtype(33, 0x01) << OP_CHECKSIGPQADD};
        std::vector<valtype> stack(4, valtype(MAX_SCRIPT_ELEMENT_SIZE, 1));
        stack.push_back({4});
        BOOST_CHECK(!t.Verify(stack, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SLHDSA_SIG_SIZE);
    }

    // n larger than 4 bytes fails.
    {
        const SLHScriptTest t{CScript() << valtype(5, 1) << valtype{0x02} << OP_CHECKSIGPQADD};
        BOOST_CHECK(!t.Verify({empty}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SCRIPTNUM);
    }

    // Fewer than 3 stack elements fails.
    {
        const SLHScriptTest t{CScript() << valtype{0x02} << OP_CHECKSIGPQADD};
        BOOST_CHECK(!t.Verify({empty}, CONSENSUS_FLAGS, err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
    }

    // The opcode is unknown outside tapscript.
    {
        std::vector<valtype> stack{empty, empty, valtype{0x02}};
        ScriptExecutionData execdata;
        execdata.m_pqsig_enabled = true;
        BOOST_CHECK(!EvalScript(stack, CScript() << OP_CHECKSIGPQADD, CONSENSUS_FLAGS, BaseSignatureChecker{}, SigVersion::WITNESS_V0, execdata, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
        // In an unexecuted branch it has no effect.
        stack = {};
        BOOST_CHECK(EvalScript(stack, CScript() << OP_0 << OP_IF << OP_CHECKSIGPQADD << OP_ENDIF << OP_1, CONSENSUS_FLAGS, BaseSignatureChecker{}, SigVersion::BASE, &err));
    }
}

BOOST_AUTO_TEST_SUITE_END()
