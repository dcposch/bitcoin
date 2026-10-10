// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa.h>
#include <test/data/slhdsa_acvp.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <test/util/slhdsa.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

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

BOOST_AUTO_TEST_SUITE_END()
