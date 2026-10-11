// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sigcache.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <span.h>
#include <streams.h>
#include <test/util/json.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

script_verify_flags ParseScriptFlags(std::string strFlags);

BOOST_AUTO_TEST_SUITE(script_assets_tests)

template <typename T>
CScript ToScript(const T& byte_container)
{
    auto span{MakeUCharSpan(byte_container)};
    return {span.begin(), span.end()};
}

static CScript ScriptFromHex(const std::string& str)
{
    return ToScript(*Assert(TryParseHex(str)));
}

static CMutableTransaction TxFromHex(const std::string& str)
{
    CMutableTransaction tx;
    SpanReader{ParseHex(str)} >> TX_NO_WITNESS(tx);
    return tx;
}

static std::vector<CTxOut> TxOutsFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    std::vector<CTxOut> prevouts;
    for (size_t i = 0; i < univalue.size(); ++i) {
        CTxOut txout;
        SpanReader{ParseHex(univalue[i].get_str())} >> txout;
        prevouts.push_back(std::move(txout));
    }
    return prevouts;
}

static CScriptWitness ScriptWitnessFromJSON(const UniValue& univalue)
{
    assert(univalue.isArray());
    CScriptWitness scriptwitness;
    for (size_t i = 0; i < univalue.size(); ++i) {
        auto bytes = ParseHex(univalue[i].get_str());
        scriptwitness.stack.push_back(std::move(bytes));
    }
    return scriptwitness;
}

static std::vector<script_verify_flags> AllConsensusFlags()
{
    std::vector<script_verify_flags> ret;

    for (unsigned int i = 0; i < 512; ++i) {
        script_verify_flags flag = 0;
        if (i & 1) flag |= SCRIPT_VERIFY_P2SH;
        if (i & 2) flag |= SCRIPT_VERIFY_DERSIG;
        if (i & 4) flag |= SCRIPT_VERIFY_NULLDUMMY;
        if (i & 8) flag |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (i & 16) flag |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (i & 32) flag |= SCRIPT_VERIFY_WITNESS;
        if (i & 64) flag |= SCRIPT_VERIFY_TAPROOT;
        if (i & 128) flag |= SCRIPT_VERIFY_P2MR;
        if (i & 256) flag |= SCRIPT_VERIFY_PQSIG;

        // SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH
        if (flag & SCRIPT_VERIFY_WITNESS && !(flag & SCRIPT_VERIFY_P2SH)) continue;
        // SCRIPT_VERIFY_TAPROOT requires SCRIPT_VERIFY_WITNESS
        if (flag & SCRIPT_VERIFY_TAPROOT && !(flag & SCRIPT_VERIFY_WITNESS)) continue;
        // SCRIPT_VERIFY_P2MR requires SCRIPT_VERIFY_TAPROOT (both are needed for the draft deployment)
        if (flag & SCRIPT_VERIFY_P2MR && !(flag & SCRIPT_VERIFY_TAPROOT)) continue;
        // SCRIPT_VERIFY_PQSIG requires SCRIPT_VERIFY_P2MR (P2MR is the only enabled output type)
        if (flag & SCRIPT_VERIFY_PQSIG && !(flag & SCRIPT_VERIFY_P2MR)) continue;

        ret.push_back(flag);
    }

    return ret;
}

/** Precomputed list of all valid combinations of consensus-relevant script validation flags. */
static const std::vector<script_verify_flags> ALL_CONSENSUS_FLAGS = AllConsensusFlags();

/** Parse the expected error from a test comment that contains "[failure: NAME]".
 *  The SLH-DSA tapscript BIP draft vectors use this form. */
static std::optional<ScriptError> ExpectedError(const UniValue& test)
{
    if (!test.exists("comment")) return std::nullopt;
    const std::string& comment{test["comment"].get_str()};
    static constexpr std::string_view PREFIX{"[failure: "};
    const auto start{comment.find(PREFIX)};
    if (start == std::string::npos) return std::nullopt;
    const auto end{comment.find(']', start)};
    if (end == std::string::npos) return std::nullopt;
    const std::string name{comment.substr(start + PREFIX.size(), end - start - PREFIX.size())};
    static const std::map<std::string, ScriptError> ERRORS{
        {"SLH_SIG", SCRIPT_ERR_SLHDSA_SIG},
        {"SLH_COUNT", SCRIPT_ERR_SLHDSA_CHUNK_COUNT},
        {"SLH_SIG_SIZE", SCRIPT_ERR_SLHDSA_SIG_SIZE},
        {"SLH_PUBKEY_SIZE", SCRIPT_ERR_SLHDSA_PUBKEY_SIZE},
        {"EVAL_FALSE", SCRIPT_ERR_EVAL_FALSE},
        {"TAPSCRIPT_VALIDATION_WEIGHT", SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT},
        {"TAPSCRIPT_EMPTY_PUBKEY", SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY},
        {"INVALID_STACK_OPERATION", SCRIPT_ERR_INVALID_STACK_OPERATION},
        {"CLEANSTACK", SCRIPT_ERR_CLEANSTACK},
        {"PUSH_SIZE", SCRIPT_ERR_PUSH_SIZE},
        {"WITNESS_PROGRAM_MISMATCH", SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH},
        {"SCRIPTNUM", SCRIPT_ERR_SCRIPTNUM},
    };
    const auto it{ERRORS.find(name)};
    BOOST_CHECK_MESSAGE(it != ERRORS.end(), "Unknown expected error " << name);
    if (it == ERRORS.end()) return std::nullopt;
    return it->second;
}

static void AssetTest(const UniValue& test, SignatureCache& signature_cache)
{
    BOOST_CHECK(test.isObject());

    CMutableTransaction mtx = TxFromHex(test["tx"].get_str());
    const std::vector<CTxOut> prevouts = TxOutsFromJSON(test["prevouts"]);
    BOOST_CHECK(prevouts.size() == mtx.vin.size());
    size_t idx = test["index"].getInt<int64_t>();
    script_verify_flags test_flags{ParseScriptFlags(test["flags"].get_str())};
    bool fin = test.exists("final") && test["final"].get_bool();

    if (test.exists("success")) {
        mtx.vin[idx].scriptSig = ScriptFromHex(test["success"]["scriptSig"].get_str());
        mtx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["success"]["witness"]);
        CTransaction tx(mtx);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        CachingTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, true, signature_cache, txdata);

        for (const auto flags : ALL_CONSENSUS_FLAGS) {
            // "final": true tests are valid for all flags. Others are only valid with flags that are
            // a subset of test_flags.
            if (fin || ((flags & test_flags) == flags)) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                BOOST_CHECK(ret);
            }
        }
    }

    if (test.exists("failure")) {
        mtx.vin[idx].scriptSig = ScriptFromHex(test["failure"]["scriptSig"].get_str());
        mtx.vin[idx].scriptWitness = ScriptWitnessFromJSON(test["failure"]["witness"]);
        CTransaction tx(mtx);
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(prevouts));
        CachingTransactionSignatureChecker txcheck(&tx, idx, prevouts[idx].nValue, true, signature_cache, txdata);

        if (const auto expected{ExpectedError(test)}) {
            ScriptError err;
            BOOST_CHECK(!VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, test_flags, txcheck, &err));
            BOOST_CHECK_MESSAGE(err == *expected, test["comment"].get_str() << ": got " << ScriptErrorString(err));
        }

        for (const auto flags : ALL_CONSENSUS_FLAGS) {
            // If a test is supposed to fail with test_flags, it should also fail with any superset thereof.
            if ((flags & test_flags) == test_flags) {
                bool ret = VerifyScript(tx.vin[idx].scriptSig, prevouts[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags, txcheck, nullptr);
                BOOST_CHECK(!ret);
            }
        }
    }
}

static void RunAssetTestFile(const fs::path& path)
{
    SignatureCache signature_cache{DEFAULT_SIGNATURE_CACHE_BYTES};
    std::ifstream file{path.std_path()};
    BOOST_CHECK(file.is_open());
    file.seekg(0, std::ios::end);
    size_t length = file.tellg();
    file.seekg(0, std::ios::beg);
    std::string data(length, '\0');
    file.read(data.data(), data.size());
    UniValue tests = read_json(data);
    BOOST_CHECK(tests.isArray());
    BOOST_CHECK(tests.size() > 0);

    for (size_t i = 0; i < tests.size(); i++) {
        AssetTest(tests[i], signature_cache);
    }
    file.close();
}

BOOST_AUTO_TEST_CASE(script_assets_test)
{
    // See src/test/fuzz/script_assets_test_minimizer.cpp for information on how to generate
    // the script_assets_test.json file used by this test.
    const char* dir = std::getenv("DIR_UNIT_TEST_DATA");
    BOOST_WARN_MESSAGE(dir != nullptr, "Variable DIR_UNIT_TEST_DATA unset, skipping script_assets_test");
    if (dir == nullptr) return;
    auto path = fs::path(dir) / "script_assets_test.json";
    bool exists = fs::exists(path);
    BOOST_WARN_MESSAGE(exists, "File $DIR_UNIT_TEST_DATA/script_assets_test.json not found, skipping script_assets_test");
    if (!exists) return;
    RunAssetTestFile(path);
}

BOOST_AUTO_TEST_CASE(slh_tapscript_vectors)
{
    // Test vectors of the SLH-DSA tapscript BIP draft (bip-slh-tapscript/vectors.json).
    // They use the script_assets_test format, with the flags P2MR and PQSIG.
    // Set SLH_TAPSCRIPT_VECTORS to the path of the file to run them.
    const char* file = std::getenv("SLH_TAPSCRIPT_VECTORS");
    BOOST_WARN_MESSAGE(file != nullptr, "Variable SLH_TAPSCRIPT_VECTORS unset, skipping slh_tapscript_vectors");
    if (file == nullptr) return;
    const fs::path path = fs::PathFromString(file);
    BOOST_REQUIRE_MESSAGE(fs::exists(path), "File $SLH_TAPSCRIPT_VECTORS not found");
    RunAssetTestFile(path);
}

BOOST_AUTO_TEST_SUITE_END()
