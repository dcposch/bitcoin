// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_SLHDSA_H
#define BITCOIN_TEST_UTIL_SLHDSA_H

#include <crypto/slhdsa.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

/** SLH-DSA-SHA2-128s key generation and signing, for tests and benchmarks only.
 *
 * This code is not constant time and is not meant to protect secret keys. */
namespace slhdsa_test {

using Seed = std::array<unsigned char, slhdsa::N>;

struct SecretKey {
    Seed sk_seed;
    Seed sk_prf;
    Seed pk_seed;
    Seed pk_root;

    /** The 32-byte FIPS 205 public key PK.seed || PK.root. */
    std::array<unsigned char, slhdsa::PUBLIC_KEY_SIZE> PubKey() const;
};

/** FIPS 205 Algorithm 18 (slh_keygen_internal). */
SecretKey KeyGen(const Seed& sk_seed, const Seed& sk_prf, const Seed& pk_seed);

/** FIPS 205 Algorithm 19 (slh_sign_internal). Without addrnd the signature is deterministic. */
std::vector<unsigned char> SignInternal(const SecretKey& key, std::span<const unsigned char> msg, const std::optional<Seed>& addrnd = std::nullopt);

/** FIPS 205 Algorithm 22 (slh_sign), pure interface. */
std::vector<unsigned char> Sign(const SecretKey& key, std::span<const unsigned char> msg, std::span<const unsigned char> ctx = {}, const std::optional<Seed>& addrnd = std::nullopt);

/** Number of WOTS+ chain steps (calls of F in the chains) that slhdsa::Verify does
 *  for each of the D hypertree layers of a signature with the pure interface. */
std::array<uint32_t, slhdsa::D> WotsChainSteps(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> ctx = {});

/** Change a signature so that verification does more WOTS+ chain steps.
 *
 * For each hypertree layer, the function tries 2^grind_bits values for one
 * authentication path node of the layer below it (or of the last FORS tree,
 * for layer 0). It keeps the value that gives the most chain steps. The
 * result is not a valid signature, but slhdsa::Verify does all of its hash
 * computations before it compares the root, so the cost of the verification
 * is the same as for a valid signature with the same chain steps.
 */
std::vector<unsigned char> GrindHighWorkSignature(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::vector<unsigned char> sig, unsigned int grind_bits, std::span<const unsigned char> ctx = {});

} // namespace slhdsa_test

#endif // BITCOIN_TEST_UTIL_SLHDSA_H
