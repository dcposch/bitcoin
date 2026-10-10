// Copyright (c) The slhdsa-c project authors
// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SLHDSA_H
#define BITCOIN_CRYPTO_SLHDSA_H

#include <crypto/sha256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

/** Verification of SLH-DSA-SHA2-128s signatures (NIST FIPS 205).
 *
 * Only signature verification is implemented. All SHA-256 computations use
 * CSHA256, so they benefit from the hardware accelerated SHA-256
 * implementations selected by SHA256AutoDetect().
 *
 * The code is derived from the portable C implementation slhdsa-c
 * (https://github.com/slh-dsa/slhdsa-c, commit 2b111e076a3b), which is
 * available under the Apache-2.0, ISC, or MIT license. It is used here under
 * the MIT license.
 */
namespace slhdsa {

/** FIPS 205 parameters of SLH-DSA-SHA2-128s (Table 2). */
inline constexpr size_t N{16};      //!< Security parameter, in bytes.
inline constexpr size_t H{63};      //!< Total height of the hypertree.
inline constexpr size_t D{7};       //!< Number of hypertree layers.
inline constexpr size_t HP{9};      //!< Height of each XMSS tree (h').
inline constexpr size_t A{12};      //!< Height of each FORS tree.
inline constexpr size_t K{14};      //!< Number of FORS trees.
inline constexpr size_t LG_W{4};    //!< log2 of the Winternitz parameter.
inline constexpr size_t W{16};      //!< Winternitz parameter.
inline constexpr size_t M{30};      //!< Length of the message digest, in bytes.
inline constexpr size_t LEN1{32};   //!< Number of WOTS+ message chains.
inline constexpr size_t LEN2{3};    //!< Number of WOTS+ checksum chains.
inline constexpr size_t LEN{LEN1 + LEN2};

inline constexpr size_t PUBLIC_KEY_SIZE{2 * N};
inline constexpr size_t SIGNATURE_SIZE{(1 + K * (1 + A) + H + D * LEN) * N};
static_assert(SIGNATURE_SIZE == 7856);

/** Maximum length of the context string of the pure SLH-DSA interface. */
inline constexpr size_t MAX_CONTEXT_SIZE{255};

/** Compressed 22-byte address (ADRSc, FIPS 205 section 11.2). */
class Address
{
    std::array<uint8_t, 22> m_data{};

    void WriteBE32(size_t pos, uint32_t v)
    {
        m_data[pos] = v >> 24;
        m_data[pos + 1] = v >> 16;
        m_data[pos + 2] = v >> 8;
        m_data[pos + 3] = v;
    }
    uint32_t ReadBE32(size_t pos) const
    {
        return (uint32_t{m_data[pos]} << 24) | (uint32_t{m_data[pos + 1]} << 16) | (uint32_t{m_data[pos + 2]} << 8) | uint32_t{m_data[pos + 3]};
    }

public:
    /** Address types (FIPS 205 section 4.2). */
    enum Type : uint8_t {
        WOTS_HASH = 0,
        WOTS_PK = 1,
        TREE = 2,
        FORS_TREE = 3,
        FORS_ROOTS = 4,
        WOTS_PRF = 5,
        FORS_PRF = 6,
    };

    void SetLayerAddress(uint32_t layer) { m_data[0] = layer; }
    void SetTreeAddress(uint64_t tree)
    {
        for (int i = 0; i < 8; ++i) m_data[1 + i] = tree >> (56 - 8 * i);
    }
    /** setTypeAndClear: set the type and clear the following three words. */
    void SetTypeAndClear(Type type)
    {
        m_data[9] = type;
        for (size_t i = 10; i < 22; ++i) m_data[i] = 0;
    }
    void SetKeyPairAddress(uint32_t v) { WriteBE32(10, v); }
    uint32_t GetKeyPairAddress() const { return ReadBE32(10); }
    void SetChainAddress(uint32_t v) { WriteBE32(14, v); }
    void SetTreeHeight(uint32_t v) { WriteBE32(14, v); }
    void SetHashAddress(uint32_t v) { WriteBE32(18, v); }
    void SetTreeIndex(uint32_t v) { WriteBE32(18, v); }
    uint32_t GetTreeIndex() const { return ReadBE32(18); }

    const uint8_t* data() const { return m_data.data(); }
    static constexpr size_t size() { return 22; }
};

/** The tweakable hash functions F, H, and T_l of the SHA2 parameter sets for
 *  security category 1 (FIPS 205 section 11.2.1). They are all
 *  Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || input)).
 *  The PRF function of the signer has the same form, with SK.seed as input. */
class HashContext
{
    CSHA256 m_seeded; //!< SHA-256 state after PK.seed || toByte(0, 64 - n).

public:
    explicit HashContext(std::span<const unsigned char, N> pk_seed);
    void Hash(const Address& adrs, std::span<const unsigned char> in, std::span<unsigned char, N> out) const;
};

namespace detail {
/** Algorithm 4: base_2b(X, b, out_len). */
void Base2b(std::span<const unsigned char> in, unsigned int b, std::span<uint32_t> out);
/** WOTS+ message and checksum digits of an n-byte message (Algorithms 7 and 8). */
std::array<uint32_t, LEN> WotsDigits(std::span<const unsigned char, N> msg);
/** Algorithm 8: wots_pkFromSig. */
void WotsPkFromSig(const HashContext& ctx, Address& adrs, std::span<const unsigned char, LEN * N> sig, std::span<const unsigned char, N> msg, std::span<unsigned char, N> pk_out);
/** Algorithm 11: xmss_pkFromSig. */
void XmssPkFromSig(const HashContext& ctx, Address& adrs, uint32_t idx, std::span<const unsigned char, (LEN + HP) * N> sig, std::span<const unsigned char, N> msg, std::span<unsigned char, N> root_out);
/** Algorithm 17: fors_pkFromSig. */
void ForsPkFromSig(const HashContext& ctx, Address& adrs, std::span<const unsigned char, K * (A + 1) * N> sig, std::span<const unsigned char> md, std::span<unsigned char, N> pk_out);
/** H_msg(R, PK.seed, PK.root, prefix || M) for security category 1 (section 11.2.1). */
std::array<unsigned char, M> HashMessage(std::span<const unsigned char, N> r, std::span<const unsigned char, PUBLIC_KEY_SIZE> pubkey, std::span<const unsigned char> prefix, std::span<const unsigned char> msg);
/** Split a message digest into md, idx_tree, and idx_leaf (Algorithm 20, lines 6 to 10). */
void SplitDigest(std::span<const unsigned char, M> digest, uint64_t& idx_tree, uint32_t& idx_leaf);
} // namespace detail

/** Verify a signature with the pure SLH-DSA-SHA2-128s interface
 *  (FIPS 205 Algorithm 24, slh_verify).
 *
 * @param[in] pubkey  The 32-byte public key PK.seed || PK.root.
 * @param[in] msg     The message M. It is not hashed first.
 * @param[in] sig     The signature.
 * @param[in] ctx     The context string (at most 255 bytes).
 * @return whether the signature is valid.
 */
bool Verify(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig, std::span<const unsigned char> ctx = {});

/** Verify a signature with the internal interface (FIPS 205 Algorithm 20,
 *  slh_verify_internal). The message is used as it is, without the domain
 *  separator and context prefix of the pure interface. */
bool VerifyInternal(std::span<const unsigned char> pubkey, std::span<const unsigned char> msg, std::span<const unsigned char> sig);

} // namespace slhdsa

#endif // BITCOIN_CRYPTO_SLHDSA_H
