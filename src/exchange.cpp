#include "curvecrypt/exchange.h"
#include "curvecrypt/utility.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <cstring>

namespace curvecrypt {

namespace {

// X25519 key exchange implementation using OpenSSL
Result<std::vector<uint8_t>> computeX25519SharedSecret(
    const std::vector<uint8_t>& privateKey,
    const std::vector<uint8_t>& peerPublicKey) {
    
    if (privateKey.size() != 32 || peerPublicKey.size() != 32) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidKey,
            "Invalid key size for X25519"
        );
    }
    
    EVP_PKEY* privKey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size());
    
    if (!privKey) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to create private key context"
        );
    }
    
    EVP_PKEY* pubKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, peerPublicKey.data(), peerPublicKey.size());
    
    if (!pubKey) {
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to create public key context"
        );
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to create key exchange context"
        );
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::ExchangeFailed,
            "Failed to initialize key exchange"
        );
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, pubKey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::ExchangeFailed,
            "Failed to set peer key"
        );
    }
    
    // Two-step derive: first get length, then the actual secret
    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::ExchangeFailed,
            "Failed to determine shared secret size"
        );
    }
    
    std::vector<uint8_t> sharedSecret(secretLen);
    if (EVP_PKEY_derive(ctx, sharedSecret.data(), &secretLen) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pubKey);
        EVP_PKEY_free(privKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::ExchangeFailed,
            "Failed to compute shared secret"
        );
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubKey);
    EVP_PKEY_free(privKey);
    
    return Result<std::vector<uint8_t>>::success(std::move(sharedSecret));
}

// NIST curve (secp256r1, secp384r1) key exchange implementation
Result<std::vector<uint8_t>> computeNistSharedSecret(
    const std::vector<uint8_t>& privateKey,
    const std::vector<uint8_t>& peerPublicKey,
    CurveType curve) {
    
    int nid;
    switch (curve) {
        case CurveType::SECP256R1:
            nid = NID_X9_62_prime256v1;
            break;
        case CurveType::SECP384R1:
            nid = NID_secp384r1;
            break;
        default:
            return Result<std::vector<uint8_t>>::failure(
                ErrorCode::InvalidCurve,
                "Unsupported curve type"
            );
    }
    
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(nid);
    if (!ecKey) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to create EC key"
        );
    }
    
    BIGNUM* privateKeyBN = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!privateKeyBN) {
        EC_KEY_free(ecKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to convert private key to BIGNUM"
        );
    }
    
    if (EC_KEY_set_private_key(ecKey, privateKeyBN) != 1) {
        BN_free(privateKeyBN);
        EC_KEY_free(ecKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to set private key"
        );
    }
    
    BN_free(privateKeyBN);
    
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* peerPoint = EC_POINT_new(group);
    
    if (!peerPoint) {
        EC_KEY_free(ecKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "Failed to create point for peer public key"
        );
    }
    
    if (EC_POINT_oct2point(
            group, peerPoint, peerPublicKey.data(), peerPublicKey.size(), nullptr) != 1) {
        EC_POINT_free(peerPoint);
        EC_KEY_free(ecKey);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidKey,
            "Invalid peer public key format"
        );
    }
    
    // Calculate key size based on curve bit length
    size_t secretSize = (EC_GROUP_get_degree(group) + 7) / 8;
    std::vector<uint8_t> sharedSecret(secretSize);
    
    int secretLen = ECDH_compute_key(
        sharedSecret.data(), secretSize, peerPoint, ecKey, nullptr);
    
    EC_POINT_free(peerPoint);
    EC_KEY_free(ecKey);
    
    if (secretLen <= 0) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::ExchangeFailed,
            "Failed to compute shared secret"
        );
    }
    
    sharedSecret.resize(secretLen);
    return Result<std::vector<uint8_t>>::success(std::move(sharedSecret));
}

// HKDF-Extract function (RFC 5869) - produces pseudorandom key
std::vector<uint8_t> hkdfExtract(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm) {
    
    const uint8_t* saltPtr = salt.empty() ? nullptr : salt.data();
    size_t saltLen = salt.empty() ? 0 : salt.size();
    
    std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
    unsigned int prkLen;
    
    HMAC(EVP_sha256(), saltPtr, saltLen, ikm.data(), ikm.size(), prk.data(), &prkLen);
    prk.resize(prkLen);
    
    return prk;
}

// HKDF-Expand function (RFC 5869) - expands pseudorandom key to desired length
std::vector<uint8_t> hkdfExpand(
    const std::vector<uint8_t>& prk,
    const std::vector<uint8_t>& info,
    size_t length) {
    
    std::vector<uint8_t> output;
    output.reserve(length);
    
    std::vector<uint8_t> T;
    unsigned int Tlen;
    uint8_t counter = 1;
    
    // T(0) = empty string
    // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    // T(N) = HMAC-Hash(PRK, T(N-1) | info | N)
    while (output.size() < length) {
        HMAC_CTX* ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk.data(), prk.size(), EVP_sha256(), nullptr);
        
        if (!T.empty()) {
            HMAC_Update(ctx, T.data(), T.size());
        }
        
        if (!info.empty()) {
            HMAC_Update(ctx, info.data(), info.size());
        }
        
        HMAC_Update(ctx, &counter, 1);
        
        T.resize(EVP_MAX_MD_SIZE);
        HMAC_Final(ctx, T.data(), &Tlen);
        T.resize(Tlen);
        counter++;
        
        HMAC_CTX_free(ctx);
        
        size_t to_copy = std::min(T.size(), length - output.size());
        output.insert(output.end(), T.begin(), T.begin() + to_copy);
    }
    
    return output;
}

// Complete HKDF implementation (RFC 5869) - extract and expand in one step
std::vector<uint8_t> hkdf(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm,
    const std::vector<uint8_t>& info,
    size_t length) {
    
    std::vector<uint8_t> prk = hkdfExtract(salt, ikm);
    return hkdfExpand(prk, info, length);
}

} // anonymous namespace

ECDHExchange::ECDHExchange(std::unique_ptr<ECDHKeyPair> keyPair)
    : keyPair_(std::move(keyPair)) {
}

Result<std::vector<uint8_t>> ECDHExchange::deriveSharedSecret(
    const std::vector<uint8_t>& peerPublicKey) {
    
    if (!keyPair_) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InternalError,
            "No key pair available for exchange"
        );
    }
    
    if (peerPublicKey.empty()) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidKey,
            "Peer public key is empty"
        );
    }
    
    switch (keyPair_->getCurveType()) {
        case CurveType::X25519:
            return computeX25519SharedSecret(keyPair_->getPrivateKey(), peerPublicKey);
            
        case CurveType::SECP256R1:
        case CurveType::SECP384R1:
            return computeNistSharedSecret(
                keyPair_->getPrivateKey(), peerPublicKey, keyPair_->getCurveType());
            
        default:
            return Result<std::vector<uint8_t>>::failure(
                ErrorCode::InvalidCurve,
                "Unsupported curve type"
            );
    }
}

Result<std::vector<uint8_t>> ECDHExchange::deriveSymmetricKey(
    const std::vector<uint8_t>& sharedSecret,
    size_t keyLength,
    const std::string& context,
    const std::vector<uint8_t>& salt) {
    
    if (sharedSecret.empty()) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Shared secret is empty"
        );
    }
    
    if (keyLength == 0) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Key length must be greater than 0"
        );
    }
    
    // Convert context string to bytes
    std::vector<uint8_t> infoBytes(context.begin(), context.end());
    
    // Apply HKDF to derive the key
    std::vector<uint8_t> derivedKey = hkdf(salt, sharedSecret, infoBytes, keyLength);
    
    return Result<std::vector<uint8_t>>::success(std::move(derivedKey));
}

std::vector<uint8_t> ECDHExchange::getPublicKey() const {
    if (keyPair_) {
        return keyPair_->getPublicKey();
    }
    return {};
}

} // namespace curvecrypt