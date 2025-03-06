#include "curvecrypt/key_pair.h"
#include "curvecrypt/utility.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdexcept>

namespace curvecrypt {

namespace {

// Utility function to convert curve type to OpenSSL NID
int curveTypeToNID(CurveType curve) {
    switch (curve) {
        case CurveType::X25519:
            return EVP_PKEY_X25519;
        case CurveType::SECP256R1:
            return NID_X9_62_prime256v1;
        case CurveType::SECP384R1:
            return NID_secp384r1;
        default:
            return 0; // Invalid
    }
}

// Get key size for a given curve
size_t getKeySizeForCurve(CurveType curve) {
    switch (curve) {
        case CurveType::X25519:
            return 32; // X25519 uses 32-byte keys
        case CurveType::SECP256R1:
            return 32; // P-256 uses 32-byte keys
        case CurveType::SECP384R1:
            return 48; // P-384 uses 48-byte keys
        default:
            return 0; // Invalid
    }
}

// Generate key pair with OpenSSL for X25519
std::unique_ptr<ECDHKeyPair> generateX25519KeyPair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    // Extract private key
    size_t privateKeyLen = 32;
    std::vector<uint8_t> privateKey(privateKeyLen);
    if (EVP_PKEY_get_raw_private_key(pkey, privateKey.data(), &privateKeyLen) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    
    // Extract public key
    size_t publicKeyLen = 32;
    std::vector<uint8_t> publicKey(publicKeyLen);
    if (EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &publicKeyLen) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        util::secureErase(privateKey);
        return nullptr;
    }
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return ECDHKeyPair::create(std::move(privateKey), std::move(publicKey), CurveType::X25519);
}

// Create X25519 key pair from private key
std::unique_ptr<ECDHKeyPair> createX25519KeyPairFromPrivate(const std::vector<uint8_t>& privateKey) {
    if (privateKey.size() != 32) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size());
    
    if (!pkey) {
        return nullptr;
    }
    
    // Extract public key
    size_t publicKeyLen = 32;
    std::vector<uint8_t> publicKey(publicKeyLen);
    if (EVP_PKEY_get_raw_public_key(pkey, publicKey.data(), &publicKeyLen) <= 0) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    
    EVP_PKEY_free(pkey);
    
    return ECDHKeyPair::create(
        std::vector<uint8_t>(privateKey), std::move(publicKey), CurveType::X25519);
}

// Generate key pair with OpenSSL for NIST curves
std::unique_ptr<ECDHKeyPair> generateNistKeyPair(CurveType curve) {
    int nid = curveTypeToNID(curve);
    if (nid == 0) {
        return nullptr;
    }
    
    EVP_PKEY_CTX* paramCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!paramCtx) {
        return nullptr;
    }
    
    if (EVP_PKEY_paramgen_init(paramCtx) <= 0) {
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, nid) <= 0) {
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    EVP_PKEY* params = nullptr;
    if (EVP_PKEY_paramgen(paramCtx, &params) <= 0) {
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    EVP_PKEY_CTX* keyCtx = EVP_PKEY_CTX_new(params, nullptr);
    if (!keyCtx) {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    if (EVP_PKEY_keygen_init(keyCtx) <= 0) {
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(keyCtx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    // Extract private key and public key
    EC_KEY* ecKey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ecKey) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    const BIGNUM* privateKeyBN = EC_KEY_get0_private_key(ecKey);
    const EC_POINT* publicKeyPoint = EC_KEY_get0_public_key(ecKey);
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    
    if (!privateKeyBN || !publicKeyPoint || !group) {
        EC_KEY_free(ecKey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(keyCtx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(paramCtx);
        return nullptr;
    }
    
    // Convert private key to binary
    size_t privateKeySize = getKeySizeForCurve(curve);
    std::vector<uint8_t> privateKey(privateKeySize);
    BN_bn2binpad(privateKeyBN, privateKey.data(), privateKeySize);
    
    // Convert public key to binary (compressed form)
    size_t publicKeySize = EC_POINT_point2oct(
        group, publicKeyPoint, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::vector<uint8_t> publicKey(publicKeySize);
    EC_POINT_point2oct(
        group, publicKeyPoint, POINT_CONVERSION_COMPRESSED, 
        publicKey.data(), publicKeySize, nullptr);
    
    EC_KEY_free(ecKey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(keyCtx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(paramCtx);
    
    return ECDHKeyPair::create(
        std::move(privateKey), std::move(publicKey), curve);
}

// Create NIST key pair from private key
std::unique_ptr<ECDHKeyPair> createNistKeyPairFromPrivate(
    const std::vector<uint8_t>& privateKey, CurveType curve) {
    
    int nid = curveTypeToNID(curve);
    if (nid == 0) {
        return nullptr;
    }
    
    size_t keySize = getKeySizeForCurve(curve);
    if (privateKey.size() != keySize) {
        return nullptr;
    }
    
    // Create EC_KEY from private key
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(nid);
    if (!ecKey) {
        return nullptr;
    }
    
    BIGNUM* privateKeyBN = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!privateKeyBN) {
        EC_KEY_free(ecKey);
        return nullptr;
    }
    
    if (EC_KEY_set_private_key(ecKey, privateKeyBN) != 1) {
        BN_free(privateKeyBN);
        EC_KEY_free(ecKey);
        return nullptr;
    }
    
    // Compute public key
    const EC_GROUP* group = EC_KEY_get0_group(ecKey);
    EC_POINT* publicKeyPoint = EC_POINT_new(group);
    if (!publicKeyPoint) {
        BN_free(privateKeyBN);
        EC_KEY_free(ecKey);
        return nullptr;
    }
    
    if (EC_POINT_mul(group, publicKeyPoint, privateKeyBN, nullptr, nullptr, nullptr) != 1) {
        EC_POINT_free(publicKeyPoint);
        BN_free(privateKeyBN);
        EC_KEY_free(ecKey);
        return nullptr;
    }
    
    if (EC_KEY_set_public_key(ecKey, publicKeyPoint) != 1) {
        EC_POINT_free(publicKeyPoint);
        BN_free(privateKeyBN);
        EC_KEY_free(ecKey);
        return nullptr;
    }
    
    // Convert public key to binary (compressed form)
    size_t publicKeySize = EC_POINT_point2oct(
        group, publicKeyPoint, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    std::vector<uint8_t> publicKey(publicKeySize);
    EC_POINT_point2oct(
        group, publicKeyPoint, POINT_CONVERSION_COMPRESSED, 
        publicKey.data(), publicKeySize, nullptr);
    
    EC_POINT_free(publicKeyPoint);
    BN_free(privateKeyBN);
    EC_KEY_free(ecKey);
    
    return ECDHKeyPair::create(
        std::vector<uint8_t>(privateKey), std::move(publicKey), curve);
}

} // anonymous namespace

// ECDHKeyPair implementation

ECDHKeyPair::ECDHKeyPair(
    std::vector<uint8_t> privateKey, 
    std::vector<uint8_t> publicKey, 
    CurveType curve)
    : privateKey_(std::move(privateKey))
    , publicKey_(std::move(publicKey))
    , curveType_(curve) {
}

std::unique_ptr<ECDHKeyPair> ECDHKeyPair::create(
    std::vector<uint8_t> privateKey,
    std::vector<uint8_t> publicKey,
    CurveType curve) {
    return std::unique_ptr<ECDHKeyPair>(
        new ECDHKeyPair(std::move(privateKey), std::move(publicKey), curve));
}

ECDHKeyPair::~ECDHKeyPair() {
    util::secureErase(privateKey_);
}

ECDHKeyPair::ECDHKeyPair(ECDHKeyPair&& other) noexcept
    : privateKey_(std::move(other.privateKey_))
    , publicKey_(std::move(other.publicKey_))
    , curveType_(other.curveType_) {
}

ECDHKeyPair& ECDHKeyPair::operator=(ECDHKeyPair&& other) noexcept {
    if (this != &other) {
        util::secureErase(privateKey_);
        privateKey_ = std::move(other.privateKey_);
        publicKey_ = std::move(other.publicKey_);
        curveType_ = other.curveType_;
    }
    return *this;
}

std::unique_ptr<ECDHKeyPair> ECDHKeyPair::generate(CurveType curve) {
    switch (curve) {
        case CurveType::X25519:
            return generateX25519KeyPair();
        case CurveType::SECP256R1:
        case CurveType::SECP384R1:
            return generateNistKeyPair(curve);
        default:
            return nullptr;
    }
}

std::unique_ptr<ECDHKeyPair> ECDHKeyPair::fromPrivateKey(
    const std::vector<uint8_t>& privateKey, CurveType curve) {
    
    if (privateKey.empty()) {
        return nullptr;
    }
    
    switch (curve) {
        case CurveType::X25519:
            return createX25519KeyPairFromPrivate(privateKey);
        case CurveType::SECP256R1:
        case CurveType::SECP384R1:
            return createNistKeyPairFromPrivate(privateKey, curve);
        default:
            return nullptr;
    }
}

std::vector<uint8_t> ECDHKeyPair::getPublicKey() const {
    return publicKey_;
}

std::string ECDHKeyPair::getPublicKeyString() const {
    return util::toHexString(publicKey_);
}

CurveType ECDHKeyPair::getCurveType() const {
    return curveType_;
}

const std::vector<uint8_t>& ECDHKeyPair::getPrivateKey() const {
    return privateKey_;
}

} // namespace curvecrypt