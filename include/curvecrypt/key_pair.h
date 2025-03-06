#ifndef CURVECRYPT_KEY_PAIR_H
#define CURVECRYPT_KEY_PAIR_H

#include "curvecrypt/types.h"
#include "curvecrypt/error.h"
#include <vector>
#include <string>
#include <memory>
#include <cstdint>

namespace curvecrypt {

/**
 * Represents a key pair (public and private) for ECDH exchange.
 */
class ECDHKeyPair {
public:
    /**
     * Create a new random key pair for the specified curve.
     */
    static std::unique_ptr<ECDHKeyPair> generate(CurveType curve = CurveType::X25519);
    
    /**
     * Create a key pair from an existing private key.
     */
    static std::unique_ptr<ECDHKeyPair> fromPrivateKey(const std::vector<uint8_t>& privateKey,
                                                    CurveType curve = CurveType::X25519);
    
    /**
     * Factory method to create a key pair from components.
     */
    static std::unique_ptr<ECDHKeyPair> create(std::vector<uint8_t> privateKey,
                                           std::vector<uint8_t> publicKey,
                                           CurveType curve);
    
    /**
     * Destructor - securely erases private key material.
     */
    ~ECDHKeyPair();
    
    // No copy, only move
    ECDHKeyPair(const ECDHKeyPair&) = delete;
    ECDHKeyPair& operator=(const ECDHKeyPair&) = delete;
    ECDHKeyPair(ECDHKeyPair&&) noexcept;
    ECDHKeyPair& operator=(ECDHKeyPair&&) noexcept;
    
    std::vector<uint8_t> getPublicKey() const;
    std::string getPublicKeyString() const;
    CurveType getCurveType() const;
    
    /**
     * Get the private key data.
     * This method should be used carefully and only within the library.
     */
    const std::vector<uint8_t>& getPrivateKey() const;
    
private:
    ECDHKeyPair(std::vector<uint8_t> privateKey, 
                std::vector<uint8_t> publicKey, 
                CurveType curve);
    
    std::vector<uint8_t> privateKey_; // Will be securely erased on destruction
    std::vector<uint8_t> publicKey_;
    CurveType curveType_;
};

} // namespace curvecrypt

#endif // CURVECRYPT_KEY_PAIR_H