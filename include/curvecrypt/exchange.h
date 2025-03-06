#ifndef CURVECRYPT_EXCHANGE_H
#define CURVECRYPT_EXCHANGE_H

#include "curvecrypt/key_pair.h"
#include "curvecrypt/error.h"
#include <vector>
#include <memory>
#include <string>
#include <cstdint>

namespace curvecrypt {

/**
 * Handles the ECDH exchange process.
 */
class ECDHExchange {
public:
    /**
     * Create a new exchange with our key pair.
     */
    explicit ECDHExchange(std::unique_ptr<ECDHKeyPair> keyPair);
    
    /**
     * Perform key exchange with peer's public key to generate a shared secret.
     */
    Result<std::vector<uint8_t>> deriveSharedSecret(const std::vector<uint8_t>& peerPublicKey);
    
    /**
     * Derive a symmetric key from the shared secret.
     * 
     * This method implements HKDF (RFC 5869) for deriving cryptographic keys.
     * 
     * @param sharedSecret The shared secret from ECDH exchange.
     * @param keyLength The desired length of the derived key in bytes.
     * @param context A context string for domain separation. Using different contexts
     *                produces different keys from the same shared secret, allowing
     *                multiple independent keys to be derived.
     * @param salt Optional salt value for additional randomness and security.
     *             Not required for security but can provide hedging against bad RNGs.
     * @return Result containing the derived key or an error.
     */
    Result<std::vector<uint8_t>> deriveSymmetricKey(
        const std::vector<uint8_t>& sharedSecret,
        size_t keyLength = 32,
        const std::string& context = "CurveCrypt Key",
        const std::vector<uint8_t>& salt = {});
    
    /**
     * Get our public key to send to peer.
     */
    std::vector<uint8_t> getPublicKey() const;
    
private:
    std::unique_ptr<ECDHKeyPair> keyPair_;
};

} // namespace curvecrypt

#endif // CURVECRYPT_EXCHANGE_H