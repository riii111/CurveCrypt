#ifndef CURVECRYPT_SECURE_MESSAGE_H
#define CURVECRYPT_SECURE_MESSAGE_H

#include "curvecrypt/error.h"
#include <vector>
#include <cstdint>

namespace curvecrypt {

/**
 * Simple authenticated encryption using derived keys.
 */
class SecureMessage {
public:
    /**
     * Encrypt a message using the derived symmetric key with AES-GCM.
     *
     * This method encrypts data using AES in Galois/Counter Mode (GCM), providing
     * both confidentiality and authenticity. The output includes a random nonce
     * and authentication tag.
     *
     * Format: [nonce][ciphertext][authentication tag]
     *
     * @param message The plaintext message to encrypt.
     * @param key The symmetric key derived from ECDH exchange (16, 24, or 32 bytes).
     * @param associatedData Optional authenticated data that is not encrypted but
     *                      is authenticated. This can be used to authenticate
     *                      additional context data (like headers, IDs, etc.).
     * @return Result containing the encrypted message or an error.
     */
    static Result<std::vector<uint8_t>> encrypt(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& associatedData = {});
    
    /**
     * Decrypt and authenticate a message using the derived symmetric key.
     * If authentication fails, returns an error.
     */
    static Result<std::vector<uint8_t>> decrypt(
        const std::vector<uint8_t>& encryptedMessage,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& associatedData = {});
};

} // namespace curvecrypt

#endif // CURVECRYPT_SECURE_MESSAGE_H