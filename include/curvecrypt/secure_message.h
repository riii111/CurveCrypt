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
     * Optionally authenticates additional associated data.
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