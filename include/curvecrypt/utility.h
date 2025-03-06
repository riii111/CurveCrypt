#ifndef CURVECRYPT_UTILITY_H
#define CURVECRYPT_UTILITY_H

#include "curvecrypt/error.h"
#include <vector>
#include <string>
#include <cstdint>

namespace curvecrypt {
namespace util {

/**
 * Generate cryptographically secure random bytes.
 */
Result<std::vector<uint8_t>> generateRandomBytes(size_t count);

/**
 * Convert binary data to a hexadecimal string representation.
 */
std::string toHexString(const std::vector<uint8_t>& data);

/**
 * Convert a hexadecimal string to binary data.
 */
Result<std::vector<uint8_t>> fromHexString(const std::string& hexString);

/**
 * Securely erase sensitive data from memory.
 * 
 * Uses volatile pointer and explicit overwrite to prevent
 * compiler optimization from skipping the erasure.
 */
void secureErase(std::vector<uint8_t>& data);

} // namespace util
} // namespace curvecrypt

#endif // CURVECRYPT_UTILITY_H