#ifndef CURVECRYPT_TYPES_H
#define CURVECRYPT_TYPES_H

#include <cstdint>

namespace curvecrypt {

/**
 * Supported elliptic curve types.
 */
enum class CurveType {
    X25519,    // Modern curve (RFC 7748)
    SECP256R1, // NIST P-256
    SECP384R1  // NIST P-384
};

} // namespace curvecrypt

#endif // CURVECRYPT_TYPES_H