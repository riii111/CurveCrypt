#include "curvecrypt/error.h"

namespace curvecrypt {

std::string getErrorMessage(ErrorCode code) {
    switch (code) {
        case ErrorCode::Success:
            return "Success";
        case ErrorCode::InvalidKey:
            return "Invalid key format or content";
        case ErrorCode::InvalidCurve:
            return "Unsupported or invalid curve";
        case ErrorCode::KeyGenerationFailed:
            return "Failed to generate key pair";
        case ErrorCode::ExchangeFailed:
            return "Failed to perform key exchange";
        case ErrorCode::EncryptionFailed:
            return "Failed to encrypt data";
        case ErrorCode::DecryptionFailed:
            return "Failed to decrypt data";
        case ErrorCode::AuthenticationFailed:
            return "Message authentication failed";
        case ErrorCode::RandomGenerationFailed:
            return "Failed to generate random bytes";
        case ErrorCode::InvalidInput:
            return "Invalid parameter or input data";
        case ErrorCode::InternalError:
            return "Internal library error";
        default:
            return "Unknown error";
    }
}

} // namespace curvecrypt