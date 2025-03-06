#ifndef CURVECRYPT_ERROR_H
#define CURVECRYPT_ERROR_H

#include <string>
#include <utility>

namespace curvecrypt {

/**
 * Error codes for the CurveCrypt library.
 */
enum class ErrorCode {
    Success,                ///< Operation completed successfully
    InvalidKey,             ///< Invalid key format or content
    InvalidCurve,           ///< Unsupported or invalid curve
    KeyGenerationFailed,    ///< Failed to generate key pair
    ExchangeFailed,         ///< Failed to perform key exchange
    EncryptionFailed,       ///< Failed to encrypt data
    DecryptionFailed,       ///< Failed to decrypt data
    AuthenticationFailed,   ///< Message authentication failed
    RandomGenerationFailed, ///< Failed to generate random bytes
    InvalidInput,           ///< Invalid parameter or input data
    InternalError           ///< Internal library error
};

/**
 * Result template for error handling.
 * 
 * Provides a way to return either a successful value or an error code with message.
 */
template <typename T>
class Result {
public:
    /**
     * Create a success result with a value.
     */
    static Result<T> success(T value) {
        return Result<T>(std::move(value));
    }
    
    /**
     * Create a failure result with an error code and message.
     */
    static Result<T> failure(ErrorCode code, const std::string& message) {
        return Result<T>(code, message);
    }
    
    /**
     * Check if the result is successful.
     *
     * @return true if the operation was successful, false otherwise.
     */
    bool isSuccess() const {
        return success_;
    }
    
    /**
     * Get the value (throws if failure).
     *
     * @return Reference to the contained value.
     * @throws std::runtime_error if the operation failed.
     */
    const T& value() const;
    
    /**
     * Get the error code (throws if success).
     *
     * @return The error code.
     * @throws std::runtime_error if the operation was successful.
     */
    ErrorCode errorCode() const;
    
    /**
     * Get the error message (throws if success).
     *
     * @return Reference to the error message.
     * @throws std::runtime_error if the operation was successful.
     */
    const std::string& errorMessage() const;
    
private:
    // Success constructor
    explicit Result(T val)
        : success_(true)
        , value_(std::move(val))
        , errorCode_(ErrorCode::Success)
        , errorMessage_("") {}
    
    // Failure constructor
    Result(ErrorCode code, std::string message)
        : success_(false)
        , errorCode_(code)
        , errorMessage_(std::move(message)) {}
    
    bool success_;
    T value_;
    ErrorCode errorCode_;
    std::string errorMessage_;
};

// Template method implementations
template <typename T>
const T& Result<T>::value() const {
    if (!success_) {
        throw std::runtime_error("Attempted to access value of failed Result: " + errorMessage_);
    }
    return value_;
}

template <typename T>
ErrorCode Result<T>::errorCode() const {
    if (success_) {
        throw std::runtime_error("Attempted to access error code of successful Result");
    }
    return errorCode_;
}

template <typename T>
const std::string& Result<T>::errorMessage() const {
    if (success_) {
        throw std::runtime_error("Attempted to access error message of successful Result");
    }
    return errorMessage_;
}

/**
 * Get a string description for an error code.
 *
 * @param code The error code.
 * @return String description of the error code.
 */
std::string getErrorMessage(ErrorCode code);

} // namespace curvecrypt

#endif // CURVECRYPT_ERROR_H