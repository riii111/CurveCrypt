#include "curvecrypt/utility.h"
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace curvecrypt {
namespace util {

Result<std::vector<uint8_t>> generateRandomBytes(size_t count) {
    if (count == 0) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Count must be greater than 0"
        );
    }

    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::RandomGenerationFailed,
            "Failed to generate random bytes"
        );
    }
    
    return Result<std::vector<uint8_t>>::success(std::move(bytes));
}

std::string toHexString(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return ss.str();
}

Result<std::vector<uint8_t>> fromHexString(const std::string& hexString) {
    if (hexString.empty()) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Hex string is empty"
        );
    }
    
    if (hexString.length() % 2 != 0) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Hex string length must be even"
        );
    }
    
    std::vector<uint8_t> result;
    result.reserve(hexString.length() / 2);
    
    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            result.push_back(byte);
        } catch (const std::exception&) {
            return Result<std::vector<uint8_t>>::failure(
                ErrorCode::InvalidInput,
                "Invalid hex string: " + byteString
            );
        }
    }
    
    return Result<std::vector<uint8_t>>::success(std::move(result));
}

void secureErase(std::vector<uint8_t>& data) {
    // Use volatile to prevent compiler optimization
    volatile uint8_t* ptr = data.data();
    size_t size = data.size();
    
    // Overwrite all bytes with zeros
    for (size_t i = 0; i < size; ++i) {
        ptr[i] = 0;
    }
    
    // Clear the vector
    data.clear();
}

} // namespace util
} // namespace curvecrypt