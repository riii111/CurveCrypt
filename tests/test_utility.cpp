#include <catch2/catch.hpp>
#include <curvecrypt/utility.h>
#include <algorithm>

using namespace curvecrypt;

TEST_CASE("Random Bytes Generation", "[utility]") {
    SECTION("Generate valid random bytes") {
        auto result = util::generateRandomBytes(32);
        REQUIRE(result.isSuccess());
        REQUIRE(result.value().size() == 32);
        
        // Verify that not all bytes are the same
        auto& bytes = result.value();
        bool allSame = std::all_of(bytes.begin() + 1, bytes.end(),
                                 [&bytes](uint8_t b) { return b == bytes[0]; });
        REQUIRE_FALSE(allSame);
    }
    
    SECTION("Zero size request fails") {
        auto result = util::generateRandomBytes(0);
        REQUIRE_FALSE(result.isSuccess());
        REQUIRE(result.errorCode() == ErrorCode::InvalidInput);
    }
}

TEST_CASE("Hex String Conversion", "[utility]") {
    SECTION("Binary to hex string") {
        std::vector<uint8_t> data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
        std::string hexString = util::toHexString(data);
        REQUIRE(hexString == "0123456789abcdef");
    }
    
    SECTION("Hex string to binary") {
        std::string hexString = "0123456789ABCDEF"; // Should be case-insensitive
        auto result = util::fromHexString(hexString);
        
        REQUIRE(result.isSuccess());
        REQUIRE(result.value().size() == 8);
        REQUIRE(result.value() == std::vector<uint8_t>({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}));
    }
    
    SECTION("Empty hex string fails") {
        auto result = util::fromHexString("");
        REQUIRE_FALSE(result.isSuccess());
        REQUIRE(result.errorCode() == ErrorCode::InvalidInput);
    }
    
    SECTION("Odd length hex string fails") {
        auto result = util::fromHexString("123");
        REQUIRE_FALSE(result.isSuccess());
        REQUIRE(result.errorCode() == ErrorCode::InvalidInput);
    }
    
    SECTION("Invalid hex string fails") {
        auto result = util::fromHexString("01ZX56");
        REQUIRE_FALSE(result.isSuccess());
        REQUIRE(result.errorCode() == ErrorCode::InvalidInput);
    }
}

TEST_CASE("Secure Erase", "[utility]") {
    std::vector<uint8_t> sensitiveData = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    util::secureErase(sensitiveData);
    
    REQUIRE(sensitiveData.empty());
}