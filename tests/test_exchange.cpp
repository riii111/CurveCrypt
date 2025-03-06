#include <catch2/catch.hpp>
#include <curvecrypt/exchange.h>

using namespace curvecrypt;

TEST_CASE("ECDH Shared Secret Derivation", "[exchange]") {
    // Generate two key pairs
    auto aliceKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    auto bobKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    
    REQUIRE(aliceKeyPair != nullptr);
    REQUIRE(bobKeyPair != nullptr);
    
    // Create exchange objects
    ECDHExchange aliceExchange(std::move(aliceKeyPair));
    ECDHExchange bobExchange(std::move(bobKeyPair));
    
    // Get public keys
    auto alicePublicKey = aliceExchange.getPublicKey();
    auto bobPublicKey = bobExchange.getPublicKey();
    
    REQUIRE(!alicePublicKey.empty());
    REQUIRE(!bobPublicKey.empty());
    
    // Derive shared secrets
    auto aliceSecretResult = aliceExchange.deriveSharedSecret(bobPublicKey);
    auto bobSecretResult = bobExchange.deriveSharedSecret(alicePublicKey);
    
    REQUIRE(aliceSecretResult.isSuccess());
    REQUIRE(bobSecretResult.isSuccess());
    
    // The shared secrets should be identical
    REQUIRE(aliceSecretResult.value() == bobSecretResult.value());
}

TEST_CASE("Key Derivation", "[exchange]") {
    // Generate a random shared secret
    std::vector<uint8_t> sharedSecret(32, 0x42);
    
    // Create exchange object (using a dummy key pair)
    auto keyPair = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair != nullptr);
    ECDHExchange exchange(std::move(keyPair));
    
    // Derive keys with different parameters
    auto keyResult1 = exchange.deriveSymmetricKey(sharedSecret);
    REQUIRE(keyResult1.isSuccess());
    REQUIRE(keyResult1.value().size() == 32);
    
    // Different key length
    auto keyResult2 = exchange.deriveSymmetricKey(sharedSecret, 16);
    REQUIRE(keyResult2.isSuccess());
    REQUIRE(keyResult2.value().size() == 16);
    
    // Different context
    auto keyResult3 = exchange.deriveSymmetricKey(sharedSecret, 32, "DifferentContext");
    REQUIRE(keyResult3.isSuccess());
    REQUIRE(keyResult3.value().size() == 32);
    
    // Keys with different parameters should be different
    REQUIRE(keyResult1.value() != keyResult2.value());
    REQUIRE(keyResult1.value() != keyResult3.value());
    
    // Keys with same parameters should be the same
    auto keyResult4 = exchange.deriveSymmetricKey(sharedSecret);
    REQUIRE(keyResult4.isSuccess());
    REQUIRE(keyResult1.value() == keyResult4.value());
}

TEST_CASE("ECDH Error Handling", "[exchange]") {
    // Generate key pair
    auto keyPair = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair != nullptr);
    ECDHExchange exchange(std::move(keyPair));
    
    // Try with empty public key
    auto result1 = exchange.deriveSharedSecret({});
    REQUIRE_FALSE(result1.isSuccess());
    REQUIRE(result1.errorCode() == ErrorCode::InvalidKey);
    
    // Try with invalid size public key
    std::vector<uint8_t> invalidKey(31, 0x42);  // X25519 needs 32 bytes
    auto result2 = exchange.deriveSharedSecret(invalidKey);
    REQUIRE_FALSE(result2.isSuccess());
    REQUIRE(result2.errorCode() == ErrorCode::InvalidKey);
    
    // Try with empty shared secret for key derivation
    auto result3 = exchange.deriveSymmetricKey({});
    REQUIRE_FALSE(result3.isSuccess());
    REQUIRE(result3.errorCode() == ErrorCode::InvalidInput);
    
    // Try with zero key length
    std::vector<uint8_t> sharedSecret(32, 0x42);
    auto result4 = exchange.deriveSymmetricKey(sharedSecret, 0);
    REQUIRE_FALSE(result4.isSuccess());
    REQUIRE(result4.errorCode() == ErrorCode::InvalidInput);
}