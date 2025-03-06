#include <catch2/catch.hpp>
#include <curvecrypt/secure_message.h>
#include <curvecrypt/utility.h>
#include <string>

using namespace curvecrypt;

TEST_CASE("Authenticated Encryption Roundtrip", "[secure_message]") {
    // Generate a random key (32 bytes for AES-256)
    auto keyResult = util::generateRandomBytes(32);
    REQUIRE(keyResult.isSuccess());
    auto key = keyResult.value();
    
    // Create a test message
    std::string message = "This is a test message for encryption";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    // Encrypt the message
    auto encryptResult = SecureMessage::encrypt(plaintext, key);
    REQUIRE(encryptResult.isSuccess());
    auto ciphertext = encryptResult.value();
    
    // Verify that the ciphertext is longer than the plaintext (due to nonce and tag)
    REQUIRE(ciphertext.size() > plaintext.size());
    
    // Decrypt the message
    auto decryptResult = SecureMessage::decrypt(ciphertext, key);
    REQUIRE(decryptResult.isSuccess());
    auto decrypted = decryptResult.value();
    
    // Check that the decrypted message matches the original
    REQUIRE(decrypted == plaintext);
    
    // Convert back to string for easier comparison
    std::string decryptedMessage(decrypted.begin(), decrypted.end());
    REQUIRE(decryptedMessage == message);
}

TEST_CASE("Authenticated Data", "[secure_message]") {
    // Generate a random key
    auto keyResult = util::generateRandomBytes(32);
    REQUIRE(keyResult.isSuccess());
    auto key = keyResult.value();
    
    // Create a test message and associated data
    std::string message = "Secret message";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    std::string aad = "Associated authenticated data";
    std::vector<uint8_t> associatedData(aad.begin(), aad.end());
    
    // Encrypt with associated data
    auto encryptResult = SecureMessage::encrypt(plaintext, key, associatedData);
    REQUIRE(encryptResult.isSuccess());
    auto ciphertext = encryptResult.value();
    
    // Decrypt with same associated data
    auto decryptResult = SecureMessage::decrypt(ciphertext, key, associatedData);
    REQUIRE(decryptResult.isSuccess());
    REQUIRE(decryptResult.value() == plaintext);
    
    // Decrypt with different associated data should fail
    std::string differentAad = "Different authenticated data";
    std::vector<uint8_t> differentAssociatedData(differentAad.begin(), differentAad.end());
    
    auto failedResult = SecureMessage::decrypt(ciphertext, key, differentAssociatedData);
    REQUIRE_FALSE(failedResult.isSuccess());
    REQUIRE(failedResult.errorCode() == ErrorCode::AuthenticationFailed);
}

TEST_CASE("Authentication Verification", "[secure_message]") {
    // Generate a random key
    auto keyResult = util::generateRandomBytes(32);
    REQUIRE(keyResult.isSuccess());
    auto key = keyResult.value();
    
    // Create a test message
    std::string message = "This is a test message for encryption";
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    // Encrypt the message
    auto encryptResult = SecureMessage::encrypt(plaintext, key);
    REQUIRE(encryptResult.isSuccess());
    auto ciphertext = encryptResult.value();
    
    // Tamper with the ciphertext (modify a byte in the middle)
    size_t middleIndex = ciphertext.size() / 2;
    ciphertext[middleIndex] ^= 0x01;
    
    // Attempt to decrypt the tampered message
    auto decryptResult = SecureMessage::decrypt(ciphertext, key);
    REQUIRE_FALSE(decryptResult.isSuccess());
    REQUIRE(decryptResult.errorCode() == ErrorCode::AuthenticationFailed);
}

TEST_CASE("Encryption Error Handling", "[secure_message]") {
    // Generate a valid key
    auto keyResult = util::generateRandomBytes(32);
    REQUIRE(keyResult.isSuccess());
    auto key = keyResult.value();
    
    // Test with empty message
    auto result1 = SecureMessage::encrypt({}, key);
    REQUIRE_FALSE(result1.isSuccess());
    REQUIRE(result1.errorCode() == ErrorCode::InvalidInput);
    
    // Test with invalid key size (not 16, 24, or 32 bytes)
    std::vector<uint8_t> invalidKey(17, 0x42);
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    auto result2 = SecureMessage::encrypt(message, invalidKey);
    REQUIRE_FALSE(result2.isSuccess());
    REQUIRE(result2.errorCode() == ErrorCode::InvalidKey);
}

TEST_CASE("Decryption Error Handling", "[secure_message]") {
    // Generate a valid key
    auto keyResult = util::generateRandomBytes(32);
    REQUIRE(keyResult.isSuccess());
    auto key = keyResult.value();
    
    // Test with too short message
    std::vector<uint8_t> tooShort(10, 0x42);
    auto result1 = SecureMessage::decrypt(tooShort, key);
    REQUIRE_FALSE(result1.isSuccess());
    REQUIRE(result1.errorCode() == ErrorCode::InvalidInput);
    
    // Test with invalid key size
    std::vector<uint8_t> invalidKey(17, 0x42);
    std::vector<uint8_t> validCiphertext(40, 0x42);  // Long enough to have nonce and tag
    auto result2 = SecureMessage::decrypt(validCiphertext, invalidKey);
    REQUIRE_FALSE(result2.isSuccess());
    REQUIRE(result2.errorCode() == ErrorCode::InvalidKey);
}