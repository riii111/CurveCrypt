#include <catch2/catch.hpp>
#include <curvecrypt/key_pair.h>
#include <curvecrypt/exchange.h>
#include <curvecrypt/utility.h>
#include <algorithm>

using namespace curvecrypt;

TEST_CASE("X25519 Key Generation", "[key_pair]") {
    auto keyPair = ECDHKeyPair::generate(CurveType::X25519);
    
    REQUIRE(keyPair != nullptr);
    REQUIRE(keyPair->getPublicKey().size() == 32);
    REQUIRE(keyPair->getPrivateKey().size() == 32);
    REQUIRE(keyPair->getCurveType() == CurveType::X25519);
    
    // Public key should not be all zeros
    auto pubKey = keyPair->getPublicKey();
    bool allZero = std::all_of(pubKey.begin(), pubKey.end(), 
                               [](uint8_t b) { return b == 0; });
    REQUIRE_FALSE(allZero);
    
    // Check that we can get the public key as a string
    std::string pubKeyStr = keyPair->getPublicKeyString();
    REQUIRE(pubKeyStr.length() == 64);  // 32 bytes = 64 hex chars
}

TEST_CASE("Key Pair Generation From Private Key", "[key_pair]") {
    // Generate a random private key
    std::vector<uint8_t> privateKey(32);
    for (size_t i = 0; i < privateKey.size(); ++i) {
        privateKey[i] = static_cast<uint8_t>(i);
    }
    
    // Create key pair from private key
    auto keyPair = ECDHKeyPair::fromPrivateKey(privateKey, CurveType::X25519);
    
    REQUIRE(keyPair != nullptr);
    REQUIRE(keyPair->getPublicKey().size() == 32);
    REQUIRE(keyPair->getPrivateKey().size() == 32);
    REQUIRE(keyPair->getCurveType() == CurveType::X25519);
    
    // Private key should match what we provided
    REQUIRE(keyPair->getPrivateKey() == privateKey);
    
    // Creating another key pair with the same private key should produce the same public key
    auto keyPair2 = ECDHKeyPair::fromPrivateKey(privateKey, CurveType::X25519);
    REQUIRE(keyPair2 != nullptr);
    REQUIRE(keyPair->getPublicKey() == keyPair2->getPublicKey());
}

TEST_CASE("Key Pair Move Operations", "[key_pair]") {
    auto keyPair1 = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair1 != nullptr);
    
    auto pubKey = keyPair1->getPublicKey();
    auto privKey = keyPair1->getPrivateKey();
    
    // Test move constructor with raw objects (not unique_ptr)
    ECDHKeyPair keyPair2(std::move(*keyPair1));
    REQUIRE(keyPair2.getPublicKey() == pubKey);
    REQUIRE(keyPair2.getPrivateKey() == privKey);
    
    // Create a new key pair for testing move assignment
    auto keyPair3_ptr = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair3_ptr != nullptr);
    
    // Move raw object
    ECDHKeyPair keyPair3(std::move(*keyPair3_ptr));
    keyPair3 = std::move(keyPair2);
    REQUIRE(keyPair3.getPublicKey() == pubKey);
    REQUIRE(keyPair3.getPrivateKey() == privKey);
}

TEST_CASE("Secure Private Key Erasure", "[key_pair][security]") {
    // Test secure erasure behavior
    std::vector<uint8_t> testVector(32, 0xFF);  // Fill with non-zero values
    
    // Test our secureErase utility directly
    util::secureErase(testVector);
    
    // Verify the vector is now empty
    REQUIRE(testVector.empty());
    
    // Now test with actual key pair
    auto keyPair = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair != nullptr);
    
    // Verify private key isn't empty before destruction
    REQUIRE(!keyPair->getPrivateKey().empty());
    
    // Get a copy of the private key
    auto privateCopy = keyPair->getPrivateKey();
    
    // Destroy the key pair
    keyPair.reset();
    
    // The original private key should be securely erased by the destructor,
    // but our copy should still be intact
    REQUIRE(!privateCopy.empty());
    
    // Now manually erase our copy
    util::secureErase(privateCopy);
    REQUIRE(privateCopy.empty());
}

TEST_CASE("X25519 Test Vectors from RFC 7748", "[key_pair][rfc7748]") {
    // Test vectors from RFC 7748, Section 5.2: https://tools.ietf.org/html/rfc7748#section-5.2
    
    // Test Vector #1
    auto alicePrivHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    auto alicePubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    auto bobPrivHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    auto bobPubHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    auto sharedSecretHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    
    // Convert hex strings to byte vectors
    auto alicePriv = util::fromHexString(alicePrivHex).value();
    auto alicePub = util::fromHexString(alicePubHex).value();
    auto bobPriv = util::fromHexString(bobPrivHex).value();
    auto bobPub = util::fromHexString(bobPubHex).value();
    auto expectedShared = util::fromHexString(sharedSecretHex).value();
    
    // Create key pairs from private keys
    auto aliceKeyPair = ECDHKeyPair::fromPrivateKey(alicePriv, CurveType::X25519);
    auto bobKeyPair = ECDHKeyPair::fromPrivateKey(bobPriv, CurveType::X25519);
    
    REQUIRE(aliceKeyPair != nullptr);
    REQUIRE(bobKeyPair != nullptr);
    
    // Verify the public keys match the expected values
    REQUIRE(aliceKeyPair->getPublicKey() == alicePub);
    REQUIRE(bobKeyPair->getPublicKey() == bobPub);
    
    // Create exchange objects
    ECDHExchange aliceExchange(std::move(aliceKeyPair));
    ECDHExchange bobExchange(std::move(bobKeyPair));
    
    // Derive shared secrets
    auto aliceSharedResult = aliceExchange.deriveSharedSecret(bobPub);
    auto bobSharedResult = bobExchange.deriveSharedSecret(alicePub);
    
    REQUIRE(aliceSharedResult.isSuccess());
    REQUIRE(bobSharedResult.isSuccess());
    
    // Verify the shared secrets match the expected value
    REQUIRE(aliceSharedResult.value() == expectedShared);
    REQUIRE(bobSharedResult.value() == expectedShared);
    
    // Verify both parties derive the same shared secret
    REQUIRE(aliceSharedResult.value() == bobSharedResult.value());
}