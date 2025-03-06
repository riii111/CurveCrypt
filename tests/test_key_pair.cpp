#include <catch2/catch.hpp>
#include <curvecrypt/key_pair.h>
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
    
    // Test move constructor
    auto keyPair2 = std::move(keyPair1);
    REQUIRE(keyPair2.getPublicKey() == pubKey);
    REQUIRE(keyPair2.getPrivateKey() == privKey);
    
    // Test move assignment
    auto keyPair3 = ECDHKeyPair::generate(CurveType::X25519);
    REQUIRE(keyPair3 != nullptr);
    
    keyPair3 = std::move(keyPair2);
    REQUIRE(keyPair3.getPublicKey() == pubKey);
    REQUIRE(keyPair3.getPrivateKey() == privKey);
}