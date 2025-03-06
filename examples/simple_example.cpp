#include <curvecrypt/curvecrypt.h>
#include <iostream>
#include <string>

using namespace curvecrypt;

int main() {
    std::cout << "CurveCrypt: Simple ECDH Key Exchange Example" << std::endl;
    std::cout << "=============================================" << std::endl << std::endl;
    
    // Generate Alice's key pair
    std::cout << "Generating Alice's key pair..." << std::endl;
    auto aliceKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    if (!aliceKeyPair) {
        std::cerr << "Failed to generate Alice's key pair" << std::endl;
        return 1;
    }
    
    // Generate Bob's key pair
    std::cout << "Generating Bob's key pair..." << std::endl;
    auto bobKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    if (!bobKeyPair) {
        std::cerr << "Failed to generate Bob's key pair" << std::endl;
        return 1;
    }
    
    // Create exchange objects
    ECDHExchange aliceExchange(std::move(aliceKeyPair));
    ECDHExchange bobExchange(std::move(bobKeyPair));
    
    // Get public keys (would be transmitted over a public channel)
    auto alicePublicKey = aliceExchange.getPublicKey();
    auto bobPublicKey = bobExchange.getPublicKey();
    
    std::cout << "Alice's public key: " << util::toHexString(alicePublicKey) << std::endl;
    std::cout << "Bob's public key: " << util::toHexString(bobPublicKey) << std::endl << std::endl;
    
    // Derive shared secrets
    std::cout << "Deriving shared secrets..." << std::endl;
    auto aliceSecretResult = aliceExchange.deriveSharedSecret(bobPublicKey);
    auto bobSecretResult = bobExchange.deriveSharedSecret(alicePublicKey);
    
    if (!aliceSecretResult.isSuccess()) {
        std::cerr << "Alice failed to derive shared secret: " 
                  << aliceSecretResult.errorMessage() << std::endl;
        return 1;
    }
    
    if (!bobSecretResult.isSuccess()) {
        std::cerr << "Bob failed to derive shared secret: " 
                  << bobSecretResult.errorMessage() << std::endl;
        return 1;
    }
    
    auto aliceSecret = aliceSecretResult.value();
    auto bobSecret = bobSecretResult.value();
    
    std::cout << "Alice's shared secret: " << util::toHexString(aliceSecret) << std::endl;
    std::cout << "Bob's shared secret: " << util::toHexString(bobSecret) << std::endl;
    
    // Verify that both derived the same secret
    if (aliceSecret == bobSecret) {
        std::cout << "Success! Both parties derived the same shared secret." << std::endl << std::endl;
    } else {
        std::cerr << "Error! Shared secrets don't match." << std::endl;
        return 1;
    }
    
    // Derive symmetric keys from shared secrets
    std::cout << "Deriving symmetric keys..." << std::endl;
    auto aliceKeyResult = aliceExchange.deriveSymmetricKey(aliceSecret);
    auto bobKeyResult = bobExchange.deriveSymmetricKey(bobSecret);
    
    if (!aliceKeyResult.isSuccess() || !bobKeyResult.isSuccess()) {
        std::cerr << "Failed to derive symmetric keys" << std::endl;
        return 1;
    }
    
    auto aliceKey = aliceKeyResult.value();
    auto bobKey = bobKeyResult.value();
    
    std::cout << "Alice's symmetric key: " << util::toHexString(aliceKey) << std::endl;
    std::cout << "Bob's symmetric key: " << util::toHexString(bobKey) << std::endl << std::endl;
    
    // Alice encrypts a message for Bob
    std::cout << "Alice encrypts a message for Bob..." << std::endl;
    std::string messageStr = "Hello, Bob! This is a secret message from Alice.";
    std::vector<uint8_t> message(messageStr.begin(), messageStr.end());
    
    auto encryptedResult = SecureMessage::encrypt(message, aliceKey);
    if (!encryptedResult.isSuccess()) {
        std::cerr << "Failed to encrypt message: " << encryptedResult.errorMessage() << std::endl;
        return 1;
    }
    
    auto encrypted = encryptedResult.value();
    std::cout << "Encrypted message: " << util::toHexString(encrypted) << std::endl << std::endl;
    
    // Bob decrypts the message
    std::cout << "Bob decrypts the message..." << std::endl;
    auto decryptedResult = SecureMessage::decrypt(encrypted, bobKey);
    if (!decryptedResult.isSuccess()) {
        std::cerr << "Failed to decrypt message: " << decryptedResult.errorMessage() << std::endl;
        return 1;
    }
    
    auto decrypted = decryptedResult.value();
    std::string decryptedStr(decrypted.begin(), decrypted.end());
    
    std::cout << "Decrypted message: \"" << decryptedStr << "\"" << std::endl << std::endl;
    
    std::cout << "End of demonstration" << std::endl;
    
    return 0;
}