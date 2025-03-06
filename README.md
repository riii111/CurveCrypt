# CurveCrypt

A C++ library implementing Elliptic Curve Diffie-Hellman (ECDH) key exchange, designed for educational purposes.

## Overview

CurveCrypt demonstrates the core cryptographic primitives used in TLS 1.3 and modern secure communications, focusing on:

1. **Key Generation**: Creating public/private key pairs using elliptic curves
2. **Key Exchange**: Implementing the ECDH protocol for deriving shared secrets
3. **Key Derivation**: Transforming shared secrets into usable symmetric keys
4. **Authenticated Encryption**: Using derived keys with AES-GCM for secure communication

## Features

- Modern C++17 implementation
- Support for X25519 and NIST curves (secp256r1, secp384r1)
- Secure key derivation using HKDF
- Authenticated encryption with AES-GCM
- Comprehensive error handling
- Secure memory management for sensitive data

## Dependencies

- C++17 compatible compiler
- OpenSSL (for cryptographic operations)
- CMake 3.14+ (for building)

## Building

```bash
# Clone the repository
git clone https://github.com/yourusername/curvecrypt.git
cd curvecrypt

# Create a build directory
mkdir build
cd build

# Configure and build
cmake ..
make

# Run the tests
make test

# Run the example
./examples/curvecrypt_example
```

## Usage Example

```cpp
#include <curvecrypt/curvecrypt.h>
#include <iostream>
#include <string>

using namespace curvecrypt;

int main() {
    // Generate Alice's key pair
    auto aliceKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    
    // Generate Bob's key pair
    auto bobKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    
    // Create exchange objects
    ECDHExchange aliceExchange(std::move(aliceKeyPair));
    ECDHExchange bobExchange(std::move(bobKeyPair));
    
    // Exchange public keys (in a real-world scenario, this would happen over a network)
    auto alicePublicKey = aliceExchange.getPublicKey();
    auto bobPublicKey = bobExchange.getPublicKey();
    
    // Derive shared secrets
    auto aliceSecretResult = aliceExchange.deriveSharedSecret(bobPublicKey);
    auto bobSecretResult = bobExchange.deriveSharedSecret(alicePublicKey);
    
    if (aliceSecretResult.isSuccess() && bobSecretResult.isSuccess()) {
        auto aliceSecret = aliceSecretResult.value();
        auto bobSecret = bobSecretResult.value();
        
        // Derive symmetric keys
        auto aliceKeyResult = aliceExchange.deriveSymmetricKey(aliceSecret);
        auto bobKeyResult = bobExchange.deriveSymmetricKey(bobSecret);
        
        if (aliceKeyResult.isSuccess() && bobKeyResult.isSuccess()) {
            auto aliceKey = aliceKeyResult.value();
            auto bobKey = bobKeyResult.value();
            
            // Alice encrypts a message for Bob
            std::string message = "Hello, Bob! This is a secret message.";
            std::vector<uint8_t> messageBytes(message.begin(), message.end());
            
            auto encryptedResult = SecureMessage::encrypt(messageBytes, aliceKey);
            
            if (encryptedResult.isSuccess()) {
                auto encrypted = encryptedResult.value();
                
                // Bob decrypts the message
                auto decryptedResult = SecureMessage::decrypt(encrypted, bobKey);
                
                if (decryptedResult.isSuccess()) {
                    auto decrypted = decryptedResult.value();
                    std::string decryptedMessage(decrypted.begin(), decrypted.end());
                    
                    std::cout << "Decrypted message: " << decryptedMessage << std::endl;
                }
            }
        }
    }
    
    return 0;
}
```

## API Documentation

### Key Pair Generation

```cpp
// Generate a new key pair
auto keyPair = ECDHKeyPair::generate(CurveType::X25519);

// Get the public key
auto publicKey = keyPair->getPublicKey();
```

### Key Exchange

```cpp
// Create an exchange object
ECDHExchange exchange(std::move(keyPair));

// Derive a shared secret using peer's public key
auto secretResult = exchange.deriveSharedSecret(peerPublicKey);

// Derive a symmetric key from the shared secret
auto keyResult = exchange.deriveSymmetricKey(secretResult.value());
```

### Authenticated Encryption

```cpp
// Encrypt a message
auto encryptedResult = SecureMessage::encrypt(message, key);

// Decrypt a message
auto decryptedResult = SecureMessage::decrypt(encryptedResult.value(), key);
```

## Security Considerations

While CurveCrypt implements cryptographic primitives correctly, it is primarily designed for educational purposes. In production environments, consider using established libraries and frameworks that have undergone extensive security reviews.

Key security features implemented:
- Private key material is securely erased from memory when no longer needed
- Constant-time operations are used where possible to avoid timing side-channels
- Proper randomness is used for key generation
- Standard algorithms are used rather than custom implementations

## License

This project is licensed under the MIT License - see the LICENSE file for details.