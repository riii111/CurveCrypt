#include "curvecrypt/secure_message.h"
#include "curvecrypt/utility.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>

namespace curvecrypt {

namespace {

// AES-GCM nonce size (12 bytes / 96 bits as recommended)
constexpr size_t NONCE_SIZE = 12;

// AES-GCM tag size (16 bytes / 128 bits)
constexpr size_t TAG_SIZE = 16;

// Structure of encrypted message: [nonce][ciphertext][tag]
} // anonymous namespace

Result<std::vector<uint8_t>> SecureMessage::encrypt(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associatedData) {
    
    if (message.empty()) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Message is empty"
        );
    }
    
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidKey,
            "Key size must be 16, 24, or 32 bytes for AES"
        );
    }
    
    auto nonceResult = util::generateRandomBytes(NONCE_SIZE);
    if (!nonceResult.isSuccess()) {
        return Result<std::vector<uint8_t>>::failure(
            nonceResult.errorCode(),
            nonceResult.errorMessage()
        );
    }
    
    std::vector<uint8_t> nonce = nonceResult.value();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to create encryption context"
        );
    }
    
    const EVP_CIPHER* cipher = nullptr;
    switch (key.size()) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
    }
    
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to initialize encryption"
        );
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to set nonce length"
        );
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to set key and nonce"
        );
    }
    
    if (!associatedData.empty()) {
        int outlen;
        if (EVP_EncryptUpdate(ctx, nullptr, &outlen, 
                            associatedData.data(), associatedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>::failure(
                ErrorCode::EncryptionFailed,
                "Failed to process associated data"
            );
        }
    }
    
    std::vector<uint8_t> ciphertext;
    ciphertext.resize(message.size() + EVP_CIPHER_block_size(cipher));
    
    int outlen;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, 
                        message.data(), message.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to encrypt message"
        );
    }
    
    int ciphertextLen = outlen;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to finalize encryption"
        );
    }
    
    ciphertextLen += outlen;
    ciphertext.resize(ciphertextLen);
    
    std::vector<uint8_t> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::EncryptionFailed,
            "Failed to get authentication tag"
        );
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    std::vector<uint8_t> result;
    result.reserve(nonce.size() + ciphertext.size() + tag.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return Result<std::vector<uint8_t>>::success(std::move(result));
}

Result<std::vector<uint8_t>> SecureMessage::decrypt(
    const std::vector<uint8_t>& encryptedMessage,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& associatedData) {
    
    if (encryptedMessage.size() < NONCE_SIZE + TAG_SIZE) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Encrypted message is too short"
        );
    }
    
    if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidKey,
            "Key size must be 16, 24, or 32 bytes for AES"
        );
    }
    
    std::vector<uint8_t> nonce(encryptedMessage.begin(), 
                              encryptedMessage.begin() + NONCE_SIZE);
    
    std::vector<uint8_t> ciphertext(encryptedMessage.begin() + NONCE_SIZE,
                                  encryptedMessage.end() - TAG_SIZE);
    
    std::vector<uint8_t> tag(encryptedMessage.end() - TAG_SIZE,
                            encryptedMessage.end());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to create decryption context"
        );
    }
    
    const EVP_CIPHER* cipher = nullptr;
    switch (key.size()) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
    }
    
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to initialize decryption"
        );
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to set nonce length"
        );
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to set key and nonce"
        );
    }
    
    if (!associatedData.empty()) {
        int outlen;
        if (EVP_DecryptUpdate(ctx, nullptr, &outlen, 
                            associatedData.data(), associatedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return Result<std::vector<uint8_t>>::failure(
                ErrorCode::DecryptionFailed,
                "Failed to process associated data"
            );
        }
    }
    
    std::vector<uint8_t> plaintext;
    plaintext.resize(ciphertext.size());
    
    int outlen;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, 
                        ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to decrypt message"
        );
    }
    
    int plaintextLen = outlen;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::DecryptionFailed,
            "Failed to set authentication tag"
        );
    }
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret <= 0) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::AuthenticationFailed,
            "Message authentication failed"
        );
    }
    
    plaintextLen += outlen;
    plaintext.resize(plaintextLen);
    
    return Result<std::vector<uint8_t>>::success(std::move(plaintext));
}

} // namespace curvecrypt