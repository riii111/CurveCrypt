#include <curvecrypt/curvecrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace curvecrypt;

// Print usage instructions
void printUsage() {
    std::cout << "CurveCrypt CLI - ECDH Key Exchange Tool\n";
    std::cout << "======================================\n\n";
    std::cout << "Usage: curvecrypt_cli [command] [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  keygen [--curve=X25519|SECP256R1|SECP384R1] [--out=filename]\n";
    std::cout << "       Generate a new key pair and save to files\n\n";
    std::cout << "  exchange [--private=file] [--peer=file] [--out=file]\n";
    std::cout << "       Derive a shared secret from your private key and peer's public key\n\n";
    std::cout << "  derive [--secret=file] [--out=file] [--context=string] [--length=32]\n";
    std::cout << "       Derive a symmetric key from a shared secret\n\n";
    std::cout << "  encrypt [--key=file] [--in=file] [--out=file]\n";
    std::cout << "       Encrypt a file using a symmetric key\n\n";
    std::cout << "  decrypt [--key=file] [--in=file] [--out=file]\n";
    std::cout << "       Decrypt a file using a symmetric key\n\n";
    std::cout << "  simulate\n";
    std::cout << "       Run a full simulation of Alice and Bob exchanging keys and messages\n\n";
    std::cout << "Options:\n";
    std::cout << "  --curve    Elliptic curve to use (default: X25519)\n";
    std::cout << "  --private  Private key file\n";
    std::cout << "  --peer     Peer's public key file\n";
    std::cout << "  --secret   Shared secret file\n";
    std::cout << "  --key      Symmetric key file\n";
    std::cout << "  --in       Input file\n";
    std::cout << "  --out      Output file\n";
    std::cout << "  --context  Context string for key derivation\n";
    std::cout << "  --length   Key length for derivation (default: 32)\n";
}

// Parse command line arguments into a map
std::map<std::string, std::string> parseArgs(int argc, char* argv[], std::string& command) {
    std::map<std::string, std::string> args;
    
    if (argc < 2) {
        return args;
    }
    
    command = argv[1];
    
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        size_t pos = arg.find('=');
        
        if (pos != std::string::npos && arg.substr(0, 2) == "--") {
            std::string key = arg.substr(2, pos - 2);
            std::string value = arg.substr(pos + 1);
            args[key] = value;
        }
    }
    
    return args;
}

// Read file contents into a byte vector
Result<std::vector<uint8_t>> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return Result<std::vector<uint8_t>>::failure(
            ErrorCode::InvalidInput,
            "Failed to open file: " + filename
        );
    }
    
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        (std::istreambuf_iterator<char>())
    );
    
    return Result<std::vector<uint8_t>>::success(std::move(data));
}

// Write byte vector to a file
bool writeFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

// Convert curve name string to CurveType
CurveType stringToCurveType(const std::string& curveStr) {
    if (curveStr == "SECP256R1") {
        return CurveType::SECP256R1;
    } else if (curveStr == "SECP384R1") {
        return CurveType::SECP384R1;
    } else {
        return CurveType::X25519; // Default
    }
}

// Generate key pair command
bool commandKeygen(const std::map<std::string, std::string>& args) {
    // Parse curve type
    CurveType curve = CurveType::X25519;
    if (args.count("curve")) {
        curve = stringToCurveType(args.at("curve"));
    }
    
    // Generate the key pair
    std::cout << "Generating key pair using ";
    switch (curve) {
        case CurveType::X25519:
            std::cout << "X25519";
            break;
        case CurveType::SECP256R1:
            std::cout << "SECP256R1";
            break;
        case CurveType::SECP384R1:
            std::cout << "SECP384R1";
            break;
    }
    std::cout << " curve..." << std::endl;
    
    auto keyPair = ECDHKeyPair::generate(curve);
    if (!keyPair) {
        std::cerr << "Failed to generate key pair" << std::endl;
        return false;
    }
    
    // Get the keys
    auto publicKey = keyPair->getPublicKey();
    auto privateKey = keyPair->getPrivateKey();
    
    // Determine output file prefix
    std::string prefix = "key";
    if (args.count("out")) {
        prefix = args.at("out");
    }
    
    // Save the keys to files
    std::string pubFile = prefix + ".pub";
    std::string privFile = prefix + ".priv";
    
    if (!writeFile(pubFile, publicKey)) {
        std::cerr << "Failed to write public key to " << pubFile << std::endl;
        return false;
    }
    
    if (!writeFile(privFile, privateKey)) {
        std::cerr << "Failed to write private key to " << privFile << std::endl;
        return false;
    }
    
    std::cout << "Keys generated successfully:" << std::endl;
    std::cout << "  Public key:  " << pubFile << " (" << publicKey.size() << " bytes)" << std::endl;
    std::cout << "  Private key: " << privFile << " (" << privateKey.size() << " bytes)" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Public key hex: " << util::toHexString(publicKey) << std::endl;
    
    return true;
}

// Exchange keys command
bool commandExchange(const std::map<std::string, std::string>& args) {
    // Check required arguments
    if (!args.count("private") || !args.count("peer")) {
        std::cerr << "Error: Missing required arguments" << std::endl;
        std::cerr << "Usage: curvecrypt_cli exchange --private=file --peer=file [--out=file]" << std::endl;
        return false;
    }
    
    // Read private key
    auto privateKeyResult = readFile(args.at("private"));
    if (!privateKeyResult.isSuccess()) {
        std::cerr << "Error: " << privateKeyResult.errorMessage() << std::endl;
        return false;
    }
    
    // Read peer's public key
    auto peerPublicKeyResult = readFile(args.at("peer"));
    if (!peerPublicKeyResult.isSuccess()) {
        std::cerr << "Error: " << peerPublicKeyResult.errorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Performing key exchange..." << std::endl;
    
    // Create key pair from private key
    auto keyPair = ECDHKeyPair::fromPrivateKey(privateKeyResult.value());
    if (!keyPair) {
        std::cerr << "Failed to create key pair from private key" << std::endl;
        return false;
    }
    
    // Create exchange object
    ECDHExchange exchange(std::move(keyPair));
    
    // Derive shared secret
    auto sharedSecretResult = exchange.deriveSharedSecret(peerPublicKeyResult.value());
    if (!sharedSecretResult.isSuccess()) {
        std::cerr << "Error: " << sharedSecretResult.errorMessage() << std::endl;
        return false;
    }
    
    auto sharedSecret = sharedSecretResult.value();
    
    // Save shared secret if output file provided
    if (args.count("out")) {
        if (!writeFile(args.at("out"), sharedSecret)) {
            std::cerr << "Failed to write shared secret to " << args.at("out") << std::endl;
            return false;
        }
        std::cout << "Shared secret written to " << args.at("out") << " (" << sharedSecret.size() << " bytes)" << std::endl;
    }
    
    std::cout << "Shared secret: " << util::toHexString(sharedSecret) << std::endl;
    
    return true;
}

// Derive symmetric key command
bool commandDerive(const std::map<std::string, std::string>& args) {
    // Check required arguments
    if (!args.count("secret")) {
        std::cerr << "Error: Missing required arguments" << std::endl;
        std::cerr << "Usage: curvecrypt_cli derive --secret=file [--out=file] [--context=string] [--length=32]" << std::endl;
        return false;
    }
    
    // Read shared secret
    auto secretResult = readFile(args.at("secret"));
    if (!secretResult.isSuccess()) {
        std::cerr << "Error: " << secretResult.errorMessage() << std::endl;
        return false;
    }
    
    // Create a temporary key pair for using the ECDHExchange
    auto keyPair = ECDHKeyPair::generate();
    ECDHExchange exchange(std::move(keyPair));
    
    // Parse optional parameters
    size_t keyLength = 32;
    std::string context = "CurveCrypt Key";
    
    if (args.count("length")) {
        try {
            keyLength = std::stoul(args.at("length"));
        } catch (const std::exception&) {
            std::cerr << "Error: Invalid key length" << std::endl;
            return false;
        }
    }
    
    if (args.count("context")) {
        context = args.at("context");
    }
    
    std::cout << "Deriving symmetric key..." << std::endl;
    std::cout << "  Length: " << keyLength << " bytes" << std::endl;
    std::cout << "  Context: \"" << context << "\"" << std::endl;
    
    // Derive the key
    auto keyResult = exchange.deriveSymmetricKey(secretResult.value(), keyLength, context);
    if (!keyResult.isSuccess()) {
        std::cerr << "Error: " << keyResult.errorMessage() << std::endl;
        return false;
    }
    
    auto key = keyResult.value();
    
    // Save key if output file provided
    if (args.count("out")) {
        if (!writeFile(args.at("out"), key)) {
            std::cerr << "Failed to write key to " << args.at("out") << std::endl;
            return false;
        }
        std::cout << "Symmetric key written to " << args.at("out") << " (" << key.size() << " bytes)" << std::endl;
    }
    
    std::cout << "Symmetric key: " << util::toHexString(key) << std::endl;
    
    return true;
}

// Encrypt file command
bool commandEncrypt(const std::map<std::string, std::string>& args) {
    // Check required arguments
    if (!args.count("key") || !args.count("in") || !args.count("out")) {
        std::cerr << "Error: Missing required arguments" << std::endl;
        std::cerr << "Usage: curvecrypt_cli encrypt --key=file --in=file --out=file" << std::endl;
        return false;
    }
    
    // Read key
    auto keyResult = readFile(args.at("key"));
    if (!keyResult.isSuccess()) {
        std::cerr << "Error: " << keyResult.errorMessage() << std::endl;
        return false;
    }
    
    // Read input file
    auto dataResult = readFile(args.at("in"));
    if (!dataResult.isSuccess()) {
        std::cerr << "Error: " << dataResult.errorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Encrypting file..." << std::endl;
    
    // Encrypt the data
    auto encryptedResult = SecureMessage::encrypt(dataResult.value(), keyResult.value());
    if (!encryptedResult.isSuccess()) {
        std::cerr << "Error: " << encryptedResult.errorMessage() << std::endl;
        return false;
    }
    
    // Write encrypted data to output file
    if (!writeFile(args.at("out"), encryptedResult.value())) {
        std::cerr << "Failed to write encrypted data to " << args.at("out") << std::endl;
        return false;
    }
    
    std::cout << "File encrypted successfully" << std::endl;
    std::cout << "  Input size: " << dataResult.value().size() << " bytes" << std::endl;
    std::cout << "  Encrypted size: " << encryptedResult.value().size() << " bytes" << std::endl;
    std::cout << "  Output file: " << args.at("out") << std::endl;
    
    return true;
}

// Decrypt file command
bool commandDecrypt(const std::map<std::string, std::string>& args) {
    // Check required arguments
    if (!args.count("key") || !args.count("in") || !args.count("out")) {
        std::cerr << "Error: Missing required arguments" << std::endl;
        std::cerr << "Usage: curvecrypt_cli decrypt --key=file --in=file --out=file" << std::endl;
        return false;
    }
    
    // Read key
    auto keyResult = readFile(args.at("key"));
    if (!keyResult.isSuccess()) {
        std::cerr << "Error: " << keyResult.errorMessage() << std::endl;
        return false;
    }
    
    // Read input file
    auto dataResult = readFile(args.at("in"));
    if (!dataResult.isSuccess()) {
        std::cerr << "Error: " << dataResult.errorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Decrypting file..." << std::endl;
    
    // Decrypt the data
    auto decryptedResult = SecureMessage::decrypt(dataResult.value(), keyResult.value());
    if (!decryptedResult.isSuccess()) {
        std::cerr << "Error: " << decryptedResult.errorMessage() << std::endl;
        return false;
    }
    
    // Write decrypted data to output file
    if (!writeFile(args.at("out"), decryptedResult.value())) {
        std::cerr << "Failed to write decrypted data to " << args.at("out") << std::endl;
        return false;
    }
    
    std::cout << "File decrypted successfully" << std::endl;
    std::cout << "  Input size: " << dataResult.value().size() << " bytes" << std::endl;
    std::cout << "  Decrypted size: " << decryptedResult.value().size() << " bytes" << std::endl;
    std::cout << "  Output file: " << args.at("out") << std::endl;
    
    return true;
}

// Simulation command - simulates a full key exchange and message exchange
bool commandSimulate() {
    std::cout << "CurveCrypt Key Exchange Simulation" << std::endl;
    std::cout << "=================================" << std::endl << std::endl;
    
    // Step 1: Generate key pairs for Alice and Bob
    std::cout << "Step 1: Generating key pairs" << std::endl;
    std::cout << "----------------------------" << std::endl;
    
    std::cout << "Generating Alice's key pair..." << std::endl;
    auto aliceKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    if (!aliceKeyPair) {
        std::cerr << "Failed to generate Alice's key pair" << std::endl;
        return false;
    }
    
    std::cout << "Generating Bob's key pair..." << std::endl;
    auto bobKeyPair = ECDHKeyPair::generate(CurveType::X25519);
    if (!bobKeyPair) {
        std::cerr << "Failed to generate Bob's key pair" << std::endl;
        return false;
    }
    
    std::cout << "Alice's public key: " << util::toHexString(aliceKeyPair->getPublicKey()) << std::endl;
    std::cout << "Bob's public key: " << util::toHexString(bobKeyPair->getPublicKey()) << std::endl;
    std::cout << std::endl;
    
    // Step 2: Exchange public keys and derive shared secrets
    std::cout << "Step 2: Deriving shared secrets" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    ECDHExchange aliceExchange(std::move(aliceKeyPair));
    ECDHExchange bobExchange(std::move(bobKeyPair));
    
    auto alicePublicKey = aliceExchange.getPublicKey();
    auto bobPublicKey = bobExchange.getPublicKey();
    
    std::cout << "Alice sends her public key to Bob" << std::endl;
    std::cout << "Bob sends his public key to Alice" << std::endl;
    
    std::cout << "Alice computes shared secret..." << std::endl;
    auto aliceSharedResult = aliceExchange.deriveSharedSecret(bobPublicKey);
    if (!aliceSharedResult.isSuccess()) {
        std::cerr << "Error: " << aliceSharedResult.errorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Bob computes shared secret..." << std::endl;
    auto bobSharedResult = bobExchange.deriveSharedSecret(alicePublicKey);
    if (!bobSharedResult.isSuccess()) {
        std::cerr << "Error: " << bobSharedResult.errorMessage() << std::endl;
        return false;
    }
    
    auto aliceShared = aliceSharedResult.value();
    auto bobShared = bobSharedResult.value();
    
    std::cout << "Alice's shared secret: " << util::toHexString(aliceShared) << std::endl;
    std::cout << "Bob's shared secret: " << util::toHexString(bobShared) << std::endl;
    
    if (aliceShared == bobShared) {
        std::cout << "✓ Shared secrets match! Key exchange successful." << std::endl;
    } else {
        std::cerr << "✗ Shared secrets do not match! Key exchange failed." << std::endl;
        return false;
    }
    std::cout << std::endl;
    
    // Step 3: Derive symmetric keys
    std::cout << "Step 3: Deriving symmetric keys" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    std::cout << "Alice derives symmetric key..." << std::endl;
    auto aliceKeyResult = aliceExchange.deriveSymmetricKey(aliceShared);
    if (!aliceKeyResult.isSuccess()) {
        std::cerr << "Error: " << aliceKeyResult.errorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Bob derives symmetric key..." << std::endl;
    auto bobKeyResult = bobExchange.deriveSymmetricKey(bobShared);
    if (!bobKeyResult.isSuccess()) {
        std::cerr << "Error: " << bobKeyResult.errorMessage() << std::endl;
        return false;
    }
    
    auto aliceKey = aliceKeyResult.value();
    auto bobKey = bobKeyResult.value();
    
    std::cout << "Alice's symmetric key: " << util::toHexString(aliceKey) << std::endl;
    std::cout << "Bob's symmetric key: " << util::toHexString(bobKey) << std::endl;
    
    if (aliceKey == bobKey) {
        std::cout << "✓ Symmetric keys match!" << std::endl;
    } else {
        std::cerr << "✗ Symmetric keys do not match!" << std::endl;
        return false;
    }
    std::cout << std::endl;
    
    // Step 4: Encrypt and decrypt a message
    std::cout << "Step 4: Secure messaging" << std::endl;
    std::cout << "----------------------" << std::endl;
    
    std::string message = "Hello, Bob! This is a secret message from Alice.";
    std::cout << "Alice's message: \"" << message << "\"" << std::endl;
    
    std::vector<uint8_t> messageData(message.begin(), message.end());
    
    std::cout << "Alice encrypts the message..." << std::endl;
    auto encryptedResult = SecureMessage::encrypt(messageData, aliceKey);
    if (!encryptedResult.isSuccess()) {
        std::cerr << "Error: " << encryptedResult.errorMessage() << std::endl;
        return false;
    }
    
    auto encrypted = encryptedResult.value();
    std::cout << "Encrypted message: " << util::toHexString(encrypted) << std::endl;
    
    std::cout << "Alice sends the encrypted message to Bob" << std::endl;
    
    std::cout << "Bob decrypts the message..." << std::endl;
    auto decryptedResult = SecureMessage::decrypt(encrypted, bobKey);
    if (!decryptedResult.isSuccess()) {
        std::cerr << "Error: " << decryptedResult.errorMessage() << std::endl;
        return false;
    }
    
    auto decrypted = decryptedResult.value();
    std::string decryptedMessage(decrypted.begin(), decrypted.end());
    
    std::cout << "Bob's decrypted message: \"" << decryptedMessage << "\"" << std::endl;
    
    if (decryptedMessage == message) {
        std::cout << "✓ Message decrypted successfully!" << std::endl;
    } else {
        std::cerr << "✗ Decrypted message does not match original!" << std::endl;
        return false;
    }
    std::cout << std::endl;
    
    std::cout << "Simulation completed successfully!" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    std::string command;
    auto args = parseArgs(argc, argv, command);
    
    if (command.empty() || command == "help") {
        printUsage();
        return 0;
    }
    
    bool success = false;
    
    if (command == "keygen") {
        success = commandKeygen(args);
    } else if (command == "exchange") {
        success = commandExchange(args);
    } else if (command == "derive") {
        success = commandDerive(args);
    } else if (command == "encrypt") {
        success = commandEncrypt(args);
    } else if (command == "decrypt") {
        success = commandDecrypt(args);
    } else if (command == "simulate") {
        success = commandSimulate();
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        printUsage();
        return 1;
    }
    
    return success ? 0 : 1;
}