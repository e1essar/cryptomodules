#include "AESModule.hh"
#include "AESModule.cc"
#include <cassert>
#include <chrono>
#include <iostream>
#include <vector>
#include <string>
#include <ctime>

void clientScenario(AESModule::DEFAULT_TYPE& ciphertext1, AESModule::DEFAULT_TYPE& ciphertext2, AESModule::DEFAULT_TYPE& key, AESModule::DEFAULT_TYPE& iv, AESModule& aesModule) {
    auto startClient = std::chrono::high_resolution_clock::now();
    AESModule::DEFAULT_TYPE decryptedText1 = aesModule.decrypt(ciphertext1, key, iv);
    AESModule::DEFAULT_TYPE decryptedText2 = aesModule.decrypt(ciphertext2, key, iv);

    std::string decryptedMessage1(decryptedText1.begin(), decryptedText1.end());
    std::string decryptedMessage2(decryptedText2.begin(), decryptedText2.end());

    if (decryptedMessage1 == decryptedMessage2) {
        std::cout << "Client decryption test: OK" << std::endl;
    } else {
        std::cout << "Client decryption test: FAIL" << std::endl;
    }

    auto endClient = std::chrono::high_resolution_clock::now();
    auto durationClient = std::chrono::duration_cast<std::chrono::microseconds>(endClient - startClient);

    std::cout << "Client decryption time: " << durationClient.count() << " microseconds" << std::endl;
}

void serverScenario(AESModule::DEFAULT_TYPE& ciphertext1, AESModule::DEFAULT_TYPE& ciphertext2) {
    auto startServer = std::chrono::high_resolution_clock::now();
    if (ciphertext1 == ciphertext2) {
        std::cout << "Server encryption test: OK" << std::endl;
    } else {
        std::cout << "Server encryption test: FAIL" << std::endl;
    }
    auto endServer = std::chrono::high_resolution_clock::now();
    auto durationServer = std::chrono::duration_cast<std::chrono::microseconds>(endServer - startServer);
    std::cout << "Server comparison time: " << durationServer.count() << " microseconds" << std::endl;
}

int main() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    
    AESModule aesModule;
    AESModule::DEFAULT_TYPE key = aesModule.generateKey();
    AESModule::DEFAULT_TYPE iv(AES_BLOCK_SIZE, 0);

    std::string plaintextMessage1 = "Hello, World!";
    std::string plaintextMessage2 = "Hello, World!";

    AESModule::DEFAULT_TYPE plaintext1(plaintextMessage1.begin(), plaintextMessage1.end());
    AESModule::DEFAULT_TYPE plaintext2(plaintextMessage2.begin(), plaintextMessage2.end());

    auto startEncrypt = std::chrono::high_resolution_clock::now();
    AESModule::DEFAULT_TYPE ciphertext1 = aesModule.encrypt(plaintext1, key, iv);
    AESModule::DEFAULT_TYPE ciphertext2 = aesModule.encrypt(plaintext2, key, iv);
    auto endEncrypt = std::chrono::high_resolution_clock::now();
    auto durationEncrypt = std::chrono::duration_cast<std::chrono::microseconds>(endEncrypt - startEncrypt);

    std::cout << "Encryption time: " << durationEncrypt.count() << " microseconds" << std::endl;

    std::cout << "ClientTest:\n";
    clientScenario(ciphertext1, ciphertext2, key, iv, aesModule);
    std::cout << std::endl;

    std::cout << "ServerTest:\n";
    serverScenario(ciphertext1, ciphertext2);
    std::cout << std::endl;

    return 0;
}
