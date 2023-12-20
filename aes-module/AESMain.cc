#include "AESModule.hh"
#include "AESModule.cc"

void runTest(int numTests, int plaintextLength) {
    AESModule aesModule;

    std::srand(std::time(0));

    for (int test = 0; test < numTests; test++) {
        AESModule::DEFAULT_TYPE key = aesModule.generateKey();
        AESModule::DEFAULT_TYPE iv = aesModule.generateIv();

        std::string plaintextMessage;
        for (int i = 0; i < plaintextLength; i++) {
            plaintextMessage.push_back(static_cast<char>(std::rand() % 256));
        }
        //std::string plaintextMessage(plaintextLength, rand() % 256);

        AESModule::DEFAULT_TYPE plaintext(plaintextMessage.begin(), plaintextMessage.end());

        //std::cout << "Plaintext: " << plaintextMessage << std::endl;

        AESModule::DEFAULT_TYPE ciphertext = aesModule.encrypt(plaintext, key, iv);

        AESModule::DEFAULT_TYPE hexCiphertext = aesModule.ucharToHex(ciphertext);

        AESModule::DEFAULT_TYPE hexCiphertextData = aesModule.hexStringToUchar(hexCiphertext);

        AESModule::DEFAULT_TYPE decryptedText = aesModule.decrypt(hexCiphertextData, key, iv);

        std::string decryptedMessage(decryptedText.begin(), decryptedText.end());
        //std::cout << "Decrypted Text: " << decryptedMessage << std::endl;

        assert(plaintext == decryptedText && "Test failed: plaintext and decryptedText do not match");

        //std::cout << "Test " << test + 1 << " passed\n";
    }

    std::cout << "All tests passed successfully!" << std::endl;
}

int main() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    auto start = std::chrono::high_resolution_clock::now(); 

    runTest(1000, 1000);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Time taken: " << duration.count() << " microseconds" << std::endl;

    return 0;

    // AESModule aesModule;

    // AESModule::DEFAULT_TYPE key = aesModule.generateKey();
    // AESModule::DEFAULT_TYPE iv = aesModule.generateIv();

    // std::cout << "Key: ";
    // for (const auto& byte : aesModule.ucharToHex(key)) {
    //     std::cout << byte;
    // }
    // std::cout << std::endl;

    // std::cout << "IV: ";
    // for (const auto& byte : aesModule.ucharToHex(iv)) {
    //     std::cout << byte;
    // }
    // std::cout << std::endl;

    // std::string plaintextMessage = "Hello, World!";

    // AESModule::DEFAULT_TYPE plaintext(plaintextMessage.begin(), plaintextMessage.end());

    // AESModule::DEFAULT_TYPE ciphertext = aesModule.encrypt(plaintext, key, iv);

    // AESModule::DEFAULT_TYPE hexCiphertext = aesModule.ucharToHex(ciphertext);

    // std::cout << "Plaintext: " << plaintextMessage << std::endl;
    // //std::cout << "Ciphertext: " << ciphertext << std::endl;

    
    // std::cout << "Ciphertext (hex): ";
    // for (const auto& byte : aesModule.ucharToHex(ciphertext)) {
    //     std::cout << byte;
    // }
    // std::cout << std::endl;

    // AESModule::DEFAULT_TYPE hexCiphertextData = aesModule.hexStringToUchar(hexCiphertext);

    // AESModule::DEFAULT_TYPE decryptedText = aesModule.decrypt(hexCiphertextData, key, iv);

    // std::string decryptedMessage(decryptedText.begin(), decryptedText.end());

    // std::cout << "Decrypted Text: " << decryptedMessage << std::endl;
}
