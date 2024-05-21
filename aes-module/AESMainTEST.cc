#include "AESModule.hh"
#include "AESModule.cc"

void runTestDET() {
    AESModule aesModule;

    AESModule::DEFAULT_TYPE key = aesModule.generateKey();
    AESModule::DEFAULT_TYPE iv(AES_BLOCK_SIZE, 0);

    std::string plaintextMessage1 = "Hello, World!";
    std::string plaintextMessage2 = "Hello, World!";
    
    AESModule::DEFAULT_TYPE plaintext1(plaintextMessage1.begin(), plaintextMessage1.end());
    AESModule::DEFAULT_TYPE plaintext2(plaintextMessage2.begin(), plaintextMessage2.end());

    AESModule::DEFAULT_TYPE ciphertext1 = aesModule.encrypt(plaintext1, key, iv);
    AESModule::DEFAULT_TYPE hexCiphertext1 = aesModule.ucharToHex(ciphertext1);
    AESModule::DEFAULT_TYPE hexCiphertextData1 = aesModule.hexStringToUchar(hexCiphertext1);

    AESModule::DEFAULT_TYPE ciphertext2 = aesModule.encrypt(plaintext2, key, iv);
    AESModule::DEFAULT_TYPE hexCiphertext2 = aesModule.ucharToHex(ciphertext2);
    AESModule::DEFAULT_TYPE hexCiphertextData2 = aesModule.hexStringToUchar(hexCiphertext2);

    assert(plaintext1 == plaintext2 && "Test failed: plaintext1 and plaintext2 do not match");
    assert(ciphertext1 == ciphertext2 && "Test failed: ciphertext1 and ciphertext2 do not match");
    assert(hexCiphertext1 == hexCiphertext2 && "Test failed: hexCiphertext1 and hexCiphertext2 do not match");
    assert(hexCiphertextData1 == hexCiphertextData2 && "Test failed: hexCiphertextData1 and hexCiphertextData2 do not match");

    //AESModule::DEFAULT_TYPE decryptedText = aesModule.decrypt(hexCiphertextData, key, iv);
    //std::string decryptedMessage(decryptedText.begin(), decryptedText.end());

    std::cout << "DET test passed successfully!" << std::endl;
}

void runTestRND(int numTests, int plaintextLength) {
    AESModule aesModule;

    std::srand(std::time(0));

    for (int test = 0; test < numTests; ++test) {
        AESModule::DEFAULT_TYPE key = aesModule.generateKey();
        AESModule::DEFAULT_TYPE iv = aesModule.generateIv();

        //std::string plaintextMessage(plaintextLength, 'a' + rand() % 26);
        std::string plaintextMessage;
        for (int i = 0; i < plaintextLength; ++i) {
            plaintextMessage.push_back(static_cast<char>(std::rand() % 256));
        }
        

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

    std::cout << "All RND tests passed successfully!" << std::endl;
}

int main() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    auto start = std::chrono::high_resolution_clock::now(); 

    runTestRND(1000, 1000);
    //runTestDET();

    /*  DET test passed successfully!
        Time taken: 1880 microseconds */

    /*  All RND tests passed successfully!
        Time taken: 210607 microseconds */

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Time taken: " << duration.count() << " microseconds" << std::endl;

    return 0;
}
