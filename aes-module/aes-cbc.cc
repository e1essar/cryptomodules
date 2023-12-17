#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <string.h>
#include <cstdlib>
#include <ctime>
#include <chrono>

/*
aes-cbc.hh
class ClientModule {

    public:
        ClientModule();
        ~ClientModule();

        // Если данные - строка (массив байт):
        // typedef vector<unsigned char> INPUT_TYPE;

        // Если данные - число (целое или действительное):
        typedef double INPUT_TYPE;

        // Выходные данные - массив байт шифртекста (когда СУБД не взаимодействует с данными)
        // или возможен другой тип - может быть целое число в случае OPE (сравнение на стороне СУБД).
        typedef vector<unsigned char> OUTPUT_TYPE;

        // По умолчанию храним любые данные как массив байт
        // (открытый/закрытый ключи и пр.)
        typedef vector<unsigned char> DEFAULT_TYPE;

        
        //    Базовые операции
        
        OUTPUT_TYPE encrypt(INPUT_TYPE input, DEFAULT_TYPE key );
        INPUT_TYPE decrypt(OUTPUT_TYPE input, DEFAULT_TYPE key);

        // Операции гомоморфного сложения/умножения
        // или другие операции над зашифрованными данными
        OUTPUT_TYPE serverOperation(OUTPUT_TYPE input );

        
        //    Вспомогательные операции
        

        // Генерация случайного ключа (или пары открытый/закрытый ключ)
        DEFAULT_TYPE generateKey();

        
    private:
        

}
*/

#define CIPHERTEXT_SIZE 1024

// vector!!!

class AESEncryption {
public:
    AESEncryption() {
        generateRandomKey(key, AES_BLOCK_SIZE);
        generateRandomIV(iv, AES_BLOCK_SIZE);
    }

    AESEncryption(bool det, unsigned char detIV = 0) {
        if (det) {
            generateRandomKey(key, AES_BLOCK_SIZE);
            memset(iv, detIV, AES_BLOCK_SIZE);
        } else {
            generateRandomKey(key, AES_BLOCK_SIZE);
            generateRandomIV(iv, AES_BLOCK_SIZE);
        }
    }

    AESEncryption(const unsigned char* key, const unsigned char* iv) {
        memcpy(this->key, key, AES_BLOCK_SIZE);
        memcpy(this->iv, iv, AES_BLOCK_SIZE);
    }

    ~AESEncryption() {}

    void ucharToHex(const unsigned char* data, size_t len, char* hexString) {
        for (size_t i = 0; i < len; ++i) {
            sprintf(hexString + 2 * i, "%02x", data[i]);
        }
    }

    void encrypt(const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handleErrors();

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv))
            handleErrors();

        int len;
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();
        ciphertext_len = len;

        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
            handleErrors();
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    void decrypt(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            handleErrors();

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv))
            handleErrors();

        int len;
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();
        plaintext_len = len;

        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
            handleErrors();
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
    }

    int getCiphertextLen() const {
        return ciphertext_len;
    }

    int getPlaintextLen() const {
        return plaintext_len;
    }

    void generateRandomKey(unsigned char* key, size_t size) {
        if (RAND_bytes(key, static_cast<int>(size)) != 1) {
            handleErrors();
        }
    }

    void generateRandomIV(unsigned char* iv, size_t size) {
        if (RAND_bytes(iv, static_cast<int>(size)) != 1) {
            handleErrors();
        }
    }

    void reset(bool det, unsigned char* _iv = 0) {
        if (det) {
            generateRandomKey(key, AES_BLOCK_SIZE);
            memcpy(this->iv, _iv, AES_BLOCK_SIZE);
        } else {
            generateRandomKey(key, AES_BLOCK_SIZE);
            generateRandomIV(iv, AES_BLOCK_SIZE);
        }
    }

private:
    void updateStorage() {
        memcpy(encryptionParams.key, key, AES_BLOCK_SIZE);
        memcpy(encryptionParams.iv, iv, AES_BLOCK_SIZE);
    }

    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    int ciphertext_len;
    int plaintext_len;
};

AESEncryption globalAESEncryption;

// Test random encryption with a random key and IV
void testRandom(const char* plain) {
    const char* plaintext = plain;
    unsigned char ciphertext[CIPHERTEXT_SIZE];
    //printf("%s\n", plaintext);

    // generate key iv

    // Encrypt the plaintext
    globalAESEncryption.encrypt(reinterpret_cast<const unsigned char*>(plaintext), strlen(plaintext), ciphertext);

    // Print the ciphertext in hex
    // string hexString(vector)
    char hexString[2 * globalAESEncryption.getCiphertextLen() + 1];
    globalAESEncryption.ucharToHex(ciphertext, globalAESEncryption.getCiphertextLen(), hexString);
    //printf("Ciphertext in Hex:\n%s\n", hexString);

    // Print the global key
    // std::cout << "Key: ";
    // for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
    //     printf("%02x", encryptionParams.key[i]);
    // }
    // std::cout << std::endl;

    // Print the global IV
    // std::cout << "IV: ";
    // for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
    //     printf("%02x", encryptionParams.iv[i]);
    // }
    // std::cout << std::endl;

    // Decrypt using the key and IV from the global structure
    unsigned char decryptedtext[1024];
    AESEncryption aesDecryption(encryptionParams.key, encryptionParams.iv);
    aesDecryption.decrypt(ciphertext, globalAESEncryption.getCiphertextLen(), decryptedtext);
    decryptedtext[aesDecryption.getPlaintextLen()] = '\0';

    // Print the decrypted text
    //printf("Decrypted text is:\n");
    //printf("%s\n", decryptedtext);
    if (memcmp(decryptedtext, plain, std::min(aesDecryption.getPlaintextLen(), aesDecryption.getPlaintextLen())) == 0) {
        std::cout << "PASSED" << std::endl;
    } else {
        std::cout << "ERROR" << std::endl;
    }   
    
}

// Test deterministic encryption with the same key and IV
void testDeterministic() {
    const char* iv = "12324654756543425";
    globalAESEncryption.reset(true, (unsigned char*)iv);
    // iv = 0
    const char* plaintext1 = "Hello, World!";
    const char* plaintext2 = "Hello, Worldd!";
    unsigned char ciphertext1[CIPHERTEXT_SIZE];
    unsigned char ciphertext2[CIPHERTEXT_SIZE];

    globalAESEncryption.encrypt(reinterpret_cast<const unsigned char*>(plaintext1), strlen(plaintext1), ciphertext1);
    globalAESEncryption.encrypt(reinterpret_cast<const unsigned char*>(plaintext2), strlen(plaintext2), ciphertext2);

    char hexString1[2 * globalAESEncryption.getCiphertextLen() + 1];
    globalAESEncryption.ucharToHex(ciphertext1, globalAESEncryption.getCiphertextLen(), hexString1);
    printf("Ciphertext 1 in Hex:\n%s\n", hexString1);

    char hexString2[2 * globalAESEncryption.getCiphertextLen() + 1];
    globalAESEncryption.ucharToHex(ciphertext2, globalAESEncryption.getCiphertextLen(), hexString2);
    printf("Ciphertext 2 in Hex:\n%s\n", hexString2);

    if (memcmp(ciphertext1, ciphertext2, std::min(globalAESEncryption.getCiphertextLen(), globalAESEncryption.getCiphertextLen())) == 0) {
        std::cout << "Ciphertexts match!" << std::endl;
    } else {
        std::cout << "Ciphertexts do not match!" << std::endl;
    }
}

void runRandomTests(int numTests, int maxTextLength) {
    for (int i = 0; i < numTests; ++i) {
        int randomLength = rand() % (maxTextLength - 1) + 1; 
        char randomText[randomLength + 1];
        for (int j = 0; j < randomLength; ++j) {
            randomText[j] = static_cast<char>(rand() % 26 + 'A'); 
        }
        randomText[randomLength] = '\0'; 
        testRandom(randomText);
        globalAESEncryption.reset(false);
    }
}

// Main function
int main() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    auto start = std::chrono::high_resolution_clock::now();  // Start the timer
    // Run random tests
    //runRandomTests(1000, 1000);
    testDeterministic();

    auto end = std::chrono::high_resolution_clock::now();  // Stop the timer
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    std::cout << "Time taken: " << duration.count() << " microseconds" << std::endl;

    return 0;
}
