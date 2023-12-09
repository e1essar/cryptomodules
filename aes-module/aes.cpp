#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <string.h>

struct EncryptionParameters {
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    EncryptionParameters() {
        memset(key, 0, AES_BLOCK_SIZE);
        memset(iv, 0, AES_BLOCK_SIZE);
    }

    EncryptionParameters(const unsigned char* newKey, const unsigned char* newIV) {
        memcpy(key, newKey, AES_BLOCK_SIZE);
        memcpy(iv, newIV, AES_BLOCK_SIZE);
    }
};

EncryptionParameters globalEncryptionParams;

class AESEncryption {
public:
    AESEncryption() {
        generateRandomKey(key, AES_BLOCK_SIZE);
        generateRandomIV(iv, AES_BLOCK_SIZE);

        globalEncryptionParams = EncryptionParameters(key, iv);
    }

    AESEncryption(bool det, unsigned char detIV = 0) {
        if (det) {
            generateRandomKey(key, AES_BLOCK_SIZE);
            memset(iv, detIV, AES_BLOCK_SIZE);
        } else {
            generateRandomKey(key, AES_BLOCK_SIZE);
            generateRandomIV(iv, AES_BLOCK_SIZE);
        }

        globalEncryptionParams = EncryptionParameters(key, iv);
    }

    AESEncryption(const unsigned char* key, const unsigned char* iv) {
        memcpy(this->key, key, AES_BLOCK_SIZE);
        memcpy(this->iv, iv, AES_BLOCK_SIZE);

        globalEncryptionParams = EncryptionParameters(key, iv);
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

private:
    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    int ciphertext_len;
    int plaintext_len;
};

void testRandom() {
    AESEncryption aesRandomEncryption;

    const char* plaintext = "Hello, World!";
    unsigned char ciphertext[128];

    aesRandomEncryption.encrypt(reinterpret_cast<const unsigned char*>(plaintext), strlen(plaintext), ciphertext);

    char hexString[2 * aesRandomEncryption.getCiphertextLen() + 1];
    aesRandomEncryption.ucharToHex(ciphertext, aesRandomEncryption.getCiphertextLen(), hexString);
    printf("Ciphertext in Hex:\n%s\n", hexString);

    std::cout << "Key: ";
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", globalEncryptionParams.key[i]);
    }
    std::cout << std::endl;

    std::cout << "IV: ";
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        printf("%02x", globalEncryptionParams.iv[i]);
    }
    std::cout << std::endl;

    unsigned char decryptedtext[128];
    AESEncryption aesDecryption(globalEncryptionParams.key, globalEncryptionParams.iv);
    aesDecryption.decrypt(ciphertext, aesRandomEncryption.getCiphertextLen(), decryptedtext);
    decryptedtext[aesDecryption.getPlaintextLen()] = '\0';

    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);
}

void testDeterministic() {
    const char* plaintext = "Hello, World!";
    unsigned char ciphertext1[128];
    unsigned char ciphertext2[128];

    AESEncryption aesDeterministic1(true);
    AESEncryption aesDeterministic2(globalEncryptionParams.key, globalEncryptionParams.iv);

    aesDeterministic1.encrypt(reinterpret_cast<const unsigned char*>(plaintext), strlen(plaintext), ciphertext1);
    aesDeterministic2.encrypt(reinterpret_cast<const unsigned char*>(plaintext), strlen(plaintext), ciphertext2);

    char hexString1[2 * aesDeterministic1.getCiphertextLen() + 1];
    aesDeterministic1.ucharToHex(ciphertext1, aesDeterministic1.getCiphertextLen(), hexString1);
    printf("Ciphertext 1 in Hex:\n%s\n", hexString1);

    char hexString2[2 * aesDeterministic2.getCiphertextLen() + 1];
    aesDeterministic2.ucharToHex(ciphertext2, aesDeterministic2.getCiphertextLen(), hexString2);
    printf("Ciphertext 2 in Hex:\n%s\n", hexString2);

    if (memcmp(ciphertext1, ciphertext2, std::min(aesDeterministic1.getCiphertextLen(), aesDeterministic2.getCiphertextLen())) == 0) {
        std::cout << "Ciphertexts match!" << std::endl;
    } else {
        std::cout << "Ciphertexts do not match!" << std::endl;
    }
}

int main() {
    testRandom();
    testDeterministic();
    return 0;
}
