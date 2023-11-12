#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>

class AESEncryption {
public:
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

int main(void) {
    // Key and IV
    unsigned char key[] = "0123456789abcdef";
    unsigned char iv[] = "1234567887654321";
    unsigned char plaintext[] = "Advanced Encryption Standard(AES) is a symmetric encryption algorithm";
    
    // Buffer for ciphertext
    unsigned char ciphertext[128];
    // Buffer for the decrypted text
    unsigned char decryptedtext[128];

    AESEncryption aes(key, iv);
    aes.encrypt(plaintext, strlen((char*)plaintext), ciphertext);

    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext, aes.getCiphertextLen());

    // HEX
    char hexString[2 * aes.getCiphertextLen() + 1];
    aes.ucharToHex(ciphertext, aes.getCiphertextLen(), hexString);
    printf("Ciphertext in Hex:\n%s\n", hexString);

    aes.decrypt(ciphertext, aes.getCiphertextLen(), decryptedtext);
    decryptedtext[aes.getPlaintextLen()] = '\0';

    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    return 0;
}
