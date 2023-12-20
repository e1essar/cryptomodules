#include "AESModule.hh"

AESModule::AESModule() {
}

AESModule::~AESModule() {
}

void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

AESModule::OUTPUT_TYPE AESModule::encrypt(INPUT_TYPE &input, DEFAULT_TYPE &key, DEFAULT_TYPE &iv) {
    size_t plaintext_len = input.size();
    size_t ciphertext_len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()))
        handleErrors();

    std::vector<unsigned char> ciphertext(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, input.data(), plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    return ciphertext;
}


AESModule::INPUT_TYPE AESModule::decrypt(INPUT_TYPE &input, DEFAULT_TYPE &key, DEFAULT_TYPE &iv) {
    size_t ciphertext_len = input.size();
    size_t plaintext_len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()))
        handleErrors();

    std::vector<unsigned char> plaintext(ciphertext_len);

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, input.data(), ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);

    return plaintext;

}

AESModule::DEFAULT_TYPE AESModule::generateKey() {
    DEFAULT_TYPE key(AES_BLOCK_SIZE);
    RAND_bytes(key.data(), AES_BLOCK_SIZE);
    return key;
}

AESModule::DEFAULT_TYPE AESModule::generateIv() {
    DEFAULT_TYPE iv(AES_BLOCK_SIZE);
    RAND_bytes(iv.data(), AES_BLOCK_SIZE);
    return iv;
}

AESModule::DEFAULT_TYPE AESModule::ucharToHex(const DEFAULT_TYPE &data) const {
    size_t len = data.size();
    DEFAULT_TYPE hexString(2 * len);

    for (size_t i = 0; i < len; ++i) {
        sprintf(reinterpret_cast<char*>(&hexString[2 * i]), "%02x", data[i]);
    }

    return hexString;
}

AESModule::OUTPUT_TYPE AESModule::hexStringToUchar(const DEFAULT_TYPE& hexCiphertext) const {
    size_t len = hexCiphertext.size();
    DEFAULT_TYPE result(len / 2, 0);

    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        std::istringstream hexByte(std::string(hexCiphertext.begin() + i, hexCiphertext.begin() + i + 2));
        hexByte >> std::hex >> byte;
        result[i / 2] = static_cast<unsigned char>(byte);
    }

    return result;
}
