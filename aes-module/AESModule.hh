#pragma once

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <string.h>
#include <cstdlib>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <cassert>

class AESModule{
public:
    AESModule();
    ~AESModule();

    // input and output
    typedef std::vector<unsigned char> INPUT_TYPE;
    typedef std::vector<unsigned char> OUTPUT_TYPE;
    // key and iv
    typedef std::vector<unsigned char> DEFAULT_TYPE;
    typedef unsigned char* TEST_TYPE;
    // encryption and decryption
    OUTPUT_TYPE encrypt(INPUT_TYPE &input, DEFAULT_TYPE &key, DEFAULT_TYPE &iv);
    INPUT_TYPE decrypt(INPUT_TYPE &input, DEFAULT_TYPE &key, DEFAULT_TYPE &iv);
    // hex
    DEFAULT_TYPE ucharToHex(const DEFAULT_TYPE& data) const;
    OUTPUT_TYPE hexStringToUchar(const DEFAULT_TYPE& hexCiphertext) const; 
    // random key and iv generation
    DEFAULT_TYPE generateKey();
    DEFAULT_TYPE generateIv();

private:

};
