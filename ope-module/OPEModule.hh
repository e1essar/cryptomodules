#pragma once

#include<iostream>
#include <vector>
#include <random>
#include <NTL/ZZ.h>
#include "lib/ope.hh"

using namespace std;

class OPEModule {
public:
    OPEModule(const std::string &key = "default_key", size_t plainbits = 32, size_t cipherbits = 64);
    ~OPEModule();
    
    typedef int INPUT_TYPE;
    typedef unsigned long OUTPUT_TYPE;

    typedef std::string KEY_TYPE;
    typedef std::string STRING_TYPE;
    typedef int DEFAULT_TYPE;
    using TEST_TYPE = NTL::ZZ;

    OUTPUT_TYPE encrypt(INPUT_TYPE input, KEY_TYPE key);
    INPUT_TYPE decrypt(OUTPUT_TYPE input, KEY_TYPE key);

    STRING_TYPE encryptS(INPUT_TYPE input, KEY_TYPE key);
    INPUT_TYPE decryptS(STRING_TYPE input, KEY_TYPE key);

    KEY_TYPE generateKey();

private:
    OPE opeInstance;
};
