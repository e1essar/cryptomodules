#include "OPEModule.hh"

OPEModule::OPEModule(const std::string &key, size_t plainbits, size_t cipherbits)
    : opeInstance(key, plainbits, cipherbits) {
}

OPEModule::~OPEModule() {

}

OPEModule::OUTPUT_TYPE OPEModule::encrypt(INPUT_TYPE input, KEY_TYPE key) {
    OUTPUT_TYPE ciphertext = to_ulong(opeInstance.encrypt(input));

    //cout << "input = " << input << endl;
    //cout << "enc = " << ciphertextLong << endl;

    return ciphertext;
}

OPEModule::INPUT_TYPE OPEModule::decrypt(OUTPUT_TYPE input, KEY_TYPE key) {
    OUTPUT_TYPE plaintext = to_int(opeInstance.decrypt(NTL::to_ZZ(input)));

    //cout << "input = " << input << endl;
    //cout << "dec = " << plaintextInt << endl;

    return plaintext;
}

OPEModule::STRING_TYPE OPEModule::encryptS(INPUT_TYPE input, KEY_TYPE key) {
    STRING_TYPE ciphertext = DecStringFromZZ(opeInstance.encrypt(input));

    //cout << "input = " << input << endl;
    //cout << "enc = " << ciphertext << endl;

    return ciphertext;
}

OPEModule::INPUT_TYPE OPEModule::decryptS(STRING_TYPE input, KEY_TYPE key) {
    INPUT_TYPE plaintext = std::stoi(DecStringFromZZ(opeInstance.decrypt(ZZFromDecString(input))));

    //cout << "input = " << input << endl;
    //cout << "dec = " << plaintextInt << endl;

    return plaintext;
}


OPEModule::KEY_TYPE OPEModule::generateKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<char> distribution('a', 'z');

    KEY_TYPE key;
    key.resize(16); 

    for (auto& character : key) {
        character = distribution(gen);
    }

    return key;
}
