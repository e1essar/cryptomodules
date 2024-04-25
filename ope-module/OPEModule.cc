#include "OPEModule.hh"

OPEModule::OPEModule(const std::string &key, size_t plainbits, size_t cipherbits)
    : opeInstance(key, plainbits, cipherbits) {
}

OPEModule::~OPEModule() {

}

OPEModule::STRING_TYPE OPEModule::encrypt(INPUT_TYPE input, KEY_TYPE key) {
    TEST_TYPE ciphertext = opeInstance.encrypt(input);
    STRING_TYPE ciphertextStr = StringFromZZ(ciphertext);

    //cout << "input = " << input << endl;
    //cout << "enc = " << ciphertext << endl;

    return ciphertextStr;
}

OPEModule::INPUT_TYPE OPEModule::decrypt(STRING_TYPE input, KEY_TYPE key) {
    TEST_TYPE ciphertext = ZZFromString(input);

    TEST_TYPE plaintext = opeInstance.decrypt(ciphertext);

    STRING_TYPE plaintextStr = DecStringFromZZ(plaintext);
    int plaintextInt = std::stoi(plaintextStr);

    //cout << "input = " << input << endl;
    //cout << "dec = " << plaintextInt << endl;

    return plaintextInt;
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
