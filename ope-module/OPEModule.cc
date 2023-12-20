#include "OPEModule.hh"

OPEModule::OPEModule(const std::string &key, size_t plainbits, size_t cipherbits)
    : opeInstance(key, plainbits, cipherbits) {
}

OPEModule::~OPEModule() {

}

OPEModule::TEST_TYPE OPEModule::encrypt(INPUT_TYPE input, KEY_TYPE key) {
    TEST_TYPE ciphertext = opeInstance.encrypt(input);

    cout << "input = " << input << endl;
    cout << "enc = " << ciphertext << endl;

    return ciphertext;
}

OPEModule::TEST_TYPE OPEModule::decrypt(TEST_TYPE input, KEY_TYPE key) {
    TEST_TYPE plaintext = opeInstance.decrypt(input);

    cout << "input = " << input << endl;
    cout << "dec = " << plaintext << endl;

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
