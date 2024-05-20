#include "OPEModule.hh"
#include "OPEModule.cc"
#include <chrono>
#include <vector>
#include <utility>
#include <iostream>

using namespace std;

void clientScenario(unsigned long enc1, unsigned long enc2, const OPEModule::KEY_TYPE& key, OPEModule& opeModule) {
    auto startClient = chrono::high_resolution_clock::now();
    int dec1 = opeModule.decrypt(enc1, key);
    int dec2 = opeModule.decrypt(enc2, key);

    if (dec1 < dec2) {
        cout << "a < b" << endl;
    } else {
        cout << "a > b" << endl;
    }
    auto endClient = chrono::high_resolution_clock::now();
    auto durationClient = chrono::duration_cast<chrono::microseconds>(endClient - startClient);
    cout << "Client comparing: " << durationClient.count() << " microseconds" << endl;

    if (dec1 == dec2) {
        cout << "Decryption test: FAIL" << endl;
    } else {
        cout << "Decryption test: OK" << endl;
    }
}

void serverScenario(unsigned long enc1, unsigned long enc2) {
    auto startServer = chrono::high_resolution_clock::now();
    if (enc1 < enc2) {
        cout << "enc(a) < enc(b)" << endl;
    } else {
        cout << "enc(a) > enc(b)" << endl;
    }
    auto endServer = chrono::high_resolution_clock::now();
    auto durationServer = chrono::duration_cast<chrono::microseconds>(endServer - startServer);
    cout << "Server comparing: " << durationServer.count() << " microseconds" << endl;
}

int main() {
    vector<pair<uint, uint>> pairsToTest = {{45, 50}, {99, 78}, {123, 567}, {2147483645, 2147483646}};

    for (const auto& pair : pairsToTest) {
        cout << "Testing pair (" << pair.first << ", " << pair.second << "):" << endl << endl;

        OPEModule opeModule;
        OPEModule::KEY_TYPE key = opeModule.generateKey();

        // Encrypt the data
        auto startEncrypt = chrono::high_resolution_clock::now();
        unsigned long enc1 = opeModule.encrypt(pair.first, key);
        unsigned long enc2 = opeModule.encrypt(pair.second, key);
        auto endEncrypt = chrono::high_resolution_clock::now();
        auto durationEncrypt = chrono::duration_cast<chrono::microseconds>(endEncrypt - startEncrypt);
        cout << "Encryption time: " << durationEncrypt.count() << " microseconds" << endl;

        // Print encrypted values
        cout << "Encrypted values: " << enc1 << "  " << enc2 << endl;

        // Client scenario
        cout << "ClientTest:\n";
        clientScenario(enc1, enc2, key, opeModule);
        cout << endl;

        // Server scenario
        cout << "ServerTest:\n";
        serverScenario(enc1, enc2);
        cout << endl;
    }
    return 0;
    /*
    Testing pair (45, 50):

    Encryption time: 5029 microseconds
    Encrypted values: 219464705085  240746831791
    ClientTest:
    a < b
    Client comparing: 297 microseconds
    Decryption test: OK

    ServerTest:
    enc(a) < enc(b)
    Server comparing: 1 microseconds

    Testing pair (99, 78):

    Encryption time: 4704 microseconds
    Encrypted values: 503588909781  420980835807
    ClientTest:
    a > b
    Client comparing: 265 microseconds
    Decryption test: OK

    ServerTest:
    enc(a) > enc(b)
    Server comparing: 1 microseconds

    Testing pair (123, 567):

    Encryption time: 5369 microseconds
    Encrypted values: 614194890946  2462328561069
    ClientTest:
    a < b
    Client comparing: 310 microseconds
    Decryption test: OK

    ServerTest:
    enc(a) < enc(b)
    Server comparing: 1 microseconds

    Testing pair (2147483645, 2147483646):

    Encryption time: 4426 microseconds
    Encrypted values: 9223058009514190446  9223058014137620870
    ClientTest:
    a < b
    Client comparing: 286 microseconds
    Decryption test: OK

    ServerTest:
    enc(a) < enc(b)
    Server comparing: 1 microseconds
    */
}
