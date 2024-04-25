#include "OPEModule.hh"
#include "OPEModule.cc"
#include <chrono>
#include <vector>
#include <utility>

using namespace std;

void runTests(int a, int b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    auto startEncrypt = chrono::high_resolution_clock::now();
    string enc1 = opeModule.encrypt(a, key);
    string enc2 = opeModule.encrypt(b, key);
    auto endEncrypt = chrono::high_resolution_clock::now();
    auto durationEncrypt = chrono::duration_cast<chrono::microseconds>(endEncrypt - startEncrypt);
    cout << "Encryption time: " << durationEncrypt.count() << " microseconds" << endl;

    auto startDecrypt = chrono::high_resolution_clock::now();
    int dec1 = opeModule.decrypt(enc1, key);
    int dec2 = opeModule.decrypt(enc2, key);
    auto endDecrypt = chrono::high_resolution_clock::now();
    auto durationDecrypt = chrono::duration_cast<chrono::microseconds>(endDecrypt - startDecrypt);
    cout << "Decryption time: " << durationDecrypt.count() << " microseconds" << endl;

    if (enc1 < enc2) {
        cout << "Encryption test: OK" << endl;
    } else {
        cout << "Encryption test: FAIL" << endl;
    }

    if (a == dec1) {
        cout << "Decryption test for a: OK" << endl;
    } else {
        cout << "Decryption test for a: FAIL" << endl;
    }

    if (b == dec2) {
        cout << "Decryption test for b: OK" << endl;
    } else {
        cout << "Decryption test for b: FAIL" << endl;
    }
}

int main() {
     vector<pair<int, int>> pairsToTest = {{45, 46}, {99, 78}, {123, 567}, {-12, -5}};

    for (const auto& pair : pairsToTest) {
        cout << "Testing pair (" << pair.first << ", " << pair.second << "):" << endl;
        runTests(pair.first, pair.second);
        cout << endl;
    }

    return 0;
}
