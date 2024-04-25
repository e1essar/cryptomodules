#include "OPEModule.hh"
#include "OPEModule.cc"
#include <chrono>
#include <vector>
#include <utility>

using namespace std;

bool compareStrings(const string& s1, const string& s2) {
    if (s1.length() != s2.length()) {
        return s1.length() < s2.length();
    }
    
    return s1 < s2;
}

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

    cout << enc1 << "  " << enc2 << endl;
    if (compareStrings(enc1, enc2)) {
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

    /*
    Testing pair (45, 46):
    Encryption time: 4637 microseconds
    Decryption time: 189 microseconds
    219464705085  219897038332
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (99, 78):
    Encryption time: 4576 microseconds
    Decryption time: 162 microseconds
    503588909781  420980835807
    Encryption test: FAIL
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (123, 567):
    Encryption time: 5276 microseconds
    Decryption time: 173 microseconds
    614194890946  2462328561069
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (-12, -5):
    Encryption time: 4305 microseconds
    Decryption time: 150 microseconds
    2343650153  6006721824
    Encryption test: OK
    Decryption test for a: FAIL
    Decryption test for b: FAIL
    */

    return 0;
}
