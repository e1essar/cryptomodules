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

void runTests(uint a, uint b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    auto startEncrypt = chrono::high_resolution_clock::now();
    unsigned long enc1 = opeModule.encrypt(a, key);
    unsigned long enc2 = opeModule.encrypt(b, key);
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

void runTestsString(uint a, uint b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    auto startEncrypt = chrono::high_resolution_clock::now();
    string enc1 = opeModule.encryptS(a, key);
    string enc2 = opeModule.encryptS(b, key);
    auto endEncrypt = chrono::high_resolution_clock::now();
    auto durationEncrypt = chrono::duration_cast<chrono::microseconds>(endEncrypt - startEncrypt);
    cout << "Encryption time: " << durationEncrypt.count() << " microseconds" << endl;

    auto startDecrypt = chrono::high_resolution_clock::now();
    int dec1 = opeModule.decryptS(enc1, key);
    int dec2 = opeModule.decryptS(enc2, key);
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
     vector<pair<uint, uint>> pairsToTest = {{45, 50}, {99, 78}, {123, 567}, {2147483645, 2147483646}};

    for (const auto& pair : pairsToTest) {
        cout << "Testing pair (" << pair.first << ", " << pair.second << "):" << endl << endl;
        cout << "StringTest:\n";
        runTestsString(pair.first, pair.second);
        cout << "\nLongTest:\n";
        runTests(pair.first, pair.second);
        cout << endl;
    }

    return 0;

    /*
    Testing pair (45, 50):
    
    StringTest:
    Encryption time: 5122 microseconds
    Decryption time: 142 microseconds
    219464705085  240746831791
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    LongTest:
    Encryption time: 3557 microseconds
    Decryption time: 213 microseconds
    219464705085  240746831791
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (99, 78):
    
    StringTest:
    Encryption time: 3606 microseconds
    Decryption time: 127 microseconds
    503588909781  420980835807
    Encryption test: FAIL
    Decryption test for a: OK
    Decryption test for b: OK
    
    LongTest:
    Encryption time: 3702 microseconds
    Decryption time: 126 microseconds
    503588909781  420980835807
    Encryption test: FAIL
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (123, 567):
    
    StringTest:
    Encryption time: 4342 microseconds
    Decryption time: 229 microseconds
    614194890946  2462328561069
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    LongTest:
    Encryption time: 3973 microseconds
    Decryption time: 233 microseconds
    614194890946  2462328561069
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    Testing pair (2147483645, 2147483646):
    
    StringTest:
    Encryption time: 3490 microseconds
    Decryption time: 224 microseconds
    9223058009514190446  9223058014137620870
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    
    LongTest:
    Encryption time: 3647 microseconds
    Decryption time: 128 microseconds
    9223058009514190446  9223058014137620870
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK
    */
}
