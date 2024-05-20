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

void testClient(uint a, uint b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    auto startEncrypt1 = chrono::high_resolution_clock::now();
    unsigned long enc1 = opeModule.encrypt(a, key);
    auto endEncrypt1 = chrono::high_resolution_clock::now();
    auto durationEncrypt1 = chrono::duration_cast<chrono::microseconds>(endEncrypt1 - startEncrypt1);
    cout << "First word encryption: " << durationEncrypt1.count() << " microseconds" << endl;
    cout << enc1 << endl;

    auto startEncrypt2 = chrono::high_resolution_clock::now();
    unsigned long enc2 = opeModule.encrypt(b, key);
    auto endEncrypt2 = chrono::high_resolution_clock::now();
    auto durationEncrypt2 = chrono::duration_cast<chrono::microseconds>(endEncrypt2 - startEncrypt2);
     cout << "Second word encryption: " << durationEncrypt2.count() << " microseconds" << endl;
    cout << enc2 << endl;

    auto startDecrypt1 = chrono::high_resolution_clock::now();
    int dec1 = opeModule.decrypt(enc1, key);
    auto endDecrypt1 = chrono::high_resolution_clock::now();
    auto durationDecrypt1 = chrono::duration_cast<chrono::microseconds>(endDecrypt1 - startDecrypt1);
    cout << "First word decryption: " << durationDecrypt1.count() << " microseconds" << endl;
    cout << dec1 << endl;

    auto startDecrypt2 = chrono::high_resolution_clock::now();
    int dec2 = opeModule.decrypt(enc2, key);
    auto endDecrypt2 = chrono::high_resolution_clock::now();
    auto durationDecrypt2 = chrono::duration_cast<chrono::microseconds>(endDecrypt2 - startDecrypt2);
    cout << "Second word decryption: " << durationDecrypt2.count() << " microseconds" << endl;
    cout << dec2 << endl;

    auto startDecrypt3 = chrono::high_resolution_clock::now();
    if (enc1 < enc2) {
        cout << "Encryption test: OK" << endl;
    } else {
        cout << "Encryption test: FAIL" << endl;
    }
    auto endDecrypt3 = chrono::high_resolution_clock::now();
    auto durationDecrypt3 = chrono::duration_cast<chrono::microseconds>(endDecrypt3 - startDecrypt3);
    cout << "Comparing encrypted: " << durationDecrypt3.count() << " microseconds" << endl;

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

    auto startDecrypt4 = chrono::high_resolution_clock::now();
    if (dec1 < dec2) {
        cout << "a < b" << endl;
    } else {
        cout << "a > b" << endl;
    }
    auto endDecrypt4 = chrono::high_resolution_clock::now();
    auto durationDecrypt4 = chrono::duration_cast<chrono::microseconds>(endDecrypt4 - startDecrypt4);
    cout << "Comparing decrypted: " << durationDecrypt4.count() << " microseconds" << endl;
}

void clearTestClient(uint a, uint b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    unsigned long enc1 = opeModule.encrypt(a, key);
    cout << enc1 << endl;

    unsigned long enc2 = opeModule.encrypt(b, key);
    cout << enc2 << endl;

    auto startClient = chrono::high_resolution_clock::now();
    int dec1 = opeModule.decrypt(enc1, key);
    int dec2 = opeModule.decrypt(enc2, key);
    
    //cout << dec1 << endl;
    //cout << dec2 << endl;

    if (dec1 < dec2) {
        cout << "a < b" << endl;
    } else {
        cout << "a > b" << endl;
    }
    auto endClient = chrono::high_resolution_clock::now();
    auto durationClient = chrono::duration_cast<chrono::microseconds>(endClient - startClient);
    cout << "Client comparing: " << durationClient.count() << " microseconds" << endl;

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

void clearTestServer(uint a, uint b) {
    OPEModule opeModule;
    OPEModule::KEY_TYPE key = opeModule.generateKey();

    unsigned long enc1 = opeModule.encrypt(a, key);
    cout << enc1 << endl;

    unsigned long enc2 = opeModule.encrypt(b, key);
    cout << enc2 << endl;

    int dec1 = opeModule.decrypt(enc1, key);
    //cout << dec1 << endl;

    int dec2 = opeModule.decrypt(enc2, key);
    //cout << dec2 << endl;

    auto startServer = chrono::high_resolution_clock::now();
    if (enc1 < enc2) {
        cout << "enc(a) < enc(b)" << endl;
    } else {
        cout << "enc(a) > enc(b)" << endl;
    }
    auto endServer = chrono::high_resolution_clock::now();
    auto durationServer = chrono::duration_cast<chrono::microseconds>(endServer - startServer);
    cout << "Server comparing: " << durationServer.count() << " microseconds" << endl;

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
        
        cout << "ClientTest:\n";
        clearTestClient(pair.first, pair.second);
        cout << endl;

        cout << "ServerTest:\n";
        clearTestServer(pair.first, pair.second);
        cout << endl;
    }

    /*
    ClientTest:
    9223058009514190446
    9223058014137620870
    a < b
    Client comparing: 93 microseconds
    Decryption test for a: OK
    Decryption test for b: OK

    ServerTest:
    9223058009514190446
    9223058014137620870
    enc(a) < enc(b)
    Server comparing: 2 microseconds
    Decryption test for a: OK
    Decryption test for b: OK
    */

    return 0;

    /*
    Testing pair (45, 50):

    StringTest:
    Encryption time: 4828 microseconds
    Decryption time: 346 microseconds
    219464705085  240746831791
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK

    LongTest:
    Encryption time: 4920 microseconds
    Decryption time: 164 microseconds
    219464705085  240746831791
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK

    Testing pair (99, 78):

    StringTest:
    Encryption time: 4106 microseconds
    Decryption time: 136 microseconds
    503588909781  420980835807
    Encryption test: FAIL
    Decryption test for a: OK
    Decryption test for b: OK

    LongTest:
    Encryption time: 3375 microseconds
    Decryption time: 125 microseconds
    503588909781  420980835807
    Encryption test: FAIL
    Decryption test for a: OK
    Decryption test for b: OK

    Testing pair (123, 567):

    StringTest:
    Encryption time: 3969 microseconds
    Decryption time: 135 microseconds
    614194890946  2462328561069
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK

    LongTest:
    Encryption time: 4029 microseconds
    Decryption time: 132 microseconds
    614194890946  2462328561069
    Encryption test: OK
    Decryption test for a: OK
    Decryption test for b: OK

    Testing pair (4294967285, 4294967290):

    StringTest:
    Encryption time: 3529 microseconds
    Decryption time: 121 microseconds
    5614143207  5808229430
    Encryption test: OK
    Decryption test for a: FAIL
    Decryption test for b: FAIL

    LongTest:
    Encryption time: 3358 microseconds
    Decryption time: 115 microseconds
    5614143207  5808229430
    Encryption test: OK
    Decryption test for a: FAIL
    Decryption test for b: FAIL
    */
}
