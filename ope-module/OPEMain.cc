#include "OPEModule.hh"
#include "OPEModule.cc"

using namespace std;

int main() {
    OPEModule opeModule;

    OPEModule::KEY_TYPE key = opeModule.generateKey();
    int a = 45;
    int b = 46;

    OPEModule::TEST_TYPE enc1 = opeModule.encrypt(a, key);
    OPEModule::TEST_TYPE enc2 = opeModule.encrypt(b, key);

    OPEModule::TEST_TYPE dec1 = opeModule.decrypt(enc1, key);
    OPEModule::TEST_TYPE dec2 = opeModule.decrypt(enc2, key);

    if(enc1 < enc2) {
        cout << "OK" << endl;
    }

    if(a == dec1) {
        cout << "OK" << endl;
    }

    if(b == dec2) {
        cout << "OK" << endl;
    }


    return 0;
}
