#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "openssl/evp.h"

bool computeHash(const std::string& unhashed, std::string& hashed)
{
    bool success = false;

    EVP_MD_CTX* context = EVP_MD_CTX_new();

    if (context != NULL)
    {
        if (EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
            if (EVP_DigestUpdate(context, unhashed.c_str(), unhashed.length()))
            {
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int lengthOfHash = 0;

                if (EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    std::stringstream ss;
                    for (unsigned int i = 0; i < lengthOfHash; ++i)
                    {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }

                    hashed = ss.str();
                    success = true;
                }
            }
        }

        EVP_MD_CTX_free(context);
    }

    return success;
}

int main(int, char**)
{
    std::string pw1 = "password1", pw1hashed;
    std::string pw2 = "password2", pw2hashed;
    std::string pw3 = "password3", pw3hashed;
    std::string pw4 = "password4", pw4hashed;

    computeHash(pw1, pw1hashed);
    computeHash(pw2, pw2hashed);
    computeHash(pw3, pw3hashed);
    computeHash(pw4, pw4hashed);

    std::cout << pw1hashed << std::endl;
    std::cout << pw2hashed << std::endl;
    std::cout << pw3hashed << std::endl;
    std::cout << pw4hashed << std::endl;

    return 0;
}