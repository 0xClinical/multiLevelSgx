#pragma once

#include <string>
#include <vector>
#include <utility>
#include "sgx_tcrypto.h"

namespace CryptoUtils {
   
    std::string H1(const std::string& key, const std::string& input);
    std::string H2(const std::string& key, const std::string& r);
    std::string H3(const std::string& stateKey, const std::string& keyword);
    std::string H4(const std::string& key, const std::string& input);
    std::string H5(const std::string& key, const std::string& input);
    std::string PRF(const std::string& z, const std::string& r);
    std::string F1(const std::string& key, const std::string& input);
    std::string F1_inverse(const std::string& key, const std::string& encrypted_input);
    std::string F2(const std::string& key, const std::string& input);
    std::string F2_inverse(const std::string& key, const std::string& encrypted_input);
    std::string xorStrings(const std::string& a, const std::string& b);
    std::string computeDigest(const std::string& input);
    size_t stringToSize(const std::string& input);
 
    std::pair<std::string, std::string> generateKeyPair();
    std::string signWithPrivateKey(const std::string& data, const std::string& private_key);
    bool verifySignature(const std::string& data, const std::string& signature, const std::string& public_key);
    std::string base64Encode(const std::string& input);
    std::string base64Decode(const std::string& input);
    std::string generateRandom(size_t len);
    std::string aesEncrypt(const std::string& data, const std::string& key, const std::string& iv);
    std::string aesDecrypt(const std::string& data, const std::string& key, const std::string& iv);
    
   
    std::string generateRandomString(size_t length = 32);

    std::pair<size_t, std::string> xorPair(const std::pair<size_t, std::string>& p, const std::string& key);
}