#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>  // 添加这一行，用于memcpy
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <random>

class CryptoUtils {
public:
    // 通用密码学操作
    static size_t generateRandomAddress(size_t maxSize);
    static std::string computeDigest(const std::string& input);
    static std::string generateRandomString(size_t length = SECURITY_PARAMETER);
    static std::string generateRandomKey(size_t length = SECURITY_PARAMETER);
    
    static std::string signWithPrivateKey(const std::string& data, const std::string& private_key);
    static bool verifySignature(const std::string& data, 
                                 const std::string& signature,
                                 const std::string& public_key);
    // PRF函数族
    static std::string H1(const std::string& key, const std::string& input);
    static std::string H2(const std::string& key, const std::string& r);
    static std::string H3(const std::string& stateKey, const std::string& keyword);
    static std::string H4(const std::string& key, const std::string& input);
    static std::string H5(const std::string& key, const std::string& input);
    
    // 加密函数
    static std::string F1(const std::string& key, const std::string& id);
    static std::string F1_inverse(const std::string& key, const std::string& encrypted_id);
    static std::string F2(const std::string& key, int level);
    static std::string F2_inverse(const std::string& key, const std::string& encrypted_level);
    
    // 字符串操作
    static std::string xorStrings(const std::string& a, const std::string& b);
    static std::pair<size_t, std::string> xorPair(
        const std::pair<size_t, std::string>& a,
        const std::string& b);
    
    // 密钥对生成
    static std::pair<std::string, std::string> generateKeyPair();

    static std::string base64Encode(const std::string& input);
    static std::string base64Decode(const std::string& input);

    static size_t stringToSize(const std::string& input);
    static std::string computeAES(const std::string& key, const std::string& input, const std::string& prefix);
    static std::string computeAES_decrypt(const std::string& key, const std::string& input, const std::string& prefix);

private:
    // 安全参数
    static const size_t SECURITY_PARAMETER = 256;  // κ
    static std::string bytesToHex(const unsigned char* bytes, size_t len);
    static std::string computeHMAC(const std::string& key, const std::string& input);
    static std::string PRF(const std::string& z, const std::string& r);
};
