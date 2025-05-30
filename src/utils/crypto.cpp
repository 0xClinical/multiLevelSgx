#include "utils/crypto.h"
#include <openssl/aes.h>
#include <iostream>


std::string CryptoUtils::H1(const std::string& key, const std::string& input) {
    return PRF(key, input);
}

std::string CryptoUtils::H2(const std::string& key, const std::string& r) {
    return PRF(key, r);
}

std::string CryptoUtils::H3(const std::string& stateKey, const std::string& keyword) {
    return PRF(stateKey, keyword);
}

std::string CryptoUtils::H4(const std::string& key, const std::string& input) {
    return PRF(key, input);
}

std::string CryptoUtils::H5(const std::string& key, const std::string& input) {
    return PRF(key, input);
}

std::string CryptoUtils::PRF(const std::string& key, const std::string& msg) {
    std::string combined = key + msg;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.length());
    SHA256_Final(hash, &sha256);
    return std::string((char*)hash, SHA256_DIGEST_LENGTH);
}

std::string CryptoUtils::F1(const std::string& key, const std::string& input) {
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    std::string encrypted;
    encrypted.reserve(input.length());
    for (size_t i = 0; i < input.length(); i++) {
        encrypted += input[i] ^ padded_key[i % 32];
    }
    return encrypted;
}

std::string CryptoUtils::F1_inverse(const std::string& key, const std::string& encrypted_input) {
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    std::string decrypted;
    decrypted.reserve(encrypted_input.length());
    for (size_t i = 0; i < encrypted_input.length(); i++) {
        decrypted += encrypted_input[i] ^ padded_key[i % 32];
    }
    return decrypted;
}

std::string CryptoUtils::F2(const std::string& key, int level) {
    unsigned char output[16];
    AES_KEY aes_key;
    
  
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
  
    std::string level_str = std::to_string(level);
    std::string padded_input = "F2";
    padded_input += std::string(1, static_cast<char>(level));  
    padded_input.resize(16, 0);
    
 
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(padded_key.c_str()), 256, &aes_key);
    AES_encrypt(reinterpret_cast<const unsigned char*>(padded_input.c_str()), output, &aes_key);
    
    return std::string(reinterpret_cast<char*>(output), 16);
}

std::string CryptoUtils::F2_inverse(const std::string& key, const std::string& encrypted_level) {
    unsigned char output[16];
    AES_KEY aes_key;
    
    
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(padded_key.c_str()), 256, &aes_key);
    AES_decrypt(reinterpret_cast<const unsigned char*>(encrypted_level.c_str()), output, &aes_key);
    

    std::string decrypted(reinterpret_cast<char*>(output), 16);
    if (decrypted.substr(0, 2) != "F2") {
        throw std::runtime_error("Invalid F2 prefix");
    }
    
  
    return std::to_string(static_cast<int>(decrypted[2]));
}

std::string CryptoUtils::generateRandomString(size_t length) {
    unsigned char buf[length];
    if (RAND_bytes(buf, length) != 1) {
        throw std::runtime_error("Failed to generate random string");
    }
    return std::string(reinterpret_cast<char*>(buf), length);
}

std::string CryptoUtils::generateRandomKey(size_t length) {
    unsigned char key[length];
    if (RAND_bytes(key, length) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    
  
    std::string hexKey;
    for (size_t i = 0; i < length; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", key[i]);
        hexKey += hex;
    }
    return hexKey;
}
std::string CryptoUtils::bytesToHex(const unsigned char* bytes, size_t len) {
    std::string hex;
    for (size_t i = 0; i < len; i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        hex += buf;
    }
    return hex;
}

std::string CryptoUtils::xorStrings(const std::string& a, const std::string& b) {
  
    const std::string& longer = (a.length() >= b.length()) ? a : b;
    const std::string& shorter = (a.length() >= b.length()) ? b : a;
    
    std::string result = longer;

    for (size_t i = 0; i < longer.length(); i++) {
        result[i] ^= shorter[i % shorter.length()];
    }
    
    return result;
}
size_t CryptoUtils::stringToSize(const std::string& input) {
  
    std::string hash = computeDigest(input);
    
   
    size_t result = 0;
    for (size_t i = 0; i < sizeof(size_t); i++) {
        result = (result << 8) | (static_cast<unsigned char>(hash[i]));
    }          
    return result;
}
std::pair<size_t, std::string> CryptoUtils::xorPair(
    const std::pair<size_t, std::string>& a,
    const std::string& b) {
    
    // 将哈希字符串转换为数字
    size_t b_num = stringToSize(b);
    
    // 直接对数字进行异或
    size_t new_first = a.first ^ b_num;
    
    // 第二个元素保持字符串异或
    std::string new_second = xorStrings(a.second, b);
    
    return {new_first, new_second};
}

std::string CryptoUtils::computeDigest(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
   // 直接返回二进制数据
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

std::pair<std::string, std::string> CryptoUtils::generateKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    
    // 转换为PEM格式
    BIO* pubBio = BIO_new(BIO_s_mem());
    BIO* privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBio, pkey);
    PEM_write_bio_PrivateKey(privBio, pkey, NULL, NULL, 0, NULL, NULL);
    
    // 读取为字符串
    char* pubData = NULL;
    char* privData = NULL;
    long pubLen = BIO_get_mem_data(pubBio, &pubData);
    long privLen = BIO_get_mem_data(privBio, &privData);
    
    std::string publicKey(pubData, pubLen);
    std::string privateKey(privData, privLen);
    
    // 清理
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    BIO_free(pubBio);
    BIO_free(privBio);
    
    return {publicKey, privateKey};
}

std::string CryptoUtils::computeAES(const std::string& key, 
                                   const std::string& input,
                                   const std::string& prefix) {
    // 准备输入 (确保总长度是16的倍数)
    std::string padded_input = prefix + input;
    size_t block_size = ((padded_input.length() + 15) / 16) * 16;
    padded_input.resize(block_size, 0);
    
    // 准备密钥 (32字节)
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    // 准备输出缓冲区
    std::vector<unsigned char> output(block_size);
    AES_KEY aes_key;
    AES_set_encrypt_key((unsigned char*)padded_key.c_str(), 256, &aes_key);
    
    // 使用CBC模式加密
    unsigned char iv[16] = {0};  // 初始化向量
    AES_cbc_encrypt(
        (unsigned char*)padded_input.c_str(),
        output.data(),
        block_size,
        &aes_key,
        iv,
        AES_ENCRYPT
    );
    
    // 存储原始长度和加密数据
    size_t original_length = input.length();
    std::string result;
    result.reserve(sizeof(size_t) + block_size);
    result.append(reinterpret_cast<char*>(&original_length), sizeof(size_t));
    result.append((char*)output.data(), block_size);
    
    return result;
}

// AES 解密实现
std::string CryptoUtils::computeAES_decrypt(const std::string& key, 
                                          const std::string& encrypted_input,
                                          const std::string& prefix) {
   
    if (encrypted_input.length() < sizeof(size_t)) {
        throw std::runtime_error("Invalid encrypted input");
    }
    
    size_t original_length;
    memcpy(&original_length, encrypted_input.data(), sizeof(size_t));
    
   
    std::string encrypted_data = encrypted_input.substr(sizeof(size_t));
    if (encrypted_data.length() % 16 != 0) {
        throw std::runtime_error("Invalid input length for AES decryption");
    }
    
 
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
  
    std::vector<unsigned char> output(encrypted_data.length());
    AES_KEY aes_key;
    AES_set_decrypt_key((unsigned char*)padded_key.c_str(), 256, &aes_key);
    
   
    unsigned char iv[16] = {0}; 
    AES_cbc_encrypt(
        (unsigned char*)encrypted_data.c_str(),
        output.data(),
        encrypted_data.length(),
        &aes_key,
        iv,
        AES_DECRYPT
    );
    
    
    std::string decrypted((char*)output.data(), output.size());
    if (decrypted.substr(0, prefix.length()) != prefix) {
        throw std::runtime_error("Invalid prefix in decrypted data");
    }
    
   
    return decrypted.substr(prefix.length(), original_length);
}
// 使用私钥签名
std::string CryptoUtils::signWithPrivateKey(const std::string& data, const std::string& private_key) {
    
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);
    if (!bio) return "";
    
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return "";
    
   
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }
    
    
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
  
    if (EVP_DigestSignUpdate(ctx, data.c_str(), data.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 获取签名长度
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 生成签名
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        OPENSSL_free(sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // Base64编码签名
    std::string signature = base64Encode(std::string(
        reinterpret_cast<char*>(sig), 
        sig_len
    ));
    
    OPENSSL_free(sig);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return signature;
}

// 使用公钥验证签名
bool CryptoUtils::verifySignature(const std::string& data, 
                                 const std::string& signature,
                                 const std::string& public_key) {
   
    std::string decoded_sig = base64Decode(signature);
    

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(public_key.c_str(), -1);
    if (!bio) return false;
    
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;
    
  
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }
    

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
  
    if (EVP_DigestVerifyUpdate(ctx, data.c_str(), data.length()) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
   
    int ret = EVP_DigestVerifyFinal(ctx, 
        reinterpret_cast<const unsigned char*>(decoded_sig.c_str()),
        decoded_sig.length());
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return (ret == 1);
}

std::string CryptoUtils::base64Encode(const std::string& input) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = input.size();
    const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.data());

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::string CryptoUtils::base64Decode(const std::string& encoded_string) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && 
           (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || 
            (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) 
            ret += char_array_3[j];
    }

    return ret;
}
