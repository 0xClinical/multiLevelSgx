#include "enclave/crypto_sgx.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "Enclave_t.h"
#include <cstring>

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

std::string CryptoUtils::PRF(const std::string& z, const std::string& r) {
    sgx_sha256_hash_t hash;
    
    
    std::string combined = z + r;
    
   
    sgx_status_t status = sgx_sha256_msg(
        (const uint8_t*)combined.c_str(),
        combined.length(),
        &hash
    );
    
    if (status != SGX_SUCCESS) {
        return "";
    }
    
    return std::string((char*)hash, sizeof(hash));
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

std::string CryptoUtils::xorStrings(const std::string& a, const std::string& b) {
   
    const std::string& longer = (a.length() >= b.length()) ? a : b;
    const std::string& shorter = (a.length() >= b.length()) ? b : a;
    
    std::string result = longer;
    
 
    for (size_t i = 0; i < longer.length(); i++) {
        result[i] ^= shorter[i % shorter.length()];
    }
    
    return result;
}


std::string CryptoUtils::computeDigest(const std::string& input) {
    sgx_sha256_hash_t hash;
    
    sgx_status_t status = sgx_sha256_msg(
        (const uint8_t*)input.c_str(),
        input.length(),
        &hash
    );
    
    if (status != SGX_SUCCESS) {
        return "";
    }
    
 
    return std::string((char*)hash, sizeof(hash));
}

size_t CryptoUtils::stringToSize(const std::string& input) {
  
    sgx_sha256_hash_t hash;
    sgx_status_t status = sgx_sha256_msg(
        (const uint8_t*)input.c_str(),
        input.length(),
        &hash
    );
    
    if (status != SGX_SUCCESS) {
        
        return 1; 
    }
    

    size_t result = 0;
    for (size_t i = 0; i < sizeof(size_t) && i < sizeof(hash); i++) {
        result = (result << 8) | (static_cast<unsigned char>(hash[i]));
    }
    
   
    return result ? result : 1;
}

// F2加密函数
std::string CryptoUtils::F2(const std::string& key, const std::string& input) {
  
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    
    uint8_t iv[12];
    sgx_aes_gcm_128bit_tag_t mac;
    std::vector<uint8_t> ciphertext(input.length());
    
  
    sgx_read_rand(iv, 12);
    

    sgx_status_t ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)padded_key.data(),
        (const uint8_t*)input.data(),
        input.length(),
        ciphertext.data(),
        iv,
        12,
        nullptr,  
        0,
        &mac
    );
    
    if (ret != SGX_SUCCESS) {
        return "";
    }
    
  
    std::string result;
    result.reserve(12 + input.length() + sizeof(mac));
    result.append((char*)iv, 12);
    result.append((char*)ciphertext.data(), input.length());
    result.append((char*)&mac, sizeof(mac));
    
    return result;
}

// F2解密函数
std::string CryptoUtils::F2_inverse(const std::string& key, const std::string& encrypted_input) {
   
    if (encrypted_input.length() < 12 + sizeof(sgx_aes_gcm_128bit_tag_t)) {
        return "";  
    }
    
   
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    
    const uint8_t* iv = (const uint8_t*)encrypted_input.data();
    const size_t ciphertext_len = encrypted_input.length() - 12 - sizeof(sgx_aes_gcm_128bit_tag_t);
    const uint8_t* ciphertext = iv + 12;
    const sgx_aes_gcm_128bit_tag_t* mac = 
        (const sgx_aes_gcm_128bit_tag_t*)(encrypted_input.data() + encrypted_input.length() - sizeof(sgx_aes_gcm_128bit_tag_t));
    
 
    std::vector<uint8_t> plaintext(ciphertext_len);
    

    sgx_status_t ret = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)padded_key.data(),
        ciphertext,
        ciphertext_len,
        plaintext.data(),
        iv,
        12,
        nullptr,  
        0,
        mac
    );
    
    if (ret != SGX_SUCCESS) {
        return "";
    }
    

    return std::string((char*)plaintext.data(), ciphertext_len);
}

// 生成密钥对
std::pair<std::string, std::string> CryptoUtils::generateKeyPair() {
    size_t pubkey_len = 0;
    size_t privkey_len = 0;
    
    sgx_status_t status;
    sgx_status_t ret = ocall_generate_key_pair(&status, nullptr, &pubkey_len, nullptr, &privkey_len);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return {"", ""};
    }
    

    char* pubkey = (char*)malloc(pubkey_len);
    char* privkey = (char*)malloc(privkey_len);
    if (!pubkey || !privkey) {
        if (pubkey) free(pubkey);
        if (privkey) free(privkey);
        return {"", ""};
    }
    
   
    ret = ocall_generate_key_pair(&status, pubkey, &pubkey_len, privkey, &privkey_len);
    
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(pubkey);
        free(privkey);
        return {"", ""};
    }
    
  
    std::string pubkey_str(pubkey, pubkey_len);
    std::string privkey_str(privkey, privkey_len);
    

    free(pubkey);
    free(privkey);
    
    return {pubkey_str, privkey_str};
}

// 签名
std::string CryptoUtils::signWithPrivateKey(const std::string& data, const std::string& private_key) {
    size_t out_len = 0;
    

    sgx_status_t status;
    sgx_status_t ret = ocall_sign_data(&status, data.c_str(), data.length(), 
                                      private_key.c_str(), private_key.length(),
                                      nullptr, &out_len);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return "";
    }
    
 
    char* result = (char*)malloc(out_len);
    if (!result) return "";
    

    ret = ocall_sign_data(&status, data.c_str(), data.length(), 
                           private_key.c_str(), private_key.length(),
                           result, &out_len);
    
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(result);
        return "";
    }
    
    
    std::string signature(result, out_len);
    
    
    free(result);
    
    return signature;
}

// 验证签名
bool CryptoUtils::verifySignature(const std::string& data, const std::string& signature, const std::string& public_key) {
    int result = 0;
    sgx_status_t status;
    sgx_status_t ret = ocall_verify_signature(&status, &result, data.c_str(), data.length(),
                                      signature.c_str(), signature.length(),
                                      public_key.c_str(), public_key.length());
    
    return ret == SGX_SUCCESS && status == SGX_SUCCESS && result != 0;
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

// 生成随机数
std::string CryptoUtils::generateRandom(size_t len) {
    size_t out_len = 0;
    
  
    sgx_status_t status;
    sgx_status_t ret = ocall_generate_random(&status, len, nullptr, &out_len);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return "";
    }
    
  
    char* result = (char*)malloc(out_len);
    if (!result) return "";
    
  
    ret = ocall_generate_random(&status, len, result, &out_len);
    
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(result);
        return "";
    }
    
   
    std::string random_str(result, out_len);
    
    
    free(result);
    
    return random_str;
}

// AES加密
std::string CryptoUtils::aesEncrypt(const std::string& data, const std::string& key, const std::string& iv) {
    size_t out_len = 0;
    
    
    sgx_status_t status;
    sgx_status_t ret = ocall_aes_encrypt(&status, data.c_str(), data.length(),
                                         key.c_str(), key.length(),
                                         iv.c_str(), iv.length(),
                                         nullptr, &out_len);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return "";
    }
    
    char* result = (char*)malloc(out_len);
    if (!result) return "";
    
  
    ret = ocall_aes_encrypt(&status, data.c_str(), data.length(),
                             key.c_str(), key.length(),
                             iv.c_str(), iv.length(),
                             result, &out_len);
    
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(result);
        return "";
    }
    
  
    std::string encrypted(result, out_len);
    

    free(result);
    
    return encrypted;
}

// AES解密
std::string CryptoUtils::aesDecrypt(const std::string& data, const std::string& key, const std::string& iv) {
    size_t out_len = 0;
    
    
    sgx_status_t status;
    sgx_status_t ret = ocall_aes_decrypt(&status, data.c_str(), data.length(),
                                         key.c_str(), key.length(),
                                         iv.c_str(), iv.length(),
                                         nullptr, &out_len);
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        return "";
    }
    

    char* result = (char*)malloc(out_len);
    if (!result) return "";
    
    
    ret = ocall_aes_decrypt(&status, data.c_str(), data.length(),
                             key.c_str(), key.length(),
                             iv.c_str(), iv.length(),
                             result, &out_len);
    
    if (ret != SGX_SUCCESS || status != SGX_SUCCESS) {
        free(result);
        return "";
    }
    

    std::string decrypted(result, out_len);
    
    
    free(result);
    
    return decrypted;
}

namespace CryptoUtils {
    
    std::string generateRandomString(size_t length) {
        const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        const size_t charset_size = sizeof(charset) - 1;
        
        std::string result;
        result.resize(length);
        
       
        sgx_status_t ret = sgx_read_rand((unsigned char*)result.data(), length);
        
        if (ret != SGX_SUCCESS) {
         
            return "";
        }
        
  
        for (size_t i = 0; i < length; i++) {
            result[i] = charset[static_cast<unsigned char>(result[i]) % charset_size];
        }
        
        return result;
    }

    std::pair<size_t, std::string> xorPair(const std::pair<size_t, std::string>& p, const std::string& s) {
    
        size_t s_num = stringToSize(s);
        
        
        if (s_num == 0) s_num = 1;
        
       
        size_t new_first = p.first ^ s_num;
        
   
        std::string new_second = xorStrings(p.second, s);
        
        return {new_first, new_second};
    }
}