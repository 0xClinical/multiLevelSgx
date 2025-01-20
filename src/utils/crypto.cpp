#include "utils/crypto.h"
#include <openssl/aes.h>

std::string CryptoUtils::H1(const std::string& key, const std::string& input) {
    return computeAES(key, input, "H1");
}

std::string CryptoUtils::H2(const std::string& key, const std::string& r) {
    return computeAES(key, r, "H2");
}

std::string CryptoUtils::H3(const std::string& stateKey, const std::string& keyword) {
    return computeAES(stateKey, keyword, "H3");
}

std::string CryptoUtils::H4(const std::string& key, const std::string& input) {
    return computeAES(key, input, "H4");
}

std::string CryptoUtils::H5(const std::string& key, const std::string& input) {
    return computeAES(key, input, "H5");
}

std::string CryptoUtils::F1(const std::string& key, const std::string& id) {
    return computeAES(key, id, "F1");
}

std::string CryptoUtils::F1_inverse(const std::string& key, const std::string& encrypted_id) {
    return computeAES_decrypt(key, encrypted_id, "F1");
}

std::string CryptoUtils::F2(const std::string& key, int level) {
    return computeAES(key, std::to_string(level), "F2");
}

std::string CryptoUtils::F2_inverse(const std::string& key, const std::string& encrypted_level) {
    return computeAES_decrypt(key, encrypted_level, "F2");
}

std::string CryptoUtils::generateRandomString(size_t length) {
    unsigned char buf[length];
    if (RAND_bytes(buf, length) != 1) {
        throw std::runtime_error("Failed to generate random string");
    }
    return std::string(reinterpret_cast<char*>(buf), length);
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
    std::string result = a;
    for (size_t i = 0; i < result.length(); i++) {
        result[i] ^= b[i % b.length()];
    }
    return result;
}

std::pair<size_t, std::string> CryptoUtils::xorPair(
    const std::pair<size_t, std::string>& a,
    const std::string& b) {
    // 将size_t转换为string进行异或
    std::string first = std::to_string(a.first);
    std::string xored_first = xorStrings(first, b);
    size_t new_first = std::stoull(xored_first);
    
    // 异或第二个元素
    std::string new_second = xorStrings(a.second, b);
    
    return {new_first, new_second};
}

std::string CryptoUtils::computeDigest(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
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
    unsigned char output[16];
    AES_KEY aes_key;
    
    // 填充密钥到32字节
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    // 准备输入（添加前缀并填充到16字节）
    std::string padded_input = prefix + input;
    padded_input.resize(16, 0);
    
    // 加密
    AES_set_encrypt_key((unsigned char*)padded_key.c_str(), 256, &aes_key);
    AES_encrypt((unsigned char*)padded_input.c_str(), output, &aes_key);
    
    return std::string((char*)output, 16);
}

// AES 解密实现
std::string CryptoUtils::computeAES_decrypt(const std::string& key, 
                                          const std::string& encrypted_input,
                                          const std::string& prefix) {
    unsigned char output[16];
    AES_KEY aes_key;
    
    // 填充密钥到32字节
    std::string padded_key = key;
    padded_key.resize(32, 0);
    
    // 解密
    AES_set_decrypt_key((unsigned char*)padded_key.c_str(), 256, &aes_key);
    AES_decrypt((unsigned char*)encrypted_input.c_str(), output, &aes_key);
    
    // 移除前缀和填充
    std::string decrypted((char*)output, 16);
    decrypted = decrypted.substr(prefix.length());
    decrypted = decrypted.substr(0, decrypted.find('\0'));
    
    return decrypted;
}

// 使用公钥加密
std::string CryptoUtils::encryptWithPrivateKey(const std::string& data, const std::string& private_key) {
    std::string encrypted;
    
    // 从PEM创建公钥
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(private_key.c_str(), -1);
    if (!bio) return "";
    
    pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) return "";
    
    // 创建加密上下文
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 初始化加密
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 确定输出长度
    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, 
        reinterpret_cast<const unsigned char*>(data.c_str()), 
        data.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 执行加密
    unsigned char* out = (unsigned char*)OPENSSL_malloc(outlen);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_PKEY_encrypt(ctx, out, &outlen,
        reinterpret_cast<const unsigned char*>(data.c_str()),
        data.length()) <= 0) {
        OPENSSL_free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // Base64编码结果
    encrypted = base64Encode(std::string(
        reinterpret_cast<char*>(out), 
        outlen
    ));
    
    OPENSSL_free(out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return encrypted;
}

// 使用私钥解密
std::string CryptoUtils::decryptWithPublicKey(const std::string& encrypted_data, const std::string& public_key) {
    // Base64解码
    std::string decoded = base64Decode(encrypted_data);
    
    // 从PEM创建私钥
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(public_key.c_str(), -1);
    if (!bio) return "";
    
    pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!pkey) return "";
    
    // 创建解密上下文
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 初始化解密
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 确定输出长度
    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen,
        reinterpret_cast<const unsigned char*>(decoded.c_str()),
        decoded.length()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // 执行解密
    unsigned char* out = (unsigned char*)OPENSSL_malloc(outlen);
    if (!out) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    if (EVP_PKEY_decrypt(ctx, out, &outlen,
        reinterpret_cast<const unsigned char*>(decoded.c_str()),
        decoded.length()) <= 0) {
        OPENSSL_free(out);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return "";
    }
    
    std::string decrypted(reinterpret_cast<char*>(out), outlen);
    
    OPENSSL_free(out);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    return decrypted;
}

std::string CryptoUtils::base64Encode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input.c_str(), input.length());
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string output(bptr->data, bptr->length - 1);  // -1 to remove newline
    
    BIO_free_all(b64);
    return output;
}

std::string CryptoUtils::base64Decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(input.c_str(), input.length());
    bmem = BIO_push(b64, bmem);
    
    std::vector<char> buffer(input.length());
    int decoded_size = BIO_read(bmem, buffer.data(), input.length());
    BIO_free_all(b64);
    
    return std::string(buffer.data(), decoded_size);
}