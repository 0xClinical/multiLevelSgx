#include "core/data_owner.h"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <httplib.h>
#include <nlohmann/json.hpp>



void DataOwner::addDocument(const Document& doc) {
    // 1. 保存到本地
    documents_.push_back(doc);
    
    // 2. 向SGX发送上传请求
    httplib::Client cli(sgx_url_);
    
    nlohmann::json requestData = {
        {"document", {
            {"id", doc.id},
            {"level", doc.level},
            {"keywords", doc.keywords},
            {"state", doc.state}
        }}
    };
    
    auto res = cli.Post("/upload-document", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to upload document to SGX");
    }
    
    std::cout << "Added document with ID: " << doc.id << std::endl;
}

void DataOwner::addDocuments(const std::vector<Document>& docs) {
    // 1. 保存到本地
    documents_.insert(documents_.end(), docs.begin(), docs.end());
    
    // 2. 向SGX发送批量上传请求
    httplib::Client cli(sgx_url_);
    
    nlohmann::json docsArray = nlohmann::json::array();
    for (const auto& doc : docs) {
        docsArray.push_back({
            {"id", doc.id},
            {"level", doc.level},
            {"keywords", doc.keywords},
            {"state", doc.state}
        });
    }
    
    nlohmann::json requestData = {
        {"documents", docsArray}
    };
    
    auto res = cli.Post("/upload-documents", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to upload documents to SGX");
    }
    
    std::cout << "Added " << docs.size() << " documents" << std::endl;
}

void DataOwner::requestRebuildIndices() {
    // 向SGX发送重建索引请求
    httplib::Client cli(sgx_url_);
    
    auto res = cli.Post("/rebuild-indices");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to rebuild indices");
    }
    
    std::cout << "Indices rebuilt successfully" << std::endl;
}


void DataOwner::deleteDocument(const Document& doc) {
    // 1. 从本地删除
    documents_.erase(
        std::remove_if(documents_.begin(), documents_.end(),
            [docId = doc.id](const Document& d) { return d.id == docId; }),
        documents_.end()
    );
    
    // 2. 向SGX发送删除请求
    httplib::Client cli(sgx_url_);
    
    nlohmann::json requestData = {
        {"document", {
            {"id", doc.id},
            {"level", doc.level},
            {"keywords", doc.keywords},
            {"state", doc.state}
        }}
    };
    
    auto res = cli.Post("/delete-document", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to delete document from SGX");
    }
    
    std::cout << "Deleted document with ID: " << doc.id << std::endl;
}

void DataOwner::deleteDocuments(const std::vector<Document>& docs) {
    // 1. 从本地批量删除
    for (const auto& doc : docs) {
        documents_.erase(
            std::remove_if(documents_.begin(), documents_.end(),
                [docId = doc.id](const Document& d) { return d.id == docId; }),
            documents_.end()
        );
    }
    
    // 2. 向SGX发送批量删除请求
    httplib::Client cli(sgx_url_);
    
    nlohmann::json docsArray = nlohmann::json::array();
    for (const auto& doc : docs) {
        docsArray.push_back({
            {"id", doc.id},
            {"level", doc.level},
            {"keywords", doc.keywords},
            {"state", doc.state}
        });
    }
    
    nlohmann::json requestData = {
        {"documents", docsArray}
    };
    
    auto res = cli.Post("/delete-documents", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to delete documents from SGX");
    }
    
    std::cout << "Deleted " << docs.size() << " documents" << std::endl;
}


void DataOwner::generateKeys(size_t numLevels, size_t numStates) {
    // 1. 生成层级密钥 kl ∈ {0, 1}κ
    for (size_t l = 1; l <= numLevels; l++) {
        levelKeys_[l] = generateRandomKey();  // κ bits random key
    }
    
    // 2. 生成状态密钥 sti ∈ {0, 1}κ
    for (size_t i = 1; i <= numStates; i++) {
        stateKeys_[i] = generateRandomKey();  // κ bits random key
    }
    
    // 3. 生成状态封装密钥 ko ∈ {0, 1}κ
    encapsulationKey_ = generateRandomKey();  // κ bits random key
    
    // 4. 上传密钥到SGX Enclave
    uploadKeysToEnclave();
    
    std::cout << "Generated " << numLevels << " level keys, " 
              << numStates << " state keys, "
              << "and 1 encapsulation key" << std::endl;
}

void DataOwner::uploadKeysToEnclave() {
    // 准备密钥数据
    nlohmann::json keyData = {
        {"keys", {
            {"levelKeys", levelKeys_},
            {"stateKeys", stateKeys_},
            {"encapsulationKey", encapsulationKey_}
        }}
    };
    
    // 发送更新密钥请求到SGX
    httplib::Client cli(sgx_url_);
    
    auto res = cli.Post("/update-keys", 
                       keyData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to upload keys to SGX Enclave");
    }
    
    std::cout << "Keys uploaded to SGX Enclave" << std::endl;
}

std::string DataOwner::generateRandomKey(size_t length) const {
    unsigned char key[length];
    if (RAND_bytes(key, length) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    
    // 转换为十六进制字符串
    std::string hexKey;
    for (size_t i = 0; i < length; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", key[i]);
        hexKey += hex;
    }
    return hexKey;
}

std::string DataOwner::getLevelKey(int level) const {
    auto it = levelKeys_.find(level);
    return (it != levelKeys_.end()) ? it->second : "";
}

std::string DataOwner::getStateKey(int stateId) const {
    auto it = stateKeys_.find(stateId);
    return (it != stateKeys_.end()) ? it->second : "";
}

std::string DataOwner::getEncapsulationKey() const {
    return encapsulationKey_;
}

//添加用户
void DataOwner::addAuthorizedUser(const std::string& userId, 
                                 AccessLevel level,
                                 State state) {
    // 1. 生成用户密钥对
    auto [publicKey, privateKey] = CryptoUtils::generateKeyPair();
    
    // 2. 创建用户
    User newUser;
    newUser.id = userId;
    newUser.level = level;
    newUser.state = state;
    newUser.publicKey = publicKey;
    
    // 3. 向SGX发送添加用户请求
    httplib::Client cli(sgx_url_);
    
    nlohmann::json requestData = {
        {"user", {
            {"id", newUser.id},
            {"level", newUser.level},
            {"state", newUser.state},
            {"publicKey", newUser.publicKey}
        }}
    };
    
    auto res = cli.Post("/add-user", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to add user to SGX Enclave");
    }
    
    // 4. 保存到本地
    authorizedUsers_[userId] = newUser;
    
    // 5. 分发私钥给用户（实际应用中需要安全传输）
    distributePrivateKey(userId, privateKey);
}

//撤销用户
void DataOwner::revokeUser(const std::string& userId) {
    // 1. 向SGX发送删除用户请求
    httplib::Client cli(sgx_url_);  // SGX服务器地址
    
    nlohmann::json requestData = {
        {"userId", userId}
    };
    
    auto res = cli.Post("/delete-user", 
                       requestData.dump(), 
                       "application/json");
                       
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to revoke user from SGX");
    }
    
    // 2. 从本地删除
    authorizedUsers_.erase(userId);
}

void DataOwner::distributePrivateKey(const std::string& userId, const std::string& privateKey) {
    // TODO: 实现安全的密钥分发
    std::cout << "Distributing private key to user: " << userId << std::endl;
}
