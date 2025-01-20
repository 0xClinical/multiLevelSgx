#pragma once
#include "utils/types.h"
#include <memory>
#include <random>
#include "core/padding_dataset.h"
#include "core/cluster.h"
#include "core/bm_scheme.h"
#include "core/bm_scheme_plus.h"


class DataOwner {
public:
    DataOwner(const std::string& sgx_url,
             const std::string& token_url,
             const std::string& server_url)
             : sgx_url_(sgx_url)
             , token_url_(token_url)
             , server_url_(server_url) {}
    
    // 用户管理
    void addAuthorizedUser(const std::string& userId, 
                          AccessLevel level,
                          State state);
    void revokeUser(const std::string& userId);
    
    // 密钥管理
    void generateKeys(size_t numLevels, size_t numStates);
    void updateKeys();
    
    // 文档管理
    void addDocument(const Document& doc);
    void addDocuments(const std::vector<Document>& docs);
    void deleteDocument(const Document& doc);
    void deleteDocuments(const std::vector<Document>& docs);
    void requestRebuildIndices();
    
    // 获取密钥
    std::string getLevelKey(int level) const;
    std::string getStateKey(int stateId) const;
    std::string getEncapsulationKey() const;
    
    // 上传数据到SGX Enclave
    void uploadToEnclave();

private:
    std::string sgx_url_;
    std::string token_url_;
    std::string server_url_;
    std::vector<Document> documents_;
    std::map<std::string, User> authorizedUsers_;
    std::map<AccessLevel, std::string> levelKeys_;
    std::map<State, std::string> stateKeys_;
    std::string encapsulationKey_;
    
    // 生成随机密钥
    std::string generateRandomKey(size_t length = 32) const;
    void uploadKeysToEnclave();
    void distributePrivateKey(const std::string& userId, const std::string& privateKey);
};
