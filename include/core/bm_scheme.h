#pragma once
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <mutex>
#include <iostream>
#include "utils/types.h"
#include "core/cluster.h"
#include "utils/timer.h"
#include "enclave/crypto_sgx.h"
#include "enclave/enclave_edb_controller.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <bitset>
#ifdef SGX_ENCLAVE
#include "Enclave_t.h"
#endif



class BMScheme {
public:
    // 构造函数
    BMScheme() :  edb_controller() {
    }
    
    // 更新层级密钥表
    void updateLevelKeys(const std::map<AccessLevel, LevelKey>& levelKeys) {
        for (const auto& pair : levelKeys) {
            const auto& level = pair.first;
            const auto& key = pair.second;
            levelKeys_[level] = key;
        }
    }
    // 更新状态密钥表
    void updateStateKeys(const std::map<State, StateKey>& stateKeys) {
        for (const auto& pair : stateKeys) {
            const auto& state = pair.first;
            const auto& key = pair.second;
            stateKeys_[state] = key;
        }
    }
    // 更新封装密钥
    void updateEncapsulationKey(const std::string& key) {
        encapsulationKey_ = key;
    }
    
    // 更新用户表
    void updateUserTable(const std::map<std::string, User>& users) {
        for (const auto& pair : users) {
            const auto& id = pair.first;
            const auto& user = pair.second;
            userTable_[id] = user;
        }
    }
    //更新用户信息
    void updateUser(const User& user) {
        userTable_[user.id] = user;
    }
    //添加用户
    void addUser(const User& user) {
        userTable_[user.id] = user;
    }
    //删除用户
    void deleteUser(const std::string& userId) {
        userTable_.erase(userId);
    }
    // 索引构建
    std::pair<std::vector<IndexNode>, LookupTable> 
    buildIndex(const Keyword keyword_hash, const std::vector<Document>& docs);
    
    //使用token进行搜索
    virtual std::vector<std::string> searchWithToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword, const SearchToken& token, size_t max_doc = 0); 
    // 搜索和索引
    std::vector<std::string> decryptSearchResults(
        const std::vector<std::pair<std::string, std::string>>& searchResults);
    
    void updateKeys(const OwnerSecretKey& KO) {
        updateLevelKeys(KO.levelKeys);
        updateStateKeys(KO.stateKeys);
        updateEncapsulationKey(KO.encapsulationKey);
        currentState_ = KO.stateKeys.rbegin()->first;
    }
    //获取搜索令牌
    SearchToken getSearchToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword);
    //上传文档
    virtual void uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs);
    //批量上传文档
    virtual void uploadDocument(const Keyword& keyword, const Document& doc);
    //删除文档
    virtual void deleteDocument(const Keyword& keyword, DocumentId docId);
    //批量删除文档
    virtual void deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs);
    //重建所有索引
    virtual void rebuildAllIndices();

    // 如果基类会被继承，最好也加上虚析构函数
    virtual ~BMScheme() = default;

    // 添加定时更新状态密钥的函数
    void startStateKeyUpdateTimer(int intervalMinutes = 60) {
        stateKeyUpdateInterval_ = intervalMinutes;
        startStateKeyTimer();
    }
    
    // 停止定时器
    void stopStateKeyUpdateTimer() {
        if (stateKeyTimer_) {
            stateKeyTimer_->stop();
        }
    }

protected:
    void rebuildIndexForKeyword(const Keyword& keyword, const std::vector<Document>& docs);    
    // 内部数据
    std::map<std::string, User> userTable_;              // 用户表
    std::map<AccessLevel, LevelKey> levelKeys_;       // 层级密钥表
    std::map<State, StateKey> stateKeys_;            // 状态密钥表
    std::string encapsulationKey_;                      // 封装密钥，实际需使用sgx环境的封装密钥确保安全
   // 缓存结构：关键字 -> 文档列表
    std::map<Keyword, std::vector<Document>> documentBatch_;

    // 生成token的内部实现
    SearchToken generateToken(
        const Keyword& keyword,
        const LevelKey& levelKey,
        const std::vector<StateKey>& stateKeys);
    // 生成填充密钥
    std::vector<std::string> generatePaddingStateKeys(size_t count) const;

    // 使用SGX随机数生成器打乱vector
    void shuffleTau4(std::vector<std::string>& vec);

    // 内部常量
    static constexpr size_t REBUILD_THRESHOLD = 1000;   // 重建索引阈值
    static constexpr size_t BATCH_SIZE = 1000;  // 批处理阈值
    
   
    EncryptedDocument encryptDocument(const Document& doc);
    Document decryptDocument(const EncryptedDocument& encryptedDoc);
    
    EnclaveEDBController edb_controller;
  

    // 定时器相关
    void startStateKeyTimer();
    void updateStateKey();
    
    std::unique_ptr<Timer> stateKeyTimer_;
    int stateKeyUpdateInterval_{60};  // 默认60分钟更新一次
    State currentState_{0};           // 当前状态
};
