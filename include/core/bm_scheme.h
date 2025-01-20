#pragma once
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <mutex>
#include "utils/types.h"
#include "utils/crypto.h"
#include "core/cluster.h"
#include "core/padding_dataset.h"
#include "utils/timer.h"
class BMScheme {
public:
    // 构造函数
    BMScheme(const std::string& token_url,
             const std::string& server_url)
        : token_url_(token_url)
        , server_url_(server_url) {
            std::cout << "Initializing BM Scheme..." << std::endl;
        }
    
    // 更新层级密钥表
    void updateLevelKeys(const std::map<AccessLevel, LevelKey>& levelKeys) {
        levelKeys_ = levelKeys;
    }
    // 更新状态密钥表
    void updateStateKeys(const std::map<State, StateKey>& stateKeys) {
        stateKeys_ = stateKeys;
    }
    // 更新封装密钥
    void updateEncapsulationKey(const std::string& key) {
        encapsulationKey_ = key;
    }
    
    // 更新用户表
    void updateUserTable(const std::map<std::string, User>& users) {
        userTable_ = users;
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
    std::pair<EncryptedIndex, LookupTable> 
    buildIndex(const std::map<Keyword, std::vector<Document>>& keywordMap);
    
    // 搜索和索引
    std::vector<std::string> decryptSearchResults(
        const std::string& userId,
        const std::string& encryptedUserId,
        const std::string& encryptedKeyword,
        const std::vector<std::pair<std::string, std::string>>& searchResults);
    
    void updateKeys(const OwnerSecretKey& KO) {
        levelKeys_ = KO.levelKeys;
        stateKeys_ = KO.stateKeys;
        encapsulationKey_ = KO.encapsulationKey;
    }
    //验证和转发密钥
    bool verifyAndForwardKeys(const std::string& userId, const std::string& encryptedId);
    //上传文档
    virtual void uploadDocument(const Document& doc);
    //批量上传文档
    virtual void uploadDocuments(const std::vector<Document>& docs);
    //删除文档
    void deleteDocument(const Document& doc);
    //批量删除文档
    void deleteDocuments(const std::vector<Document>& docs);
    //重建所有索引
    void rebuildAllIndices();

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
    
protected:
    std::string token_url_;
    std::string server_url_;
    // 内部数据
    std::map<std::string, User> userTable_;              // 用户表
    std::map<AccessLevel, LevelKey> levelKeys_;       // 层级密钥表
    std::map<State, StateKey> stateKeys_;            // 状态密钥表
    std::string encapsulationKey_;                      // 封装密钥，实际需使用sgx环境的封装密钥确保安全
   // 缓存结构：关键字 -> 文档列表
    std::map<Keyword, std::vector<Document>> documentBatch_;
    static const size_t BATCH_THRESHOLD = 100;  // 批处理阈值
    

    // 内部常量
    static constexpr size_t REBUILD_THRESHOLD = 1000;   // 重建索引阈值
    static constexpr size_t BATCH_SIZE = 1000;  // 批处理阈值
    
    // 内部辅助方法
    bool forwardKeysToGenerator(const std::string& userId, 
                                      const LevelKey& levelKey,
                                      const std::vector<std::string>& stateKeys);
    
    EncryptedDocument encryptDocument(const Document& doc);
    Document decryptDocument(const EncryptedDocument& encryptedDoc);
    // 序列化和反序列化方法
    /*void serialize_tables();
    void deserialize_tables();
    
    // 加密密钥
    sgx_aes_gcm_128bit_key_t sealing_key_;*/

    // 定时器相关
    void startStateKeyTimer();
    void updateStateKey();
    
    std::unique_ptr<Timer> stateKeyTimer_;
    int stateKeyUpdateInterval_{60};  // 默认60分钟更新一次
    State currentState_{0};           // 当前状态
};
