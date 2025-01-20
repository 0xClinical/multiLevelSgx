#include "core/token_generator.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <random>
#include <openssl/rand.h>
#include <chrono>
#include <nlohmann/json.hpp>

class TokenGenerator {
private:
    // 简化存储结构
    struct UserKeys {
        LevelKey levelKey;
        std::vector<std::string> stateKeys;  // 存储从初始到当前状态的所有密钥
        std::chrono::system_clock::time_point timestamp;
    };
    std::map<std::string, UserKeys> userKeys_;
    
    static const size_t TOTAL_STATE_KEYS = 30;

public:
    // 接收来自SGX的密钥
    bool receiveKeys(const std::string& request) {
        auto data = nlohmann::json::parse(request);
        
        UserKeys keys {
            LevelKey {
                data["levelKey"]["key1"],
                data["levelKey"]["key2"],
                data["levelKey"]["key3"],
                data["levelKey"]["key4"]
            },
            data["stateKeys"].get<std::vector<std::string>>(),  // 接收状态密钥数组
            std::chrono::system_clock::now()
        };
        
        userKeys_[data["userId"]] = keys;
        return true;
    }
    
    // 处理用户的token请求
    SearchToken handleTokenRequest(const std::string& userId, 
                                 const std::string& blindedKeyword) {
        // 1. 检查是否有该用户的密钥
        auto it = userKeys_.find(userId);
        if (it == userKeys_.end()) {
            return SearchToken();  // 返回空token
        }
        
        // 2. 检查密钥是否过期（例如15分钟）
        auto now = std::chrono::system_clock::now();
        if (now - it->second.timestamp > std::chrono::minutes(15)) {
            userKeys_.erase(it);
            return SearchToken();
        }
        
        // 4. 生成搜索token
        return generateToken(
            blindedKeyword,
            it->second.levelKey,
            it->second.stateKeys
        );
    }

    SearchToken TokenGenerator::generateToken(
        const Keyword& keyword,
        const LevelKey& levelKey,
        const std::vector<StateKey>& stateKeys) {
        
        SearchToken token;
        
        // 1. 生成tau1 - 用于解密第一个节点
        token.tau1 = CryptoUtils::H1(levelKey.key2, keyword);
        
        // 2. 生成tau2 - 用于定位查找表条目
        token.tau2 = CryptoUtils::H4(levelKey.key3, keyword);
        
        // 3. 生成tau3 - 用于解密起始节点位置
        token.tau3 = CryptoUtils::H5(levelKey.key4, keyword);
        
        // 4. 生成tau4 - 状态密钥哈希值集合
        // 首先添加所有已有状态的密钥哈希值
        for (const auto& stateKey : stateKeys) {
            token.tau4.push_back(CryptoUtils::H3(stateKey, keyword));
        }
        
        // 添加随机填充，直到达到总数TOTAL_STATE_KEYS
        size_t paddingCount = TOTAL_STATE_KEYS - stateKeys.size();
        auto paddingKeys = generatePaddingStateKeys(paddingCount);
        for (const auto& key : paddingKeys) {
            token.tau4.push_back(CryptoUtils::H3(key, keyword));
        }
        
        // 随机打乱tau4
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(token.tau4.begin(), token.tau4.end(), gen);
        
        return token;
    }

    std::vector<std::string> TokenGenerator::generatePaddingStateKeys(size_t count) const {
        std::vector<std::string> paddingKeys;
        for (size_t i = 0; i < count; i++) {
            paddingKeys.push_back(CryptoUtils::generateRandomString());
        }
        return paddingKeys;
    }

};