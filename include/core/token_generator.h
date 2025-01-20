#pragma once
#include "utils/types.h"
#include "utils/crypto.h"


class TokenGenerator {
private:
    // 存储用户密钥信息
    struct UserKeys {
        LevelKey levelKey;
        std::string stateKey;
        std::chrono::system_clock::time_point timestamp;
    };
    std::map<std::string, UserKeys> userKeys_;
    static const size_t TOTAL_STATE_KEYS = 10;

public:
    TokenGenerator() = default;
    
    // 接收来自SGX的密钥
    bool receiveKeys(const std::string& request);
    
    // 处理用户的token请求
    SearchToken handleTokenRequest(const std::string& userId, 
                                 const std::string& blindedKeyword);

private:
    // 生成token的内部实现
    SearchToken generateToken(
        const Keyword& keyword,
        const LevelKey& levelKey,
        const std::vector<StateKey>& stateKeys);
};
