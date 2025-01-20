#pragma once

#include <memory>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "core/token_generator.h"

class TokenServer {
public:
    // 构造函数
    explicit TokenServer(int port);
    
    // 启动服务器
    void start();
    
    // 禁用拷贝
    TokenServer(const TokenServer&) = delete;
    TokenServer& operator=(const TokenServer&) = delete;

private:
    // 设置路由
    void setupRoutes();

private:
    httplib::Server server_;
    int port_;
    std::unique_ptr<TokenGenerator> tokenGen_;
}; 