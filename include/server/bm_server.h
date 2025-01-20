#pragma once

#include <memory>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "core/bm_scheme.h"

class BMServer {
public:
    // 构造函数
    explicit BMServer(int port);
    
    // 启动服务器
    void start();
    
    // 禁用拷贝
    BMServer(const BMServer&) = delete;
    BMServer& operator=(const BMServer&) = delete;

private:
    // 设置路由
    void setupRoutes();

private:
    httplib::Server server_;
    int port_;
    std::unique_ptr<BMScheme> bm_;
}; 