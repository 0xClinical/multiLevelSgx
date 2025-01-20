#pragma once

#include <memory>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "core/edb_controller.h"

class EDBServer {
public:
    // 构造函数
    explicit EDBServer(int port);
    
    // 启动服务器
    void start();
    
    // 禁用拷贝
    EDBServer(const EDBServer&) = delete;
    EDBServer& operator=(const EDBServer&) = delete;

private:
    // 设置路由
    void setupRoutes();

private:
    httplib::Server server_;
    int port_;
    std::unique_ptr<EDBController> edb_;
};
