 #pragma once
#include <memory>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "core/bm_scheme_plus.h"

class BMServerPlus {
public:
    // 构造函数
    explicit BMServerPlus(int port);
    
    // 启动服务器
    void start();
    
    // 禁用拷贝
    BMServerPlus(const BMServerPlus&) = delete;
    BMServerPlus& operator=(const BMServerPlus&) = delete;

private:
    // 设置路由
    void setupRoutes();

private:
    httplib::Server server_;
    int port_;
    std::unique_ptr<BMSchemePlus> bm_plus_;
}; 