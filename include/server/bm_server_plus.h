#pragma once

#include <memory>
#include <string>
#include <vector>
#include <map>
#include "../httplib.h"
#include "sgx_urts.h"

// 不再使用前向声明，直接包含完整头文件
#include <nlohmann/json.hpp>

class BMServerPlus {
public:
    // 构造函数，指定服务器端口和 SGX 封装 ID
    explicit BMServerPlus(int port, sgx_enclave_id_t eid);
    
    // 启动服务器
    void start();
    
    // 禁止拷贝和赋值
    BMServerPlus(const BMServerPlus&) = delete;
    BMServerPlus& operator=(const BMServerPlus&) = delete;
    
    // 析构函数
    ~BMServerPlus() = default;

private:
    // 设置路由规则
    void setupRoutes();
    
    // 初始化 BM++ 方案
    bool initializeBMPlusScheme();
    
    // 初始化簇
    bool initializeClusters();

private:
    httplib::Server server_;      // HTTP 服务器
    int port_;                    // 服务器端口
    sgx_enclave_id_t enclaveId_;  // SGX 封装 ID
    bool initialized_{false};     // 初始化状态
}; 