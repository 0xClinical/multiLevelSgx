#include "server/bm_server.h"
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>
#include <string>
#include <stdexcept>

// 创建 SGX 封装
sgx_enclave_id_t create_enclave() {
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = {0};

    // 创建封装
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &launch_token, 
                            &launch_token_updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave: " << std::hex << ret << std::endl;
        throw std::runtime_error("Enclave creation failed");
    }

    std::cout << "Enclave created successfully, ID: " << eid << std::endl;
    return eid;
}

int main(int argc, char* argv[]) {
    try {
        // 默认端口
        int port = 8080;
        
        // 解析命令行参数
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--port" && i + 1 < argc) {
                try {
                    port = std::stoi(argv[++i]);
                    if (port <= 0 || port > 65535) {
                        std::cerr << "Error: Port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error: Invalid port number" << std::endl;
                    return 1;
                }
            } else if (arg == "--help") {
                std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
                std::cout << "Options:" << std::endl;
                std::cout << "  --port PORT     Specify server port (default: 8080)" << std::endl;
                std::cout << "  --help          Display this help message" << std::endl;
                return 0;
            }
        }
        
        // 创建 SGX 封装
        std::cout << "\n*** Creating SGX Enclave ***" << std::endl;
        sgx_enclave_id_t eid = create_enclave();
        
        // 创建并启动服务器
        std::cout << "\n*** Starting BM Search Server ***" << std::endl;
        BMServer server(port, eid);
        std::cout << "Server initialized, starting on port " << port << std::endl;
        server.start();
        
        // 销毁封装
        sgx_destroy_enclave(eid);
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}