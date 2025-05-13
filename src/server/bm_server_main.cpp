#include "server/bm_server.h"
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        // 默认端口
        int port = 8080;
        
        // 解析命令行参数
        if (argc > 2 && std::string(argv[1]) == "--port") {
            port = std::stoi(argv[2]);
        }
        
        // 创建并启动服务器
        BMServer server(port);
        std::cout << "SGX Server starting on port " << port << std::endl;
        server.start();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}