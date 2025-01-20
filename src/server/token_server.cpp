#include "server/token_server.h"

TokenServer::TokenServer(int port) : port_(port) {
    tokenGen_ = std::make_unique<TokenGenerator>();
    setupRoutes();
}

void TokenServer::start() {
    std::cout << "Token Server starting on port " << port_ << std::endl;
    server_.listen("localhost", port_);
}

void TokenServer::setupRoutes() {
    // 接收密钥
    server_.Post("/receive-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            bool success = tokenGen_->receiveKeys(json.dump());
            
            res.status = success ? 200 : 400;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 处理token请求
    server_.Post("/handle-token", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string userId = json["userId"];
            std::string blindedKeyword = json["blindedKeyword"];
            
            auto token = tokenGen_->handleTokenRequest(userId, blindedKeyword);
            
            nlohmann::json response = token;  // 使用之前定义的序列化
            res.set_content(response.dump(), "application/json");
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}

int main() {
    TokenServer server(8081);  // 使用不同的端口
    server.start();
    return 0;
} 