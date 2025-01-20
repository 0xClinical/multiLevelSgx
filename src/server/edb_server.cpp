#include "server/edb_server.h"


EDBServer::EDBServer(int port) : port_(port) {
    edb_ = std::make_unique<EDBController>();
    setupRoutes();
}
    
void EDBServer::start() {
    std::cout << "EDB Server starting on port " << port_ << std::endl;
    server_.listen("localhost", port_);
}

void EDBServer::setupRoutes() {
    // 获取关键字数据
    server_.Get("/get-keyword-data/:keyword", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                auto keyword = req.path_params.at("keyword");
                auto data = edb_->getKeywordData(keyword);
                
                nlohmann::json response = {
                    {"encryptedIndex", data.encryptedIndex},
                    {"lookupTable", data.lookupTable},
                    {"encryptedDocs", data.docs}
                };
                
                res.set_content(response.dump(), "application/json");
                res.status = 200;
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
        });

        // 更新索引
        server_.Post("/update-index", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                auto json = nlohmann::json::parse(req.body);
                Keyword keyword = json["keyword"];
                std::vector<IndexNode> newNodes = json["newNodes"];
                LookupTable newTable = json["lookupTable"];
                std::vector<EncryptedDocument> newEncryptedDocs = json["encryptedDocs"];
                
                edb_->updateIndex(keyword, newNodes, newTable, newEncryptedDocs);
                res.status = 200;
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
        });

        // 搜索
        server_.Post("/search", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                auto json = nlohmann::json::parse(req.body);
                auto token = json["token"].get<SearchToken>();
                
                auto results = edb_->search(token);
                
                nlohmann::json response = {
                    {"results", results}
                };
                
                res.set_content(response.dump(), "application/json");
                res.status = 200;
            } catch (const std::exception& e) {
                res.status = 500;
                res.set_content(e.what(), "text/plain");
            }
    });
}

int main() {
    EDBServer server(8080);
    server.start();
    return 0;
} 