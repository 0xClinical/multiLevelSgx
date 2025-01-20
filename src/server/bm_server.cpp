#include "server/bm_server.h"

BMServer::BMServer(int port) : port_(port) {
    bm_ = std::make_unique<BMScheme>("http://localhost:8081", "http://localhost:8082");
    setupRoutes();
}

void BMServer::start() {
    std::cout << "BM Server starting on port " << port_ << std::endl;
    server_.listen("localhost", port_);
}

void BMServer::setupRoutes() {
    // 更新密钥
    server_.Post("/update-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            OwnerSecretKey KO{
                json["levelKeys"].get<std::map<AccessLevel, LevelKey>>(),
                json["stateKeys"].get<std::map<State, StateKey>>(),
                json["encapsulationKey"].get<std::string>()
            };
            bm_->updateKeys(KO);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 上传单个文档
    server_.Post("/upload-document", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            Document doc = json.get<Document>();
            bm_->uploadDocument(doc);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 批量上传文档
    server_.Post("/upload-documents", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::vector<Document> docs = json.get<std::vector<Document>>();
            bm_->uploadDocuments(docs);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 删除文档
    server_.Delete("/delete-document", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            Document doc = json.get<Document>();
            bm_->deleteDocument(doc);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 批量删除文档
    server_.Delete("/delete-documents", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::vector<Document> docs = json.get<std::vector<Document>>();
            bm_->deleteDocuments(docs);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 重建所有索引
    server_.Post("/rebuild-indices", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            bm_->rebuildAllIndices();
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 验证和转发密钥
    server_.Post("/verify-forward-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string userId = json["userId"];
            std::string encryptedId = json["encryptedId"];
            
            bool success = bm_->verifyAndForwardKeys(userId, encryptedId);
            res.status = success ? 200 : 400;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 解密搜索结果
    server_.Post("/decrypt-search-results", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            auto results = bm_->decryptSearchResults(
                json["userId"],
                json["encryptedUserId"],
                json["encryptedKeyword"],
                json["searchResults"].get<std::vector<std::pair<std::string, std::string>>>()
            );
            
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
    BMServer server(8083);  // 使用不同的端口
    server.start();
    return 0;
} 