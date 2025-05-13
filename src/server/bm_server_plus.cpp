#include "server/bm_server_plus.h"

BMServerPlus::BMServerPlus(int port) : port_(port) {
    bm_plus_ = std::make_unique<BMSchemePlus>();
    
    setupRoutes();
}

void BMServerPlus::start() {
    std::cout << "BM Server Plus starting on port " << port_ << std::endl;
    bm_plus_->startStateKeyUpdateTimer(1);
    bm_plus_->getCacheController().startRefreshTimer(1);
    server_.listen("localhost", port_);
}

void BMServerPlus::setupRoutes() {
    // 更新密钥
    server_.Post("/update-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            OwnerSecretKey KO{
                json["levelKeys"].get<std::map<AccessLevel, LevelKey>>(),
                json["stateKeys"].get<std::map<State, StateKey>>(),
                json["encapsulationKey"].get<std::string>()
            };
            bm_plus_->updateKeys(KO);
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
            // 解析关键词-文档对
            auto keyword = json["keyword"].get<std::string>();
            auto doc = json["document"].get<Document>();
            bm_plus_->uploadDocument(keyword, doc);
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
            std::vector<std::pair<Keyword, Document>> pairs;
            // 解析关键词-文档对数组
            for (const auto& item : json) {
                pairs.emplace_back(
                    item["keyword"].get<std::string>(),
                    item["document"].get<Document>()
                );
            }
            bm_plus_->uploadDocuments(pairs);
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
            // 解析关键词和文档ID
            auto keyword = json["keyword"].get<std::string>();
            auto doc_id = json["document_id"].get<std::string>();
            bm_plus_->deleteDocument(keyword, doc_id);
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
            std::vector<std::pair<Keyword, DocumentId>> pairs;
            // 解析关键词-文档ID对数组
            for (const auto& item : json) {
                pairs.emplace_back(
                    item["keyword"].get<std::string>(),
                    item["document_id"].get<std::string>()
                );
            }
            bm_plus_->deleteDocuments(pairs);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 重建所有索引
    server_.Post("/rebuild-indices", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            bm_plus_->rebuildAllIndices();
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 获取搜索令牌
    server_.Post("/get-search-token", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string userId = json["userId"];
            std::string encryptedId = json["encryptedId"];
            std::string hashedKeyword = json["hashedKeyword"];
            std::cout << "userId: " << userId << ", encryptedId: " << encryptedId << ", hashedKeyword: " << hashedKeyword << std::endl;
            SearchToken token = bm_plus_->getSearchToken(userId, encryptedId, hashedKeyword);
            
            // 将 token 序列化为 JSON 并返回
            res.set_content(nlohmann::json(token).dump(), "application/json");
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    //使用token搜索
    server_.Post("/search-with-token", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string userId = json["userId"];
            std::string encryptedUserId = json["encryptedUserId"];
            std::string encryptedKeyword = json["encryptedKeyword"];
            SearchToken token = json["token"].get<SearchToken>();
            auto results = bm_plus_->searchWithToken(userId, encryptedUserId, encryptedKeyword, token);
            res.set_content(nlohmann::json(results).dump(), "application/json");
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
    // 更新用户表
    server_.Post("/update-user-table", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            auto users = json["users"].get<std::map<std::string, User>>();
            bm_plus_->updateUserTable(users);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 更新单个用户
    server_.Post("/update-user", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            User user = json["user"].get<User>();
            bm_plus_->updateUser(user);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 添加用户
    server_.Post("/add-user", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            User user = json["user"].get<User>();
            bm_plus_->addUser(user);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 删除用户
    server_.Post("/delete-user", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string userId = json["userId"].get<std::string>();
            bm_plus_->deleteUser(userId);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 更新层级密钥表
    server_.Post("/update-level-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            auto levelKeys = json["levelKeys"].get<std::map<AccessLevel, LevelKey>>();
            bm_plus_->updateLevelKeys(levelKeys);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 更新状态密钥表
    server_.Post("/update-state-keys", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            auto stateKeys = json["stateKeys"].get<std::map<State, StateKey>>();
            bm_plus_->updateStateKeys(stateKeys);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });

    // 更新封装密钥
    server_.Post("/update-encapsulation-key", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            auto json = nlohmann::json::parse(req.body);
            std::string encapsulationKey = json["encapsulationKey"].get<std::string>();
            bm_plus_->updateEncapsulationKey(encapsulationKey);
            res.status = 200;
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(e.what(), "text/plain");
        }
    });
}
