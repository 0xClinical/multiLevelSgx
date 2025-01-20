#pragma once
#include "utils/types.h"
#include "utils/crypto.h"


class AuthorizedUser {
public:
    AuthorizedUser(const std::string& id, 
                  const std::string& privateKey,
                  const std::string& sgx_url = "http://localhost:8080",
                  const std::string& token_url = "http://localhost:8081",
                  const std::string& server_url = "http://localhost:8082")
        : userId_(id)
        , privateKey_(privateKey)
        , sgx_url_(sgx_url)
        , token_url_(token_url)
        , server_url_(server_url) {}

    // 搜索文件
    std::vector<Document> searchFiles(const std::string& keyword);
    
private:
    std::string userId_;
    std::string privateKey_;
    std::string sgx_url_;
    std::string token_url_;
    std::string server_url_;
};
