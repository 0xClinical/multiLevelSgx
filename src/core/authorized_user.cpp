#include "core/authorized_user.h"
#include <iostream>
#include <httplib.h>
#include <nlohmann/json.hpp>

std::vector<Document> AuthorizedUser::searchFiles(const std::string& keyword) {
    // 1. 请求SGX转发密钥到Token Generator
    std::string encrypted_userId = CryptoUtils::encryptWithPrivateKey(userId_,privateKey_ );
    std::string encrypted_keyword = CryptoUtils::encryptWithPrivateKey(keyword,privateKey_ );
    nlohmann::json keyRequestData = {
        {"userId", userId_},
        {"encrypted_userId", encrypted_userId}, 
    };
    
    httplib::Client sgx_cli(sgx_url_);
    auto key_res = sgx_cli.Post("/forward-keys", keyRequestData.dump(), "application/json");
    if (!key_res || key_res->status != 200) {
        return {};
    }
    
    // 2. 生成掩码并盲化关键字
    std::string mask = CryptoUtils::generateRandomString();
    std::string blinded_keyword = CryptoUtils::xorStrings(keyword, mask);
    
    // 3. 向Token Generator请求OPRF计算
    nlohmann::json tokenRequestData = {
        {"userId", userId_},
        {"blindedKeyword", blinded_keyword}
    };
    
    httplib::Client token_cli(token_url_);
    auto token_res = token_cli.Post("/compute-token", tokenRequestData.dump(), "application/json");
    if (!token_res || token_res->status != 200) {
        return {};
    }
    
    // 4. 解析OPRF结果并解盲
    auto response = nlohmann::json::parse(token_res->body);
    std::string blinded_token = response["token"].get<std::string>();
    std::string token = CryptoUtils::xorStrings(blinded_token, mask);  // 解盲
    
    // 5. 向云服务器发送搜索请求
    httplib::Client cloud_cli(server_url_);
    nlohmann::json searchRequestData = {
        {"token", token}
    };
    
    auto search_res = cloud_cli.Post("/search", searchRequestData.dump(), "application/json");
    if (!search_res || search_res->status != 200) {
        return {};
    }
    
    // 6. 解析搜索结果 - 现在是<docId, z2>对的列表
    auto search_response = nlohmann::json::parse(search_res->body);
    std::vector<std::pair<std::string, std::string>> searchResults = 
        search_response["results"].get<std::vector<std::pair<std::string, std::string>>>();
    
    // 7. 请求SGX解密文档ID列表
    nlohmann::json decryptRequestData = {
        {"userId", userId_},
        {"encrypted_userId", encrypted_userId},
        {"encrypted_keyword", encrypted_keyword},
        {"searchResults", searchResults}  // 包含docId和z2
    };
    
    auto decrypt_res = sgx_cli.Post("/decrypt-search-results", decryptRequestData.dump(), "application/json");
    if (!decrypt_res || decrypt_res->status != 200) {
        return {};
    }
    
    // 8. 返回解密后的文档
    auto decrypt_response = nlohmann::json::parse(decrypt_res->body);
    return decrypt_response["documents"].get<std::vector<Document>>();
}


