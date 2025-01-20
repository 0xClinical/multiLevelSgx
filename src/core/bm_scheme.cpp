#include "core/BM_scheme.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>

std::pair<EncryptedIndex, LookupTable> 
BMScheme::buildIndex(const std::map<Keyword, std::vector<Document>>& keywordMap) {
    std::vector<IndexNode> A;  // 使用vector存储节点
    LookupTable T;            // 查找表
    
    for (const auto& [keyword, docs] : keywordMap) {
        // 初始化列表
        std::vector<std::string> L;  // Lωi
        std::vector<size_t> X(100, 0);       // Xωi,100个层级容量
        std::vector<size_t> N;       // Nωi
        std::vector<std::string> digest;  // digestωi
        
        // 按访问级别降序排序
        std::vector<Document> sortedDocs = docs;
        std::sort(sortedDocs.begin(), sortedDocs.end(),
                 [](const Document& a, const Document& b) {
                     return a.level > b.level;
                 });
        
        // 生成随机地址序列
        std::vector<size_t> N(sortedDocs.size());
        std::iota(N.begin(), N.end(), 0);  // 填充 [0,1,2,...,n-1]
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(N.begin(), N.end(), gen);  // 随机打乱
        
        // 预分配空间
        A.resize(sortedDocs.size());
        
        // 第一阶段：构建基础列表
        size_t loc = 0;
        AccessLevel current_level = sortedDocs[0].level;  // 从最高层级开始
        
        for (const auto& doc : sortedDocs) {
            loc++;
            // Lωi ← Lωi ∪ {F1(kλ(id),1, id)}
            L.push_back(CryptoUtils::F1(levelKeys_[doc.level].key1, doc.id));
            
            // 记录每个层级的第一个位置
            if (doc.level != current_level) {
                X[doc.level] = loc;  // 直接用层级作为索引
                current_level = doc.level;
            }
        }
        
        // 第二阶段：构建加密节点
        // 处理除最后一个节点外的所有节点
        for (size_t j = 0; j < N.size() - 1; j++) {
            // 生成随机数 rj
            std::string r = CryptoUtils::generateRandomString();
            
            // 计算z值
            std::string z = CryptoUtils::H1(levelKeys_[sortedDocs[j].level].key2, keyword);
            std::string z_next = CryptoUtils::H1(levelKeys_[sortedDocs[j+1].level].key2, keyword);
            
            // 计算h2
            std::string h2 = CryptoUtils::H2(z, r);
            
            // 计算摘要
            digest.push_back(CryptoUtils::computeDigest(
                CryptoUtils::xorStrings(h2, L[j])));
            
            // 构建节点
            IndexNode node;
            // a1 计算
            node.a1 = CryptoUtils::xorStrings(
                CryptoUtils::xorStrings(L[j], h2),
                CryptoUtils::H3(stateKeys_[sortedDocs[j].state], keyword)
            );
            
            // a2 计算
            node.a2 = {N[j + 1], z_next};
            node.a2 = CryptoUtils::xorPair(node.a2, h2);
            
            node.a3 = r;
            node.a4 = CryptoUtils::F2(encapsulationKey_, sortedDocs[j].level);
            node.a5 = digest[j];
            
            A[N[j]] = node;
        }
        
        // 处理最后一个节点
        size_t last = N.size() - 1;
        std::string r_last = CryptoUtils::generateRandomString();
        std::string z_last = CryptoUtils::H1(
            levelKeys_[sortedDocs[last].level].key2, 
            keyword
        );
        std::string h2_last = CryptoUtils::H2(z_last, r_last);
        
        digest.push_back(CryptoUtils::computeDigest(
            CryptoUtils::xorStrings(h2_last, L[last])));
            
        IndexNode last_node;
        last_node.a1 = CryptoUtils::xorStrings(
            CryptoUtils::xorStrings(L[last], h2_last),
            CryptoUtils::H3(stateKeys_[sortedDocs[last].state], keyword)
        );
        last_node.a2 = {0, ""};  // 链表结束
        last_node.a3 = r_last;
        last_node.a4 = CryptoUtils::F2(encapsulationKey_, sortedDocs[last].level);
        last_node.a5 = digest[last];
        
        A[N[last]] = last_node;
        
        // 构建查找表
        for (size_t level = 0; level < X.size(); level++) {
            if (X[level] != 0) {
                T[CryptoUtils::H4(levelKeys_[level].key3, keyword)] = 
                    N[X[level]-1] ^ std::stoull(CryptoUtils::H5(levelKeys_[level].key4, keyword));
            } else {
                T[CryptoUtils::H4(levelKeys_[level].key3, keyword)] = 0;
            }
        }
    }
    
    return {A, T};
}

std::vector<std::string> BMScheme::decryptSearchResults(
    const std::string& userId,
    const std::string& encryptedUserId,
    const std::string& encryptedKeyword,
    const std::vector<std::pair<std::string, std::string>>& searchResults) {
    
    // 1. 验证用户身份和签名
    auto userIt = userTable_.find(userId);
    std::string userId_ = CryptoUtils::decryptWithPublicKey(encryptedUserId, userIt->second.publicKey);
    if (userIt == userTable_.end() || userId_ != userId) {
        return {};
    }
    
    // 2. 获取用户的层级和状态
    AccessLevel userLevel = userIt->second.level;
    State userState = userIt->second.state;
    
    // 3. 使用用户公钥解密关键字
    std::string keyword = CryptoUtils::decryptWithPublicKey(encryptedKeyword, userIt->second.publicKey);
    
    // 4. 从本地缓存中搜索匹配关键字的文档ID
    std::vector<std::string> localIds;
    auto batchIt = documentBatch_.find(keyword);
    if (batchIt != documentBatch_.end()) {
        for (const auto& doc : batchIt->second) {
            if (doc.level <= userLevel && doc.state <= userState) {
                localIds.push_back(doc.id);
            }
        }
    }
    
    // 5. 解密服务器返回的搜索结果
    std::vector<std::string> serverIds;
    for (const auto& [res, z2] : searchResults) {
        // 解密z2得到文件层级
        std::string decryptedZ2 = CryptoUtils::xorStrings(
            z2, 
            CryptoUtils::F2_inverse(encapsulationKey_, z2)
        );
        AccessLevel fileLevel = static_cast<AccessLevel>(std::stoi(decryptedZ2));
        
        // 检查用户是否有权限访问该文件
        if (fileLevel > userLevel) {
            continue;
        }
        
        // 使用层级密钥解密文件标识符
        auto levelKeyIt = levelKeys_.find(fileLevel);
        if (levelKeyIt == levelKeys_.end()) {
            continue;
        }
        
        std::string fileId = CryptoUtils::xorStrings(
            res,
            CryptoUtils::F1_inverse(levelKeyIt->second.key1, res)
        );
        
        serverIds.push_back(fileId);
    }
    
    // 6. 合并本地和服务器的结果
    std::vector<std::string> allIds = serverIds;
    allIds.insert(allIds.end(), localIds.begin(), localIds.end());
    
    return allIds;
}


bool BMScheme::verifyAndForwardKeys(const std::string& userId, const std::string& encryptedId) {
    // 解密用户ID
    std::string userId_ = CryptoUtils::decryptWithPublicKey(encryptedId, userTable_[userId].publicKey);
    
    // 验证用户存在
    auto userIt = userTable_.find(userId_);
    if (userIt == userTable_.end() || userId_ != userId) {
        return false;
    }
    
    // 获取用户的密钥
    AccessLevel level = userIt->second.level;
    LevelKey levelKey = levelKeys_[level];
    
    // 收集从状态0到当前状态的所有状态密钥
    std::vector<std::string> stateKeys;
    State currentState = userIt->second.state;
    for (State s = 0; s <= currentState; s++) {
        stateKeys.push_back(stateKeys_[s]);
    }
    
    // 转发到Token Generator
    return forwardKeysToGenerator(userId, levelKey, stateKeys);
   
}

bool BMScheme::forwardKeysToGenerator(
    const std::string& userId, 
    const LevelKey& levelKey,
    const std::vector<std::string>& stateKeys) {
    
    nlohmann::json requestData = {
        {"userId", userId},
        {"levelKey", {
            {"key1", levelKey.key1},
            {"key2", levelKey.key2},
            {"key3", levelKey.key3},
            {"key4", levelKey.key4}
        }},
        {"stateKeys", stateKeys}
    };
    
    httplib::Client cli(token_url_);
    auto res = cli.Post("/receive-keys", requestData.dump(), "application/json");
    if (res && res->status == 200) {
        return true;
    }
    return false;
    

}


// 管理员批量上传文件到本地缓存
void BMScheme::uploadDocuments(const std::vector<Document>& docs) {
    // 将文档批量添加到每个关键字的缓存中
    for (const auto& doc : docs) {
        for (const auto& keyword : doc.keywords) {
            documentBatch_[keyword].push_back(doc);
        }
    }
}

// 保留单文件上传接口，内部调用批量上传
void BMScheme::uploadDocument(const Document& doc) {
    uploadDocuments({doc});
}

//删除文档
void BMScheme::deleteDocument(const Document& doc) {
    // 1. 直接从文档对象获取关键字集
    const std::set<Keyword>& affectedKeywords = doc.keywords;
    
    // 2. 从本地缓存中删除文档
    for (auto& [keyword, docs] : documentBatch_) {
        docs.erase(
            std::remove_if(docs.begin(), docs.end(),
                [docId = doc.id](const Document& d) { return d.id == docId; }),
            docs.end()
        );
    }
    
    // 3. 为每个受影响的关键字重建索引
    for (const auto& keyword : affectedKeywords) {
        // 获取该关键字下的所有文档
        auto& docs = documentBatch_[keyword];
        
        // 重建该关键字的索引并上传到服务器
        rebuildIndexForKeyword(keyword, docs);
    }
}

//批量删除文档
void BMScheme::deleteDocuments(const std::vector<Document>& docs) {
    for (const auto& doc : docs) {
        deleteDocument(doc);
    }
}

// 管理员手动触发上传到服务器
void BMScheme::rebuildAllIndices() {
    // 获取需要更新的关键字列表
    std::map<Keyword, std::vector<Document>> keywordMap;
    for (const auto& [keyword, docs] : documentBatch_) {
        if (!docs.empty()) {
            keywordMap[keyword] = docs;
        }
    }
    
    // 为每个关键字重建索引
    for (const auto& [keyword, newDocs] : keywordMap) {
        rebuildIndexForKeyword(keyword, newDocs);
    }
    
    // 清空批处理缓存
    documentBatch_.clear();
}

// 重建单个关键字的索引
void BMScheme::rebuildIndexForKeyword(const Keyword& keyword, 
                                      const std::vector<Document>& newDocs) {
    // 1. 从云服务器获取现有数据
    httplib::Client cli(server_url_);
    auto res = cli.Get("/get-keyword-data/" + keyword);
    
    if (!res || res->status != 200) {
        // 处理错误情况
        std::cerr << "Failed to get keyword data from server" << std::endl;
        return;
    }
    
    // 解析响应数据
    auto data = nlohmann::json::parse(res->body);
    EncryptedList keywordData {
        data["encryptedIndex"].get<std::vector<IndexNode>>(),
        data["lookupTable"].get<LookupTable>(),
        data["encryptedDocs"].get<std::vector<DocumentId>>()
    };
    
    // 2. 解密现有文档
    std::vector<Document> allDocs = newDocs;
    for (const auto& encDoc : keywordData.docs) {
        allDocs.push_back(decryptDocument(encDoc));
    }
    
    // 3. 重建索引
    auto [newIndex, newTable] = buildIndex({{keyword, allDocs}});
    
    // 4. 加密新文档
    std::vector<DocumentId> encryptedDocs;
    for (const auto& doc : allDocs) {
        encryptedDocs.push_back(encryptDocument(doc));
    }
    
    // 5. 通过网络请求更新云服务器
    nlohmann::json updateData = {
        {"keyword", keyword},
        {"encryptedIndex", newIndex},
        {"lookupTable", newTable},
        {"encryptedDocs", encryptedDocs}
    };
    
    auto update_res = cli.Post("/update-keyword-data", 
                              updateData.dump(), 
                              "application/json");
    
    if (!update_res || update_res->status != 200) {
        std::cerr << "Failed to update keyword data on server" << std::endl;
    }
}

// 加密单个文档
EncryptedDocument BMScheme::encryptDocument(const Document& doc) {
    // 序列化文档为JSON
    nlohmann::json docJson = {
        {"id", doc.id},
        {"level", doc.level},
        {"keywords", doc.keywords},
        {"state", doc.state}
    };
    
    // 加密整个文档信息
    return CryptoUtils::F1(encapsulationKey_, docJson.dump());
}

// 解密单个文档
Document BMScheme::decryptDocument(const EncryptedDocument& encryptedDoc) {
    // 解密文档
    std::string decrypted = CryptoUtils::F1_inverse(
        encapsulationKey_,
        encryptedDoc
    );
    
    // 解析JSON并构造Document对象
    auto docJson = nlohmann::json::parse(decrypted);
    return Document {
        docJson["id"].get<std::string>(),
        docJson["level"].get<AccessLevel>(),
        docJson["keywords"].get<std::set<Keyword>>(),
        docJson["state"].get<State>()
    };
}

void BMScheme::startStateKeyTimer() {
    stateKeyTimer_ = std::make_unique<Timer>();
    stateKeyTimer_->start(stateKeyUpdateInterval_, [this]() {
        updateStateKey();
    });
}

void BMScheme::updateStateKey() {
    // 生成新的状态密钥
    currentState_++;
    std::string newStateKey = CryptoUtils::generateRandomString();
    
    // 更新状态密钥表
    stateKeys_[currentState_] = newStateKey;
    
    std::cout << "Successfully updated state key for state " << currentState_ << std::endl;
    
}
