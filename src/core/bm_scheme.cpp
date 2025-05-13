#include "core/bm_scheme.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <httplib.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <bitset>
#include <numeric>  // 用于std::iota
#include "sgx_trts.h"  // 包含SGX运行时服务，其中包括sgx_read_rand


// 使用自定义随机数生成器
class SGXRandomGenerator {
public:
    using result_type = uint32_t;
    
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return UINT32_MAX; }
    
    result_type operator()() {
        result_type value;
        sgx_read_rand((unsigned char*)&value, sizeof(value));
        return value;
    }
};

std::pair<EncryptedIndex, LookupTable> 
BMScheme::buildIndex(const Keyword keyword_hash,const std::vector<Document>& docs) {
   
    std::vector<IndexNode> A;  // 使用vector存储节点
    LookupTable T;            // 查找表
    
    // 初始化列表
    std::vector<std::string> L;  // Lωi
    std::vector<size_t> X;       // Xωi,L个层级容量
    std::vector<size_t> N;       // Nωi
    std::vector<std::string> digest;  // digestωi
    
    
    // 按访问级别降序排序
    std::vector<Document> sortedDocs = docs;
    std::sort(sortedDocs.begin(), sortedDocs.end(),
                [](const Document& a, const Document& b) {
                    return a.level > b.level;
                });
 
    // 生成随机地址序列
    N.resize(sortedDocs.size());
    std::iota(N.begin(), N.end(), 0);  // 填充 [0,1,2,...,n-1]
    X.resize(4);

    // 使用自定义随机数生成器
    SGXRandomGenerator rng;
    std::shuffle(N.begin(), N.end(), rng);
    // 预分配空间
    A.resize(sortedDocs.size());

    // 第一阶段：构建基础列表
    size_t loc = 0;
    AccessLevel current_level = 0;  // 从0开始

    L.reserve(sortedDocs.size());
   
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
    for (size_t j = 0; j < N.size() - 1; j++) {
      
        // 生成随机数 rj
        std::string r = CryptoUtils::generateRandomString();
     
        // 计算z值
        std::string z = CryptoUtils::H1(levelKeys_[sortedDocs[j].level].key2, keyword_hash);
        std::string z_next = CryptoUtils::H1(levelKeys_[sortedDocs[j+1].level].key2, keyword_hash);
        
        // 计算h2并验证
        std::string h2 = CryptoUtils::H2(z, r);
        size_t h2_num = CryptoUtils::stringToSize(h2);

        // 计算摘要
        digest.push_back(CryptoUtils::computeDigest(
            CryptoUtils::xorStrings(h2, L[j])));
  
        // 构建节点
        IndexNode node;
        // a1 计算
        node.a1 = CryptoUtils::xorStrings(
            CryptoUtils::xorStrings(L[j], h2),
            CryptoUtils::H3(stateKeys_[sortedDocs[j].state], keyword_hash)
        );
        
        // a2 计算
        node.a2 = {N[j + 1], z_next};
      
        node.a2 = CryptoUtils::xorPair(node.a2, h2);
      
        node.a3 = r;
     
        node.a4 = CryptoUtils::F2(encapsulationKey_, std::to_string(sortedDocs[j].level));
        node.a5 = digest[j];

        A[N[j]] = node;
    }
    // 处理最后一个节点
    size_t last = N.size() - 1;
    std::string r_last = CryptoUtils::generateRandomString();
    std::string z_last = CryptoUtils::H1(
        levelKeys_[sortedDocs[last].level].key2, 
        keyword_hash
    );
    std::string h2_last = CryptoUtils::H2(z_last, r_last);
    
    digest.push_back(CryptoUtils::computeDigest(
        CryptoUtils::xorStrings(h2_last, L[last])));
        
    IndexNode last_node;
    last_node.a1 = CryptoUtils::xorStrings(
        CryptoUtils::xorStrings(L[last], h2_last),
        CryptoUtils::H3(stateKeys_[sortedDocs[last].state], keyword_hash)
    );
    last_node.a2 = {0, ""};  // 链表结束
    last_node.a3 = r_last;
    last_node.a4 = CryptoUtils::F2(encapsulationKey_, std::to_string(sortedDocs[last].level));
    last_node.a5 = digest[last];
    
    A[N[last]] = last_node;
    
    // 构建查找表
    for (size_t level = 1; level < X.size(); level++) {
        if (X[level] != 0) {
            auto tau2 = CryptoUtils::H4(levelKeys_[level].key3, keyword_hash);
            std::string h5 = CryptoUtils::H5(levelKeys_[level].key4, keyword_hash);        
            // 使用相同的哈希转换方式
            size_t h5_num = CryptoUtils::stringToSize(h5);
            
            T[tau2] = N[X[level]-1] ^ h5_num;
          
        } else {
            T[CryptoUtils::H4(levelKeys_[level].key3, keyword_hash)] = 0;
        }
        
    }
    return {A, T};
}

std::vector<std::string> BMScheme::decryptSearchResults(
    const std::vector<std::pair<std::string, std::string>>& searchResults) {
    std::vector<std::string> serverIds;
    int count = 0;
    
    for (const auto& [res, z2] : searchResults) {
   
        try {
            // 解密z2得到文件层级
            std::string f2_inv = CryptoUtils::F2_inverse(encapsulationKey_, z2);
        
            // 直接使用 F2_inverse 的结果作为层级
            AccessLevel fileLevel = static_cast<AccessLevel>(std::stoi(f2_inv));
           
            
            // 使用层级密钥解密文件标识符
            auto levelKeyIt = levelKeys_.find(fileLevel);
            if (levelKeyIt == levelKeys_.end()) {
               
                continue;
            }
            
            std::string fileId = CryptoUtils::F1_inverse(levelKeyIt->second.key1, res);
          
            serverIds.push_back(fileId);
            
        } catch (const std::exception& e) {
           
        }
    }
    

    return serverIds;
}

// 获取搜索令牌
SearchToken BMScheme::getSearchToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword) {
    // 获取用户的密钥
    AccessLevel level = userTable_[userId].level;
    LevelKey levelKey = levelKeys_[level];
   
    
    // 收集从状态0到当前状态的所有状态密钥
    std::vector<std::string> stateKeys;
    State currentState = userTable_[userId].state;
    
    for (State s = 1; s <= currentState; s++) {
        stateKeys.push_back(stateKeys_[s]);
       
    }
    
    return generateToken(hashedKeyword, levelKey, stateKeys);
}

//使用token进行搜索
std::vector<std::string> BMScheme::searchWithToken(const std::string& userId, 
        const std::string& encryptedId, 
        const std::string& hashed_keyword, 
        const SearchToken& token,
        size_t max_doc) {
 
    
    // 1. 从edb中获取结果
    std::vector<std::pair<std::string, std::string>> results = edb_controller.search(token, max_doc);
    
   
    // 2. 解密结果
    std::vector<std::string> decryptedResults = decryptSearchResults(results);
   
    //4.从本地缓存中找出关键字对应的文档且这些文档满足用户的状态和层级
    std::vector<std::string> localResults;
    for(const auto& doc : documentBatch_[hashed_keyword]){
        if(doc.state <= userTable_[userId].state && doc.level <= userTable_[userId].level){
            localResults.push_back(doc.id);
        }
    }
    //5.将本地结果和解密结果合并
    localResults.insert(localResults.end(), decryptedResults.begin(), decryptedResults.end());
    
    // 如果设置了结果数量限制，裁剪最终结果
    if (max_doc > 0 && localResults.size() > max_doc) {
        localResults.resize(max_doc);
    }
    return localResults;
}


// 管理员批量上传文件到本地缓存
void BMScheme::uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs) {
    
    for (const auto& pair : pairs) {
        const auto& keyword = pair.first;
        const auto& doc = pair.second;
        uploadDocument(keyword, doc);
    }
}

// 单文件上传接口
void BMScheme::uploadDocument(const Keyword& keyword, const Document& doc) {
   
    // 检查并更新状态
    Document updatedDoc = doc;
    if(updatedDoc.state == 0 || updatedDoc.state >= currentState_) {
        updatedDoc.state = currentState_;
    }
    // 添加到批处理缓存
    documentBatch_[keyword].push_back(updatedDoc);
    
}

// 删除文档
void BMScheme::deleteDocument(const Keyword& keyword, DocumentId docId) {
    // 1. 从本地缓存中删除
    auto& docs = documentBatch_[keyword];
    auto originalSize = docs.size();
    docs.erase(
        std::remove_if(docs.begin(), docs.end(),
            [docId](const Document& d) { return d.id == docId; }),
        docs.end()
    );
    bool deletedFromCache = (docs.size() < originalSize);
    
    // 2. 如果本地缓存中没有，从服务器删除
    if (!deletedFromCache) {
        // 获取服务器上的加密文档
        EncryptedList keywordData = edb_controller.getKeywordData(keyword);
        
        // 解密并过滤文档
        std::vector<Document> allDocs;
        for (const auto& encDoc : keywordData.documents) {
            Document decDoc = decryptDocument(encDoc);
            if (decDoc.id != docId) {  // 保留非目标文档
                allDocs.push_back(std::move(decDoc));
            }
        }
        
        // 如果还有剩余文档，重建索引
        if (!allDocs.empty()) {
            std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, allDocs);
            EncryptedIndex newIndex = result.first;
            LookupTable newTable = result.second;
            
            // 加密剩余文档
            std::vector<EncryptedDocument> encryptedDocs;
            encryptedDocs.reserve(allDocs.size());
            for (const auto& d : allDocs) {
                encryptedDocs.push_back(encryptDocument(d));
            }
            
            // 更新服务器
            edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);
        }
    }
}

// 批量删除文档
void BMScheme::deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs) {
    // 按关键字分组需要删除的文档ID
    std::map<Keyword, std::vector<DocumentId>> keywordToDocIds;
    for (const auto& pair : pairs) {
        const auto& keyword = pair.first;
        const auto& docId = pair.second;
        keywordToDocIds[keyword].push_back(docId);
    }
    
    // 对每个关键字分别处理
    for (const auto& [keyword, docIds] : keywordToDocIds) {
        // 1. 从本地缓存中删除
        auto& docs = documentBatch_[keyword];
        auto originalSize = docs.size();
        docs.erase(
            std::remove_if(docs.begin(), docs.end(),
                [&docIds](const Document& d) {
                    return std::find(docIds.begin(), docIds.end(), d.id) != docIds.end();
                }),
            docs.end()
        );
        bool deletedFromCache = (docs.size() < originalSize);
       
        // 2. 如果本地缓存中没有全部找到，从服务器删除
        if (!deletedFromCache || docs.size() + docIds.size() > originalSize) {
            // 获取服务器上的加密文档
            EncryptedList keywordData = edb_controller.getKeywordData(keyword);
            // 解密并过滤文档
            std::vector<Document> remainingDocs;
            for (const auto& encDoc : keywordData.documents) {
                Document decDoc = decryptDocument(encDoc);
                // 保留不在删除列表中的文档
                if (std::find(docIds.begin(), docIds.end(), decDoc.id) == docIds.end()) {
                    remainingDocs.push_back(std::move(decDoc));
                }
            }
        
            // 重建索引（无论是否有剩余文档）
            std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, remainingDocs);
            EncryptedIndex newIndex = result.first;
            LookupTable newTable = result.second;
            // 加密剩余文档（如果有的话）
            std::vector<EncryptedDocument> encryptedDocs;
            if (!remainingDocs.empty()) {
                encryptedDocs.reserve(remainingDocs.size());
                for (const auto& doc : remainingDocs) {
                    encryptedDocs.push_back(encryptDocument(doc));
                }
            }
   
            // 更新服务器（即使是空的也更新）
            edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);
        }
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
    size_t completed = 0;
    for (const auto& [keyword, newDocs] : keywordMap) {
        try {
            rebuildIndexForKeyword(keyword, newDocs);
            completed++;
            
        } catch (const std::exception& e) {
            throw;
        }
    }
    
    // 清空批处理缓存
    documentBatch_.clear();

}
// 重建单个关键字的索引
void BMScheme::rebuildIndexForKeyword(const Keyword& keyword, 
                                      const std::vector<Document>& newDocs) {
 
    
    // 1. 从云服务器获取现有数据
    EncryptedList keywordData = edb_controller.getKeywordData(keyword);

    // 2. 解密现有文档
  
    std::vector<Document> allDocs = newDocs;
    for (const auto& encDoc : keywordData.documents) {
        allDocs.push_back(decryptDocument(encDoc));
    }
    
    
    // 3. 重建索引
    
    std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, allDocs);
    EncryptedIndex newIndex = result.first;
    LookupTable newTable = result.second;
    
  
    // 4. 加密新文档
  
    std::vector<DocumentId> encryptedDocs;
    for (const auto& doc : allDocs) {
        encryptedDocs.push_back(encryptDocument(doc));
    }
    edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);

}

// 加密单个文档
EncryptedDocument BMScheme::encryptDocument(const Document& doc) {
    // 序列化文档为JSON
    SGXValue docJson;
    docJson["id"] = doc.id;
    docJson["level"] = static_cast<int>(doc.level);
    docJson["state"] = static_cast<int>(doc.state);
    docJson["isBogus"] = doc.isBogus;
    
    std::string jsonStr = docJson.dump();
    
    // 加密整个文档信息
    //auto encrypted = CryptoUtils::F1(encapsulationKey_, jsonStr);
    return jsonStr;
}

// 解密单个文档
Document BMScheme::decryptDocument(const EncryptedDocument& encryptedDoc) {
    try {
        // 解密文档
        std::string decrypted = encryptedDoc;
        //std::string decrypted = CryptoUtils::F1_inverse(
        //    encapsulationKey_,
        //    encryptedDoc
        //);
        
        try {
            // 使用我们的SGX兼容序列化库
            SGXValue docJson = sgx_serializer::parse(decrypted);
            
            return Document {
                docJson["id"].get_string(),
                static_cast<AccessLevel>(docJson["level"].get_int()),
                static_cast<State>(docJson["state"].get_int()),
                docJson["isBogus"].get_bool()
            };
        } catch (const std::exception& e) {
            throw;
        }
    } catch (const std::exception& e) {
        throw;
    }
}

void BMScheme::startStateKeyTimer() {
    stateKeyTimer_.reset(new Timer());
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
    
}

SearchToken BMScheme::generateToken(const Keyword& keyword, const LevelKey& levelKey, const std::vector<StateKey>& stateKeys) {
    
    SearchToken token;
    
    // 1. 生成tau1 - 用于解密第一个节点
    token.tau1 = CryptoUtils::H1(levelKey.key2, keyword);
    
    
    // 2. 生成tau2 - 用于定位查找表条目
    token.tau2 = CryptoUtils::H4(levelKey.key3, keyword);
    
    
    // 3. 生成tau3 - 用于解密起始节点位置
    token.tau3 = CryptoUtils::H5(levelKey.key4, keyword);
    
    
    // 4. 生成tau4 - 状态密钥哈希值集合
    
    for (const auto& stateKey : stateKeys) {
        token.tau4.push_back(CryptoUtils::H3(stateKey, keyword));
    }
    
    size_t paddingCount = stateKeys_.size() - stateKeys.size();
    
    
    auto paddingKeys = generatePaddingStateKeys(paddingCount);
    for (const auto& key : paddingKeys) {
        token.tau4.push_back(CryptoUtils::H3(key, keyword));
    }
    
    // 使用SGX随机数生成器打乱tau4
    shuffleTau4(token.tau4);
    
    return token;
}

void BMScheme::shuffleTau4(std::vector<std::string>& vec) {
    if (vec.size() <= 1) return;
    for (size_t i = vec.size() - 1; i > 0; --i) {
        // 生成0到i之间的随机索引
        uint32_t rand_idx = 0;
        sgx_status_t ret = sgx_read_rand((unsigned char*)&rand_idx, sizeof(rand_idx));
        
        if (ret != SGX_SUCCESS) {
            // 如果随机数生成失败，使用简单的替代方法
            rand_idx = i * 0x5DEECE66DLL + 0xBLL;
        }
        
        rand_idx = rand_idx % (i + 1);
        
        // 交换元素
        if (rand_idx != i) {
            std::string temp = vec[i];
            vec[i] = vec[rand_idx];
            vec[rand_idx] = temp;
        }
    }
}

        
std::vector<std::string> BMScheme::generatePaddingStateKeys(size_t count) const {
    std::vector<std::string> paddingKeys;
        for (size_t i = 0; i < count; i++) {
            paddingKeys.push_back(CryptoUtils::generateRandomString());
        }
        return paddingKeys;
}