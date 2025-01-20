#include "core/bm_scheme_plus.h"

void BMSchemePlus::uploadDocument(const Document& doc) {
    uploadDocuments({doc});
}

void BMSchemePlus::uploadDocuments(const std::vector<Document>& M) {
    // 1. 执行填充检查
    auto D = paddingCheck(M, clusters_, paddingDataset_);
    
    // 2. 如果没有需要处理的数据，直接返回
    if (D.empty()) {
        return;
    }
    
    // 3. 为每个文档列表构建索引
    for (const auto& Dw : D) {
        if (!Dw.empty()) {
            std::map<Keyword, std::vector<Document>> keywordMap;
            // 将文档按关键词分组
            for (const auto& doc : Dw) {
                for (const auto& keyword : doc.keywords) {
                    keywordMap[keyword].push_back(doc);
                }
            }
            // 构建索引
            auto [index, table] = buildIndex(keywordMap);
            // TODO: 上传到EDB
        }
    }
}

std::vector<DocumentList> BMSchemePlus::paddingCheck(
    const std::vector<Document>& M,
    const std::vector<Cluster>& clusters,
    PaddingDataset& B) {
    
    // 1. 将文件推送到对应的簇
    for (const auto& doc : M) {
        for (const auto& keyword : doc.keywords) {
            for (auto& cluster : clusters_) {
                if (cluster.containsKeyword(keyword)) {
                    cluster.addDocument(doc);
                    searchTable_[keyword].flag = true;
                    break;
                }
            }
        }
    }
    
    std::vector<DocumentList> D;
    
    // 2. 根据对手类型执行不同的填充策略
    if (!isPersistentAdversary_) {
        // 非持续性对手的填充策略
        for (const auto& cluster : clusters) {
            if (cluster.capacity() >= cluster.threshold()) {
                DocumentList Dw;
                bool skipCluster = false;
                
                // 检查簇中的关键词状态
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        skipCluster = true;
                        break;
                    }
                }
                
                if (!skipCluster) {
                    Dw = padding(cluster, searchTable_, B);
                    if (!Dw.empty()) {
                        D.push_back(Dw);
                    }
                }
            }
        }
    } else {
        // 持续性对手的填充策略
        for (const auto& cluster : clusters) {
            bool allKeywordsPresent = true;
            
            // 检查是否所有关键词都出现过
            if (cluster.isFirstBatch()) {
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        allKeywordsPresent = false;
                        break;
                    }
                }
                
                if (allKeywordsPresent) {
                    auto Dw = padding(cluster, searchTable_, B);
                    if (!Dw.empty()) {
                        D.push_back(Dw);
                    }
                }
            } else if (cluster.capacity() >= cluster.threshold()) {
                auto Dw = padding(cluster, searchTable_, B);
                if (!Dw.empty()) {
                    D.push_back(Dw);
                }
            }
        }
    }
    
    return D;
}

DocumentList BMSchemePlus::padding(
    const Cluster& cluster,
    std::map<Keyword, SearchState>& ST,
    PaddingDataset& B) {
    
    DocumentList D;
    
    // 1. 计算簇中每个关键词的缓存长度
    std::map<Keyword, size_t> cw;
    size_t cmax = 0;
    for (const auto& keyword : cluster.getKeywords()) {
        cw[keyword] = cluster.getKeywordCount(keyword);
        cmax = std::max(cmax, cw[keyword]);
    }
    
    // 2. 计算ST中的最大计数
    size_t stmax = 0;
    for (const auto& keyword : cluster.getKeywords()) {
        stmax = std::max(stmax, ST[keyword].count);
    }
    
    // 3. 计算目标长度
    size_t C = stmax + cmax;
    
    // 4. 为每个已出现的关键词执行填充
    for (const auto& keyword : cluster.getKeywords()) {
        if (ST[keyword].flag) {
            DocumentList Dw;
            
            // 添加虚假文档
            size_t paddingNeeded = cmax - cw[keyword];
            for (size_t i = 0; i < paddingNeeded; i++) {
                Dw.push_back(B.getBogusDocument(keyword));
            }
            
            // 添加缓存的真实文档
            auto cachedDocs = cluster.getDocuments(keyword);
            Dw.insert(Dw.end(), cachedDocs.begin(), cachedDocs.end());
            
            // 更新搜索状态
            ST[keyword].count = C;
            
            // 将结果添加到返回列表
            D.insert(D.end(), Dw.begin(), Dw.end());
        }
    }
    
    return D;
}

void BMSchemePlus::reencryptCluster(Cluster& cluster) {
    // 对簇中的每个关键词进行处理
    for (const auto& keyword : cluster.getKeywords()) {
        // 1. 从EDB获取该关键词的所有数据
        auto res = fetchKeywordData(keyword);
        auto& [encryptedIndex, lookupTable, encryptedDocs] = res;
        
        // 2. 解密所有文档并过滤
        std::vector<Document> realDocs;
        for (const auto& encDoc : encryptedDocs) {
            Document doc = decryptDocument(encDoc);
            // 保留非虚假且未被标记删除的文档
            if (!doc.isBogus && documentsToDelete_.count(doc.id) == 0) {
                realDocs.push_back(doc);
            }
        }
        
        // 3. 按层级分组并随机打乱
        std::map<AccessLevel, std::vector<Document>> levelDocs;
        for (const auto& doc : realDocs) {
            levelDocs[doc.level].push_back(doc);
        }
        
        for (auto& [_, docs] : levelDocs) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::shuffle(docs.begin(), docs.end(), gen);
        }
        
        // 4. 重新填充
        std::vector<Document> allDocs;
        for (const auto& [_, docs] : levelDocs) {
            allDocs.insert(allDocs.end(), docs.begin(), docs.end());
        }
        
        // 计算需要填充的数量
        size_t realCount = allDocs.size();
        size_t targetCount = std::max(realCount, searchTable_[keyword].count);
        size_t paddingNeeded = targetCount - realCount;
        
        // 添加虚假文档
        for (size_t i = 0; i < paddingNeeded; i++) {
            allDocs.push_back(paddingDataset_.getBogusDocument(keyword));
        }
        
        // 5. 重新加密文档并构建索引
        std::vector<EncryptedDocument> newEncryptedDocs;
        for (const auto& doc : allDocs) {
            newEncryptedDocs.push_back(encryptDocument(doc));
        }
        
        // 构建新的索引
        std::map<Keyword, std::vector<Document>> keywordMap;
        keywordMap[keyword] = allDocs;
        auto [newIndex, newTable] = buildIndex(keywordMap);
        
        // 6. 上传到EDB
        uploadKeywordData(keyword, newIndex, newTable, newEncryptedDocs);
        
        // 7. 从删除列表中移除已处理的文档
        for (const auto& doc : realDocs) {
            documentsToDelete_.erase(doc.id);
        }
    }
}

EncryptedList BMSchemePlus::fetchKeywordData(const Keyword& keyword) {
    httplib::Client cli(server_url_);
    
    // 使用 GET 请求获取关键词数据
    auto res = cli.Get("/get-keyword-data/" + keyword);
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to fetch keyword data from EDB");
    }
    
    auto response = nlohmann::json::parse(res->body);
    return EncryptedList{
        response["encryptedIndex"].get<EncryptedIndex>(),
        response["lookupTable"].get<LookupTable>(),
        response["encryptedDocs"].get<std::vector<EncryptedDocument>>()
    };
}

void BMSchemePlus::uploadKeywordData(
    const Keyword& keyword,
    const EncryptedIndex& index,
    const LookupTable& table,
    const std::vector<EncryptedDocument>& docs) {
    
    httplib::Client cli(server_url_);
    
    nlohmann::json request = {
        {"keyword", keyword},
        {"newNodes", index},         // 匹配服务器端的字段名
        {"lookupTable", table},
        {"encryptedDocs", docs}
    };
    
    auto res = cli.Post("/update-index", request.dump(), "application/json");
    if (!res || res->status != 200) {
        throw std::runtime_error("Failed to upload keyword data to EDB");
    }
}