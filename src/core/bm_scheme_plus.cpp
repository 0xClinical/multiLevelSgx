#include "core/bm_scheme_plus.h"

void BMSchemePlus::uploadDocument(const Keyword& keyword, const Document& doc) {
    // 创建一个只包含单个关键词/文档对的 vector
    std::vector<std::pair<Keyword, Document>> pairs = {{keyword, doc}};
    uploadDocuments(pairs);
}

void BMSchemePlus::uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs) {
    // 1. 执行填充检查
    auto D = paddingCheck(pairs);
    // 2. 如果没有需要处理的数据，直接返回
    if (D.empty()) {
        return;
    }
    
    for (const auto& [keyword, docs] : D) {
        rebuildIndexForKeyword(keyword, docs);
    }
}

std::map<Keyword, DocumentList> BMSchemePlus::paddingCheck(
    const std::vector<std::pair<Keyword, Document>>& pairs) {
    
    // 用于记录被修改的簇的索引
    std::set<size_t> modified_clusters;
    ocall_print_string("before paddingcheck");
    ocall_print_string(std::to_string(pairs.size()).c_str());
    // 1. 将文件推送到对应的簇
    for (const auto& [keyword, doc] : pairs) {
        auto cluster_idx = keyword_to_cluster_.find(keyword);
        if (cluster_idx != keyword_to_cluster_.end()) {
            clusters_[cluster_idx->second].addDocument(keyword,doc);
            searchTable_[keyword].flag = true;
            modified_clusters.insert(cluster_idx->second);  // 记录被修改的簇
        }
    }
    std::map<Keyword, DocumentList> D;
    
    // 2. 根据对手类型执行不同的填充策略
    if (!isPersistentAdversary_) {
        // 只遍历被修改的簇
        for (size_t idx : modified_clusters) {
            auto& cluster = clusters_[idx];
            if (cluster.capacity() >= cluster.threshold()) {
                bool skipCluster = false;
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        skipCluster = true;
                        break;
                    }
                }
                
                if (!skipCluster) {
                    auto cluster_results = padding(cluster);
                    D.insert(cluster_results.begin(), cluster_results.end());
                    cluster.clear();
                }
            }
        }
    } else {
        // 只遍历被修改的簇
        for (size_t idx : modified_clusters) {
            auto& cluster = clusters_[idx];
            if (cluster.isFirstBatch()) {
                bool allKeywordsPresent = true;
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        allKeywordsPresent = false;
                        break;
                    }
                }
                
                if (allKeywordsPresent) {
                    auto cluster_results = padding(cluster);
                    D.insert(cluster_results.begin(), cluster_results.end());
                    cluster.setNotFirstBatch();
                    cluster.clear();
                }
            } else if (cluster.capacity() >= cluster.threshold()) {
                auto cluster_results = padding(cluster);
                D.insert(cluster_results.begin(), cluster_results.end());
                cluster.clear();
            }
        }
    }
    
    return D;
}

std::map<Keyword, DocumentList> BMSchemePlus::padding(
    const Cluster& cluster) {
    
    std::map<Keyword, DocumentList> D;
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
        stmax = std::max(stmax, searchTable_[keyword].count);
    }
    
    // 3. 计算目标长度
    size_t C = stmax + cmax;
    // 4. 为每个已出现的关键词执行填充
    for (const auto& keyword : cluster.getKeywords()) {
        if (searchTable_[keyword].flag) {
            DocumentList& Dw = D[keyword];  // 直接在map中创建/获取文档列表
            
            // 添加虚假文档
            size_t paddingNeeded = cmax - cw[keyword];
            for (size_t i = 0; i < paddingNeeded; i++) {
                Dw.push_back(g_dataset_loader.getBogusDocument(keyword, currentState_));
            }
            
            // 添加缓存的真实文档
            auto cachedDocs = cluster.getDocuments(keyword);
            Dw.insert(Dw.end(), cachedDocs.begin(), cachedDocs.end());
            
            // 更新搜索状态
            searchTable_[keyword].count = C;
        }
    }

    
    return D;
}

void BMSchemePlus::reencryptCluster(Cluster& cluster) {
    // 实现重加密簇的逻辑
    // 1. 获取簇中的所有关键词
    const std::set<Keyword>& keywords = cluster.getKeywords();
    std::vector<std::pair<Keyword, Document>> allPairs;
    // 2. 对每个关键词进行重加密
    for (const auto keyword : keywords) {
        // 2.1 从edb中获取关键词对应的文档列表
        EncryptedList keywordData = edb_controller.getKeywordData(keyword);
        for (const auto& encDoc : keywordData.documents) {
            Document doc = decryptDocument(encDoc);
            
            if (doc.isBogus == true) {
                continue;
            }
            if(documentsToDelete_[doc.id] == true){
                documentsToDelete_.erase(doc.id);
                continue;
            }
            allPairs.push_back(std::make_pair(keyword, doc));
        }
        
         
        ocall_print_string("after delete allpairs");
        ocall_print_string(decryptDocument(keywordData.documents[0]).id.c_str());
        
        
        
    }
    uploadDocuments(allPairs);
    
}

std::vector<std::string> BMSchemePlus::searchWithToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword, const SearchToken& token, size_t max_doc) {
    // 实现搜索方法的逻辑
    // 解密用户ID
    
    // 1. 从edb中获取结果
    std::vector<std::pair<std::string, std::string>> results = edb_controller.search(token, max_doc);
   
    // 2. 解密结果
    std::vector<std::string> decryptedResults = decryptSearchResults(results);
  
    //4.从本地簇中找出关键字对应的文档且这些文档满足用户的状态和层级
    std::vector<std::string> localResults;
    auto it = keyword_to_cluster_.find(hashedKeyword);
    if (it != keyword_to_cluster_.end()) {
        for(const auto& doc : clusters_[it->second].getDocuments(hashedKeyword)){
            if(doc.state <= userTable_[userId].state && doc.level <= userTable_[userId].level){
                localResults.push_back(doc.id);
            }
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


void BMSchemePlus::deleteDocument(const Keyword& keyword, DocumentId docId) {
    // 1. 通过关键词找到对应的簇
    auto clusterIt = keyword_to_cluster_.find(keyword);
    if (clusterIt == keyword_to_cluster_.end()) {
        // 如果找不到对应的簇，直接添加到待删除列表
        documentsToDelete_[docId] = true;
        return;
    }
    
    // 2. 尝试从簇的缓存中删除文档
    Cluster& cluster = clusters_[clusterIt->second];
    bool deletedFromCache = cluster.removeDocument(keyword, docId);
    
    documentsToDelete_[docId] = true;
    
}

void BMSchemePlus::deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs) {
    // 按关键字分组需要删除的文档ID
    std::map<Keyword, std::vector<DocumentId>> keywordToDocIds;
    for (const auto& [keyword, docId] : pairs) {
        keywordToDocIds[keyword].push_back(docId);
    }
    // 对每个关键字分别处理
    for (const auto& [keyword, docIds] : keywordToDocIds) {
        // 1. 找到对应的簇
        auto clusterIt = keyword_to_cluster_.find(keyword);
        if (clusterIt == keyword_to_cluster_.end()) {
            // 如果找不到对应的簇，直接添加到待删除列表
            for (const auto& docId : docIds) {
                documentsToDelete_[docId] = true;
            }
            continue;
        }
        
        // 2. 尝试从簇的缓存中删除文档
        Cluster& cluster = clusters_[clusterIt->second];
        for (const auto& docId : docIds) {
            bool deletedFromCache = cluster.removeDocument(keyword, docId);
            // 3. 如果簇中没有这个文档，添加到待删除列表
            
                documentsToDelete_[docId] = true;
            
        }
    }
    ocall_print_string("delete documents size");
    ocall_print_string(std::to_string(documentsToDelete_.size()).c_str());
}

void BMSchemePlus::initializeClusters() {
    // 使用g_dataset_loader获取簇信息
    std::vector<ClusterData> clusterData = g_dataset_loader.getAllClusters();
    
    // 初始化簇
    clusters_.clear();
    keyword_to_cluster_.clear();
    
    for (const auto& data : clusterData) {
        // 使用正确的构造函数创建簇
        Cluster cluster(data.threshold, 3);  // 假设最大层级为3，您可以根据需要调整
        
        // 添加关键词到簇
        for (const auto& keyword : data.keywords) {
            cluster.addKeyword(keyword);
        }
        
        // 将簇添加到集合中
        size_t clusterIndex = clusters_.size();
        clusters_.push_back(cluster);
        
        // 更新关键词到簇的映射
        for (const auto& keyword : data.keywords) {
            keyword_to_cluster_[keyword] = clusterIndex;
        }
    }
}
