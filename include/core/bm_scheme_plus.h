#pragma once
#include "core/bm_scheme.h"
#include <httplib.h>
#include "core/cache_controller.h"

class BMSchemePlus : public BMScheme {
public:
    BMSchemePlus(const std::string& token_url, 
                 const std::string& server_url,
                 bool isPersistentAdversary = false)
        : BMScheme(token_url, server_url)
        , isPersistentAdversary_(isPersistentAdversary) {
             // 初始化 Cache Controller
        cacheController_ = std::make_unique<CacheController>();
        
        // 设置刷新回调
        cacheController_->setRefreshCallback([this](Cluster& cluster) {
            // 即使未达到阈值也执行填充检查
            auto D = paddingCheck({}, {cluster}, paddingDataset_);
            
            // 如果有需要处理的数据，构建索引并上传
            if (!D.empty()) {
                for (const auto& Dw : D) {
                    if (!Dw.empty()) {
                        std::map<Keyword, std::vector<Document>> keywordMap;
                        for (const auto& doc : Dw) {
                            for (const auto& keyword : doc.keywords) {
                                keywordMap[keyword].push_back(doc);
                            }
                        }
                        auto [index, table] = buildIndex(keywordMap);
                        // 上传到EDB
                        for (const auto& [keyword, docs] : keywordMap) {
                            uploadKeywordData(keyword, index, table, 
                                encryptDocuments(docs));
                        }
                    }
                }
                // 清空已处理的簇
                cluster.clear();
            }
        });
        }

    // 重写上传文档方法
    void uploadDocument(const Document& doc) override;
    void uploadDocuments(const std::vector<Document>& docs) override;

    // 重加密指定簇
    void reencryptCluster(Cluster& cluster);
    
    // 添加要删除的文档ID
    void addDocumentToDeleteList(const DocumentId& docId) {
        documentsToDelete_.insert(docId);
    }
    //获取缓存控制器
    CacheController& getCacheController() {
        return *cacheController_;
    }
    ~BMSchemePlus() {
        cacheController_->stopRefreshTimer();
    }

private:
    // 填充检查
    std::vector<DocumentList> paddingCheck(
        const std::vector<Document>& M,
        const std::vector<Cluster>& clusters,
        PaddingDataset& B);

    // 填充操作
    DocumentList padding(
        const Cluster& cluster,
        std::map<Keyword, SearchState>& ST,
        PaddingDataset& B);

    // 从EDB获取簇数据的辅助方法
    EncryptedList fetchKeywordData(const Keyword& keyword);

    // 上传关键词数据到EDB
    void uploadKeywordData(
        const Keyword& keyword,
        const EncryptedIndex& index,
        const LookupTable& table,
        const std::vector<EncryptedDocument>& docs);

    bool isPersistentAdversary_;
    std::vector<Cluster> clusters_;      // 簇      
    std::map<Keyword, SearchState> searchTable_;  // ST
    PaddingDataset paddingDataset_;              // B
    std::set<DocumentId> documentsToDelete_;  // 待删除文档ID表
    std::unique_ptr<CacheController> cacheController_;

    // 批量加密文档
    std::vector<EncryptedDocument> encryptDocuments(const std::vector<Document>& docs) {
        std::vector<EncryptedDocument> encryptedDocs;
        for (const auto& doc : docs) {
            encryptedDocs.push_back(encryptDocument(doc));
        }
        return encryptedDocs;
    }
};

// 搜索状态
struct SearchState {
    bool flag{false};    // 关键词是否出现过
    size_t count{0};     // 关键词出现次数
};

// 文档列表类型
using DocumentList = std::vector<Document>;
