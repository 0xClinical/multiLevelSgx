#pragma once
#include "core/bm_scheme.h"
#include <httplib.h>
#include "core/cache_controller.h"
#include "utils/constants.h"
#include <memory>
#include <unordered_map>
#include "enclave/enclave_dataset_loader.h"
class BMSchemePlus : public BMScheme {
public:
        BMSchemePlus(bool isPersistentAdversary = false)
        : BMScheme()
        , isPersistentAdversary_(isPersistentAdversary)
        , refreshThreshold_(3) {

        // 初始化数据集加载器
        g_dataset_loader = EnclaveDatasetLoader();
            // 初始化 Cache Controller
        cacheController_.reset(new CacheController());
        // 设置刷新回调
        cacheController_->setRefreshCallback([this](Cluster& cluster) {
           // 如果簇是空的，不需要处理
        if (cluster.capacity() == 0) {
            return;
        }

        // 检查簇的最后活动时间
        if (cluster.isInactive(refreshThreshold_ * 60)) {  // 转换为秒
            // 对于非持久性对手
            if (!isPersistentAdversary_) {
                bool skipCluster = false;
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        skipCluster = true;
                        break;
                    }
                }
                
                if (!skipCluster) {
                    auto results = padding(cluster);
                    // 构建索引并上传到EDB
                    for (const auto& pair : results) {
                        const auto& keyword = pair.first;
                        const auto& docs = pair.second;
                        rebuildIndexForKeyword(keyword, docs);
                    }
                    cluster.clear();
                }
            }
            // 对于持久性对手
            else {
                if (cluster.isFirstBatch()) {
                    bool allKeywordsPresent = true;
                    for (const auto& keyword : cluster.getKeywords()) {
                        if (!searchTable_[keyword].flag) {
                            allKeywordsPresent = false;
                            break;
                        }
                    }
                    
                    if (allKeywordsPresent) {
                        auto results = padding(cluster);
                        for (const auto& pair : results) {
                            const auto& keyword = pair.first;
                            const auto& docs = pair.second;
                            rebuildIndexForKeyword(keyword, docs);
                        }
                        cluster.setNotFirstBatch();
                        cluster.clear();
                    }
                } else {
                    auto results = padding(cluster);
                    for (const auto& pair : results) {
                        const auto& keyword = pair.first;
                        const auto& docs = pair.second;
                        rebuildIndexForKeyword(keyword, docs);
                    }
                        cluster.clear();
                    }
                }
            }
        });
    }

    // 重写上传文档方法
    void uploadDocument(const Keyword& keyword, const Document& doc) override;
    void uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs) override;

    // 重写删除文档方法
    void deleteDocument(const Keyword& keyword, DocumentId docId) override;
    void deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs) override;
    // 重写搜索方法
    std::vector<std::string> searchWithToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword, const SearchToken& token, size_t max_doc = 0) override;
    // 重加密指定簇
    void reencryptCluster(Cluster& cluster);
    
    // 添加要删除的文档ID
    void addDocumentToDeleteList(const DocumentId& docId) {
        documentsToDelete_[docId] = true;
    }
    //获取缓存控制器
    CacheController& getCacheController() {
        return *cacheController_;
    }
    ~BMSchemePlus() {
        cacheController_->stopRefreshTimer();
    }
    // 初始化簇
    void initializeClusters();
    // 获取关键词所属的簇
    Cluster* getClusterForKeyword(const Keyword& keyword) {
        auto it = keyword_to_cluster_.find(keyword);
        if (it != keyword_to_cluster_.end()) {
            return &clusters_[it->second];
        }
        return nullptr;
    }

    // 获取关键词所属的簇的索引
    std::pair<bool, size_t> getClusterIndexForKeyword(const Keyword& keyword) const {
        for (size_t i = 0; i < clusters_.size(); ++i) {
            if (clusters_[i].containsKeyword(keyword)) {
                return {true, i};
            }
        }
        return {false, 0};
    }

    // 添加获取簇的方法
    std::vector<Cluster>& getClusters() {
        return clusters_;
    }
   

private:
    EnclaveDatasetLoader g_dataset_loader;

    // 填充检查
    std::map<Keyword, DocumentList> paddingCheck(
    const std::vector<std::pair<Keyword, Document>>& pairs);

    // 填充操作
    std::map<Keyword, DocumentList> padding(
        const Cluster& cluster);

    bool isPersistentAdversary_;
    std::vector<Cluster> clusters_;      // 簇      
    std::map<Keyword, SearchState> searchTable_;  // ST
    std::map<DocumentId, bool> documentsToDelete_;  // 待删除文档ID表
    std::unique_ptr<CacheController> cacheController_;
    std::unordered_map<Keyword, size_t> keyword_to_cluster_;  // 关键词到簇索引的映射
    int refreshThreshold_;  // 刷新阈值
};
