#pragma once
#include <set>
#include <map>
#include <vector>
#include "utils/types.h"
#include "sgx_tae_service.h"  // 包含SGX可信时间服务
#include "sgx_error.h"        // SGX错误码定义

class Cluster {
public:
    // 构造函数：设置阈值和最大层级
    Cluster(size_t threshold, size_t maxLevel) 
        : threshold_(threshold)
        , maxLevel_(maxLevel)
        , firstBatch_(true)
        , capacity_(0)
        , lastActivityTime_(0) {}  // 初始化为0时间戳
    
    // 添加关键字到簇
    void addKeyword(const Keyword& keyword) {
        keywords_.insert(keyword);
    }
    
    // 添加文档到簇
    void addDocument(Keyword keyword,const Document& doc) {
        documents_[keyword].push_back(doc);
        docCount_[keyword]++;
        
        capacity_++;
        // 更新活动时间为当前时间
        uint8_t nonce_array[32];
        sgx_get_trusted_time(&lastActivityTime_, &nonce_array);
    }
    
    //删除文档
    bool removeDocument(const Keyword& keyword, DocumentId docId) {
        auto it = documents_.find(keyword);
        if (it != documents_.end()) {
            it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
                [docId](const Document& doc) { return doc.id == docId; }), it->second.end());
            return true;
        }
        return false;
    }
    // 获取簇的容量（当前文档数量）
    size_t capacity() const { return capacity_; }
    
    // 获取簇的阈值
    size_t threshold() const { return threshold_; }
    
    // 检查关键字是否在簇中
    bool containsKeyword(const Keyword& keyword) const {
        return keywords_.count(keyword) > 0;
    }
    
    // 获取簇中所有关键字
    const std::set<Keyword>& getKeywords() const { return keywords_; }
    
    // 获取关键字的文档数量
    size_t getKeywordCount(const Keyword& keyword) const {
        auto it = docCount_.find(keyword);
        return it != docCount_.end() ? it->second : 0;
    }
    
    // 获取关键字对应的所有文档
    std::vector<Document> getDocuments(const Keyword& keyword) const {
        auto it = documents_.find(keyword);
        return it != documents_.end() ? it->second : std::vector<Document>();
    }

    // 是否是第一批
    bool isFirstBatch() const { return firstBatch_; }
    
    // 设置不再是第一批
    void setNotFirstBatch() { firstBatch_ = false; }
    
    // 清空簇
    void clear() {
        documents_.clear();
        docCount_.clear();
        capacity_ = 0;
    }

    // 检查簇是否不活跃
    bool isInactive(uint32_t threshold_seconds) const {
        sgx_time_t current_time = 0;
        uint8_t nonce_array[32];
        if (sgx_get_trusted_time(&current_time, &nonce_array) != SGX_SUCCESS) {
            // 错误处理逻辑
            return false;
        }
        // 计算时间差（秒）
        return (current_time - lastActivityTime_) > threshold_seconds;
    }

private:
    std::set<Keyword> keywords_;                              // 簇中的关键字集合
    std::map<Keyword, std::vector<Document>> documents_;      // 关键字到文档的映射
    std::map<Keyword, size_t> docCount_;                     // 关键字对应的文档数量
    size_t capacity_{0};                                     // 当前容量
    size_t threshold_;                                       // 阈值
    size_t maxLevel_;                                        // 最大层级
    bool firstBatch_;                                        // 是否是第一批
    sgx_time_t lastActivityTime_;  // SGX可信时间戳
};