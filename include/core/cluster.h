#pragma once

#include <set>
#include <map>
#include <vector>
#include <string>
#include "utils/types.h"

class Cluster {
public:
    // 构造函数
    Cluster(size_t threshold, size_t maxLevel) 
        : threshold_(threshold), maxLevel_(maxLevel), firstBatch_(true) {}
    
    // 添加关键字到簇
    void addKeyword(const Keyword& keyword) {
        keywords_.insert(keyword);
        keywordFlags_[keyword] = false;  // 初始化标记为未出现
    }
    
    // 添加文档
    void addDocument(const Document& doc) {
        for (const auto& keyword : doc.keywords) {
            if (keywords_.count(keyword) > 0) {
                documents_[keyword].push_back(doc);
                docCount_[keyword]++;
                keywordFlags_[keyword] = true;  // 标记关键词已出现
                usedDocIds_.insert(doc.id);  // 记录文档ID
            }
        }
        capacity_++;
    }
    
    // 检查是否所有关键词都已出现（用于第一批检查）
    bool allKeywordsPresent() const {
        return std::all_of(keywordFlags_.begin(), keywordFlags_.end(),
                          [](const auto& pair) { return pair.second; });
    }
    
    // 获取关键词是否出现的标记
    bool getKeywordFlag(const Keyword& keyword) const {
        auto it = keywordFlags_.find(keyword);
        return it != keywordFlags_.end() ? it->second : false;
    }
    
    // 设置不再是第一批
    void setNotFirstBatch() { firstBatch_ = false; }
    
    // 是否是第一批
    bool isFirstBatch() const { return firstBatch_; }
    
    // 获取簇的容量
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
    
    // 获取已使用的所有文档ID
    const std::set<DocumentId>& getUsedDocIds() const {
        return usedDocIds_;
    }
    
    // 清空簇
    void clear() {
        documents_.clear();
        docCount_.clear();
        keywordFlags_.clear();
        usedDocIds_.clear();  // 清空ID记录
        capacity_ = 0;
        // 重置关键词出现标记，但保持关键词集合
        for (auto& [keyword, flag] : keywordFlags_) {
            flag = false;
        }
        firstBatch_ = true;
    }

private:
    std::set<Keyword> keywords_;                                      // 簇中的关键字集合
    std::map<Keyword, std::vector<Document>> documents_;             // 关键字到文档的映射
    std::map<Keyword, size_t> docCount_;                            // 关键字对应的文档数量
    std::map<Keyword, bool> keywordFlags_;                          // 关键字是否出现的标记
    size_t capacity_{0};                                            // 当前容量
    size_t threshold_;                                              // 阈值
    size_t maxLevel_;                                              // 最大层级
    bool firstBatch_;                                              // 是否是第一批
    std::set<DocumentId> usedDocIds_;  // 记录簇中所有已使用的文档ID
}; 