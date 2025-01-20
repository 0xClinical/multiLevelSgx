#pragma once

#include <map>
#include <vector>
#include <random>
#include "utils/types.h"
#include "utils/crypto.h"

class PaddingDataset {
public:
    // 构造函数，指定初始大小和最大层级
    PaddingDataset(size_t initialSize = 1000, size_t maxLevel = 5) 
        : initialSize_(initialSize), maxLevel_(maxLevel) {
        initializeDataset();
    }
    
    // 获取指定关键词的虚假文档
    Document getBogusDocument(const Keyword& keyword)    {
        if (bogusDocuments_[keyword].empty()) {
            // 如果该关键词的虚假文档用完，生成新的批次
            generateBogusDocuments(keyword, initialSize_);
        }
        
        // 获取并移除最后一个文档
        Document doc = bogusDocuments_[keyword].back();
        bogusDocuments_[keyword].pop_back();
        return doc;
    }
    
    // 为关键词生成指定数量的虚假文档
    void generateBogusDocuments(const Keyword& keyword, size_t count) {
        for (size_t i = 0; i < count; i++) {
            Document doc;
            doc.id = generateBogusId();
            doc.level = generateBogusLevel();
            doc.state = generateBogusState();
            doc.keywords.insert(keyword);
            // 标记为虚假文档
            doc.isBogus = true;
            
            bogusDocuments_[keyword].push_back(doc);
        }
    }
    
    // 获取指定关键词的可用虚假文档数量
    size_t getAvailableCount(const Keyword& keyword) const {
        auto it = bogusDocuments_.find(keyword);
        return it != bogusDocuments_.end() ? it->second.size() : 0;
    }
    
    // 清空数据集
    void clear() {
        bogusDocuments_.clear();
    }

private:
    // 初始化数据集
    void initializeDataset() {
        // 初始化随机数生成器
        std::random_device rd;
        rng_ = std::mt19937(rd());
    }
    
    // 生成虚假文档ID
    std::string generateBogusId() const {
        return "bogus_" + CryptoUtils::generateRandomString(16);
    }
    
    // 生成虚假层级
    AccessLevel generateBogusLevel() {
        std::uniform_int_distribution<> levelDist(0, maxLevel_ - 1);
        return static_cast<AccessLevel>(levelDist(rng_));
    }
    
    // 生成虚假状态
    State generateBogusState() {
        // 使用当前时间生成状态
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
        return static_cast<State>(minutes / 60);  // 每小时一个状态
    }

private:
    std::map<Keyword, std::vector<Document>> bogusDocuments_;  // 关键词到虚假文档的映射
    size_t initialSize_;                                       // 初始数据集大小
    size_t maxLevel_;                                         // 最大层级
    std::mt19937 rng_;                                        // 随机数生成器
}; 