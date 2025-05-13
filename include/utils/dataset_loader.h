#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <memory>
#include <random>
#include <fstream>
#include <algorithm>
#include <iostream>
#include <cstring>
#include "utils/types.h"
#include "utils/constants.h"


class DatasetLoader {
public:
    explicit DatasetLoader(const std::string& base_dir, uint32_t cluster_size) 
        : bogus_doc_counter_(0) {  // 初始化计数器
        loadDataset(base_dir, cluster_size);
    }

    // 获取指定关键词的所有文档
    std::vector<Document> getDocumentsByKeyword(const Keyword& keyword) const {
        std::cout << "getDocumentsByKeyword: " << keyword << std::endl;
        auto it = keyword_to_docs_.find(keyword);
        return it != keyword_to_docs_.end() ? it->second : std::vector<Document>();
    }

    // 获取指定关键词的指定数量的文档,如果文档数量不足则生成新文档补充
    std::vector<Document> getDocumentsByKeyword(const Keyword& keyword, size_t count) {
        auto documents = getDocumentsByKeyword(keyword);
        if(documents.size() < count){
            for(size_t i = documents.size(); i < count; i++){
                Document doc = getBogusDocument(keyword);
                doc.isBogus = false;
                documents.push_back(doc);
            }
        }
        std::cout << "getDocumentsByKeyword: " << keyword << " count: " << documents.size() << std::endl;
        return documents;
    }

    // 获取所有簇
    const std::vector<ClusterData>& getAllClusters() const {
        return clusters_;
    }

    // 通过ID获取文档
    std::optional<Document> getDocumentById(const DocumentId& doc_id) const {
        auto it = id_to_doc_.find(doc_id);
        return it != id_to_doc_.end() ? std::optional<Document>(it->second) : std::nullopt;
    }

    // 获取频率最高的N个关键词
    std::vector<std::pair<std::string, size_t>> getTopKeywords(size_t n = 10) const {
        std::vector<std::pair<std::string, size_t>> keywords;
        for (const auto& [keyword, docs] : keyword_to_docs_) {
            keywords.emplace_back(keyword, docs.size());
        }
        
        std::partial_sort(keywords.begin(), 
                         keywords.begin() + std::min(n, keywords.size()), 
                         keywords.end(),
                         [](const auto& a, const auto& b) { return a.second > b.second; });
        
        keywords.resize(std::min(n, keywords.size()));
        return keywords;
    }

    // 获取指定数量的随机文档
    std::vector<Document> getRandomDocuments(size_t count) const {
        if (count >= all_docs_.size()) return all_docs_;

        std::vector<Document> result;
        std::set<size_t> selected;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, all_docs_.size() - 1);

        while (result.size() < count) {
            size_t idx = dis(gen);
            if (selected.insert(idx).second) {
                result.push_back(all_docs_[idx]);
            }
        }
        return result;
    }
    // 获取数据集中的所有文档
    std::vector<Document> getAllDocuments() const {
        return all_docs_;
    }
    //获取文档的关键词
    Keyword getKeywordById(DocumentId doc_id) const {
        auto it = id_to_keyword_.find(doc_id);
        return it != id_to_keyword_.end() ? it->second : "";
    }

    // 获取虚假文档
    Document getBogusDocument(const Keyword& keyword,
                            State maxState = 10,
                            AccessLevel maxLevel = 3) {
        Document doc;
        doc.isBogus = true;
        
        // 生成文档ID: "Bogus" + 递增的计数
        doc.id = "Bogus" + std::to_string(++bogus_doc_counter_);

        // 生成随机数
        static std::random_device rd;
        static std::mt19937 gen(rd());
        
        // 生成随机层级 (1 到 maxLevel)
        std::uniform_int_distribution<AccessLevel> level_dist(1, maxLevel);
        doc.level = level_dist(gen);

        // 生成随机状态 (1 到 maxState)
        std::uniform_int_distribution<State> state_dist(1, maxState);
        doc.state = state_dist(gen);

        // 将虚假文档添加到索引中
        id_to_doc_[doc.id] = doc;
        all_docs_.push_back(doc);
        id_to_keyword_[doc.id] = keyword;
        keyword_to_docs_[keyword].push_back(doc);

        return doc;
    }

private:
    void loadDataset(const std::string& base_dir, uint32_t cluster_size) {
        std::string cluster_dir = getClusterPath(base_dir, cluster_size);
        
        // 1. 加载元数据
        loadMetadata(cluster_dir + "/metadata.bin");
        
        // 2. 加载关键词
        auto keywords = loadKeywords(cluster_dir + "/keywords.bin");
        
        // 3. 加载簇信息
        loadClusters(cluster_dir + "/clusters.bin", keywords);
        
        // 4. 加载文档
        loadDocuments(cluster_dir + "/keyword_doc_pairs.bin", keywords);
    }

    void loadMetadata(const std::string& path) {
        std::cout << "Attempting to open metadata file: " << path << std::endl;
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            int err = errno;
            std::cerr << "Error opening file: " << path << std::endl;
            std::cerr << "Error code: " << err << " - " << strerror(err) << std::endl;
            throw std::runtime_error("Cannot open metadata file: " + std::string(strerror(err)));
        }
        
        file.read(reinterpret_cast<char*>(&total_documents_), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&total_keywords_), sizeof(uint32_t));
        file.read(reinterpret_cast<char*>(&cluster_size_), sizeof(uint32_t));
    }

    std::vector<std::string> loadKeywords(const std::string& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open keywords file");
        
        uint32_t num_keywords;
        file.read(reinterpret_cast<char*>(&num_keywords), sizeof(uint32_t));
        
        std::vector<std::string> keywords;
        keywords.reserve(num_keywords);
        
        for (uint32_t i = 0; i < num_keywords; ++i) {
            uint32_t length;
            file.read(reinterpret_cast<char*>(&length), sizeof(uint32_t));
            
            std::string keyword(length, '\0');
            file.read(&keyword[0], length);
            keywords.push_back(keyword);
        }
        
        return keywords;
    }

    void loadClusters(const std::string& path, const std::vector<std::string>& keywords) {
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open clusters file");
        
        uint32_t num_clusters;
        file.read(reinterpret_cast<char*>(&num_clusters), sizeof(uint32_t));
        
        clusters_.reserve(num_clusters);
        
        for (uint32_t i = 0; i < num_clusters; ++i) {
            uint32_t num_keywords;
            file.read(reinterpret_cast<char*>(&num_keywords), sizeof(uint32_t));
            
            ClusterData cluster;
            cluster.keywords.reserve(num_keywords);
            
            for (uint32_t j = 0; j < num_keywords; ++j) {
                uint32_t keyword_id;
                file.read(reinterpret_cast<char*>(&keyword_id), sizeof(uint32_t));
                cluster.keywords.push_back(keywords[keyword_id]);
            }
            
            file.read(reinterpret_cast<char*>(&cluster.min_freq), sizeof(float));
            file.read(reinterpret_cast<char*>(&cluster.max_freq), sizeof(float));
            file.read(reinterpret_cast<char*>(&cluster.avg_freq), sizeof(float));
            file.read(reinterpret_cast<char*>(&cluster.threshold), sizeof(uint32_t));
            
            clusters_.push_back(std::move(cluster));
        }
    }

    void loadDocuments(const std::string& path, const std::vector<std::string>& keywords) {
        std::ifstream file(path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open documents file");
        
        uint32_t num_pairs;
        file.read(reinterpret_cast<char*>(&num_pairs), sizeof(uint32_t));
        
        for (uint32_t i = 0; i < num_pairs; ++i) {
            // 读取关键词ID
            uint32_t keyword_id;
            file.read(reinterpret_cast<char*>(&keyword_id), sizeof(uint32_t));
            const std::string& keyword = keywords[keyword_id];
            
            // 读取文档信息
            Document doc;
            
            // 读取文档ID
            uint32_t id_length;
            file.read(reinterpret_cast<char*>(&id_length), sizeof(uint32_t));
            doc.id.resize(id_length);
            file.read(&doc.id[0], id_length);
            
            // 读取level和state
            file.read(reinterpret_cast<char*>(&doc.level), sizeof(uint8_t));
            file.read(reinterpret_cast<char*>(&doc.state), sizeof(uint8_t));
            
            // 更新索引
            id_to_doc_[doc.id] = doc;
            all_docs_.push_back(doc);
            id_to_keyword_[doc.id] = keyword;
            
            // 添加到关键词-文档映射
            keyword_to_docs_[keyword].push_back(doc);
        }
    }

    static std::string getClusterPath(const std::string& base_dir, uint32_t cluster_size) {
        return base_dir + "/cluster_" + std::to_string(cluster_size);
    }

private:
    uint32_t total_documents_;
    uint32_t total_keywords_;
    uint32_t cluster_size_;
    
    std::vector<Document> all_docs_;
    std::vector<ClusterData> clusters_;
    std::unordered_map<DocumentId, Document> id_to_doc_;
    std::unordered_map<DocumentId, Keyword> id_to_keyword_;
    std::unordered_map<Keyword, std::vector<Document>> keyword_to_docs_;
    mutable size_t bogus_doc_counter_;  // 虚假文档ID计数器
};

// 在类定义之后，声明全局变量
extern DatasetLoader dataset_loader;