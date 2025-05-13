#include "enclave/enclave_dataset_loader.h"
#include "Enclave_t.h"
#include "sgx_trts.h"

// 创建全局实例
EnclaveDatasetLoader g_dataset_loader;

Document EnclaveDatasetLoader::getBogusDocument(const Keyword& keyword, State maxState, AccessLevel maxLevel) {
    // 准备接收文档的缓冲区
    const size_t MAX_DOC_SIZE = 1*1024*1024; // 1MB 应该足够存储一个文档
    uint8_t* doc_buffer = new uint8_t[MAX_DOC_SIZE];
    size_t actual_size = 0;
    
    // 调用 OCALL
    ocall_dataset_get_bogus_document(keyword.c_str(), maxState, maxLevel, 
                                   doc_buffer, MAX_DOC_SIZE, &actual_size);
    
    // 反序列化文档
    Document doc;
    if (actual_size > 0) {
        doc = deserializeDocument(doc_buffer, actual_size);
    }
    
    delete[] doc_buffer;
    return doc;
}

std::vector<ClusterData> EnclaveDatasetLoader::getAllClusters() {
    // 准备接收数据的缓冲区
    const size_t MAX_DATA_SIZE = 400 * 1024 * 1024; // 400MB
    uint8_t* data_buffer = new uint8_t[MAX_DATA_SIZE];
    size_t actual_size = 0;
    
    // 调用 OCALL
    ocall_dataset_get_all_clusters(data_buffer, MAX_DATA_SIZE, &actual_size);
    
    // 反序列化簇数据
    std::vector<ClusterData> clusters;
    if (actual_size > 0) {
        clusters = deserializeClusters(data_buffer, actual_size);
    }
    
    delete[] data_buffer;
    return clusters;
}

Document EnclaveDatasetLoader::deserializeDocument(const uint8_t* data, size_t size) {
    // 验证输入数据在enclave内
    if (!sgx_is_within_enclave(data, size)) {
        throw std::runtime_error("Untrusted data source");
    }
    std::string json_str(reinterpret_cast<const char*>(data), size);
    SGXValue j = sgx_serializer::parse(json_str);
    
    Document doc;
    doc.id = j["id"].get_string();
    doc.level = j["level"].get_int();
    doc.state = j["state"].get_int();
    doc.isBogus = j["is_bogus"].get_bool();
    
    return doc;
}

std::vector<ClusterData> EnclaveDatasetLoader::deserializeClusters(const uint8_t* data, size_t size) {
    // 验证输入数据在enclave内
    if (!sgx_is_within_enclave(data, size)) {
        throw std::runtime_error("Untrusted data source");
    }
    std::string json_str(reinterpret_cast<const char*>(data), size);
    SGXValue j = sgx_serializer::parse(json_str);
    
    std::vector<ClusterData> clusters;
    for (size_t i = 0; i < j.size(); i++) {
        const auto& cluster_json = j[i];
        ClusterData cluster;
        
        // 反序列化关键词列表
        const SGXValue& keywords = cluster_json["keywords"];
        for (size_t k = 0; k < keywords.size(); k++) {
            const auto& keyword = keywords[k];
            cluster.keywords.push_back(keyword.get_string());
        }
        
        cluster.min_freq = cluster_json["min_freq"].get_size_t();
        cluster.max_freq = cluster_json["max_freq"].get_size_t();
        cluster.avg_freq = cluster_json["avg_freq"].get_size_t();
        cluster.threshold = cluster_json["threshold"].get_size_t();
        
        clusters.push_back(cluster);
    }
    
    return clusters;
} 