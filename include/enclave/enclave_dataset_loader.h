#pragma once
#include "utils/types.h"
#include "enclave/sgx_serializer.h"
#include <vector>
#include <string>
#include <stdexcept>

// DatasetLoader 接口封装
class EnclaveDatasetLoader {
public:
    EnclaveDatasetLoader() = default;
    
    // 获取虚假文档
    Document getBogusDocument(const Keyword& keyword, State maxState = 10, AccessLevel maxLevel = 3);
    
    // 获取所有簇
    std::vector<ClusterData> getAllClusters();
    
private:
    // 反序列化文档
    Document deserializeDocument(const uint8_t* data, size_t size);
    
    // 反序列化簇数据
    std::vector<ClusterData> deserializeClusters(const uint8_t* data, size_t size);
};
