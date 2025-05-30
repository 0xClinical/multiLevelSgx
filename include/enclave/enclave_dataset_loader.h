#pragma once
#include "utils/types.h"
#include "enclave/sgx_serializer.h"
#include <vector>
#include <string>
#include <stdexcept>


class EnclaveDatasetLoader {
public:
    EnclaveDatasetLoader() = default;
    
    
    Document getBogusDocument(const Keyword& keyword, State maxState = 10, AccessLevel maxLevel = 3);
    
  
    std::vector<ClusterData> getAllClusters();
    
private:
   
    Document deserializeDocument(const uint8_t* data, size_t size);
    
 
    std::vector<ClusterData> deserializeClusters(const uint8_t* data, size_t size);
};
