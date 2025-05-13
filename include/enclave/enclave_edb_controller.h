#pragma once
#include "utils/types.h"
#include "enclave/crypto_sgx.h"
#include "enclave/sgx_serializer.h"

#include <vector>
#include <string>
#include <map>
#include <stdexcept>

// EDBController 接口封装
class EnclaveEDBController {
public:
    EnclaveEDBController() = default;
    
    // 搜索功能
    std::vector<std::pair<std::string, std::string>> search(const SearchToken& token, size_t max_doc = 0);
    
    // 更新索引
    void updateIndex(const Keyword& keyword, 
                    const std::vector<IndexNode>& newNodes, 
                    const LookupTable& newTable,
                    const std::vector<EncryptedDocument>& newEncryptedDocs);
    
    // 获取关键字数据
    EncryptedList getKeywordData(const Keyword& keyword);
    
private:
    // 序列化和反序列化函数
    std::string serializeSearchToken(const SearchToken& token);
    std::vector<std::pair<std::string, std::string>> deserializeSearchResults(const uint8_t* data, size_t size);
    std::string serializeIndexNodes(const std::vector<IndexNode>& nodes);
    std::string serializeLookupTable(const LookupTable& table);
    std::string serializeEncryptedDocuments(const std::vector<EncryptedDocument>& docs);
    EncryptedList deserializeEncryptedList(const uint8_t* data, size_t size);
};

