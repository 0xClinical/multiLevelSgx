#pragma once
#include "utils/types.h"
#include "enclave/crypto_sgx.h"
#include "enclave/sgx_serializer.h"

#include <vector>
#include <string>
#include <map>
#include <stdexcept>


class EnclaveEDBController {
public:
    EnclaveEDBController() = default;
    

    std::vector<std::pair<std::string, std::string>> search(const SearchToken& token, size_t max_doc = 0);
    
  
    void updateIndex(const Keyword& keyword, 
                    const std::vector<IndexNode>& newNodes, 
                    const LookupTable& newTable,
                    const std::vector<EncryptedDocument>& newEncryptedDocs);
    
   
    EncryptedList getKeywordData(const Keyword& keyword);
    
private:
  
    std::string serializeSearchToken(const SearchToken& token);
    std::vector<std::pair<std::string, std::string>> deserializeSearchResults(const uint8_t* data, size_t size);
    std::string serializeIndexNodes(const std::vector<IndexNode>& nodes);
    std::string serializeLookupTable(const LookupTable& table);
    std::string serializeEncryptedDocuments(const std::vector<EncryptedDocument>& docs);
    EncryptedList deserializeEncryptedList(const uint8_t* data, size_t size);
};

