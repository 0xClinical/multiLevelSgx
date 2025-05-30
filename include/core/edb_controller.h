#pragma once
#include "utils/types.h"
#include "utils/crypto.h"
class EDBController {
public:

    EDBController() = default;
   
    std::vector<std::pair<std::string, std::string>> 
    search(const SearchToken& token,size_t max_doc = 0);
    
   
    void updateIndex(const Keyword& keyword, 
                    const std::vector<IndexNode>& newNodes, 
                    const LookupTable& newTable,
                    const std::vector<EncryptedDocument>& newEncryptedDocs);

    EncryptedList getKeywordData(const Keyword& keyword);
private:
    
    std::map<Keyword, EncryptedList> keywordLists_;  
};
