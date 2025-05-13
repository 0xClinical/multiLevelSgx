#pragma once
#include "utils/types.h"
#include "utils/crypto.h"
class EDBController {
public:

    EDBController() = default;
    // 搜索功能
    std::vector<std::pair<std::string, std::string>> 
    search(const SearchToken& token,size_t max_doc = 0);
    
    // 更新索引功能
    void updateIndex(const Keyword& keyword, 
                    const std::vector<IndexNode>& newNodes, 
                    const LookupTable& newTable,
                    const std::vector<EncryptedDocument>& newEncryptedDocs);
    //获取索引和加密的文档功能
    EncryptedList getKeywordData(const Keyword& keyword);
private:
    
    std::map<Keyword, EncryptedList> keywordLists_;  // 每个关键字的文件链表
};
