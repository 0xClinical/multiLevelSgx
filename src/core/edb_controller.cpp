#include "core/edb_controller.h"
#include <iostream>

EDBController::EDBController() {}

std::vector<std::pair<std::string, std::string>> 
EDBController::search(const SearchToken& token) {
    std::vector<std::pair<std::string, std::string>> results;
    
    // 遍历所有关键字的链表
    for (const auto& [keyword, list] : keywordLists_) {
        // 检查当前查找表是否存在入口点
        if (list.lookupTable.find(token.tau2) == list.lookupTable.end()) {
            continue;  // 当前关键字不匹配，继续检查下一个
        }
        
        // 找到匹配的查找表，执行搜索
        size_t addr = list.lookupTable.at(token.tau2) ^ std::stoull(token.tau3);
        std::string z0 = token.tau1;
        
        // 遍历链表
        while (addr != 0) {  // 0表示链表结束
            const IndexNode& node = list.encryptedIndex[addr];
            
            // 解析节点
            std::string Eid = node.a1;
            auto [next_addr, z1] = node.a2;
            std::string r = node.a3;
            std::string z2 = node.a4;
            std::string digest = node.a5;
            
            // 计算下一个地址
            addr = next_addr ^ std::stoull(CryptoUtils::H2(z0, r));
            
            // 尝试所有状态密钥
            bool flag = false;
            std::string res;
            
            for (const std::string& tau4_c : token.tau4) {
                std::string tmp = CryptoUtils::xorStrings(Eid, tau4_c);
                
                // 验证解密是否正确
                if (CryptoUtils::computeDigest(tmp) == digest) {
                    flag = true;
                    res = CryptoUtils::xorStrings(tmp, CryptoUtils::H2(z0, r));
                    break;
                }
            }
            
            if (!flag) {
                continue;  // 无法用任何状态密钥解密
            }
            
            // 更新z0
            z0 = CryptoUtils::xorStrings(z1, CryptoUtils::H2(z0, r));
            
            // 添加到结果集
            results.emplace_back(res, z2);
        }
        
        // 找到匹配的关键字后就可以返回了
        return results;
    }
    
    return results;  // 如果没有找到任何匹配的关键字，返回空结果
}

void EDBController::updateIndex(const Keyword& keyword, 
                              const std::vector<IndexNode>& newNodes, 
                              const LookupTable& newTable,
                              const std::vector<DocumentId>& newEncryptedDocs) {
    keywordLists_[keyword].encryptedIndex = newNodes;
    keywordLists_[keyword].lookupTable = newTable;
    keywordLists_[keyword].docs = newEncryptedDocs;
}

EncryptedList EDBController::getKeywordData(const Keyword& keyword) {
    auto it = keywordLists_.find(keyword);
    if (it != keywordLists_.end()) {
        return {
            it->second.encryptedIndex,
            it->second.lookupTable,
            it->second.docs
        };
    }
    return {}; // 返回空数据
}

