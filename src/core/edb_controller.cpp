#include "core/edb_controller.h"
#include <iostream>


std::vector<std::pair<std::string, std::string>> 
EDBController::search(const SearchToken& token, size_t max_doc) {
    std::vector<std::pair<std::string, std::string>> results;
    
    std::cout << "\n=== Starting Search ===\n";

    for (const auto& [keyword, list] : keywordLists_) {
        
        if (list.lookupTable.find(token.tau2) == list.lookupTable.end()) {
            std::cout << "No matching entry point found in this list\n";
            continue;
        }
        

        // 详细打印查找表中存储的值
        size_t stored = list.lookupTable.at(token.tau2);
       
        // 详细打印tau3转换后的值
        size_t tau3_num = CryptoUtils::stringToSize(token.tau3);
    
        // 详细打印异或结果（地址）
        size_t addr = stored ^ tau3_num;
    
        
        std::string z0 = token.tau1;
        
        // 遍历链表
        while (true) {
            // 检查是否达到最大结果数量限制
            if (max_doc > 0 && results.size() >= max_doc) {
                std::cout << "Reached maximum result limit (" << max_doc << "), stopping search\n";
                return results;
            }

            try {
                const IndexNode& node = list.encryptedIndex.at(addr);
          
                auto [next_addr, z1] = node.a2;
                
                // 如果存储的下一个地址为0，说明是链表末尾
                if (next_addr == 0) {
                    
                    
                    // 处理当前节点
                    std::string h2 = CryptoUtils::H2(z0, node.a3);
                    
                    bool flag = false;
                    std::string res;
                    
                    for (const auto& tau4_c : token.tau4) {
                        
                        std::string tmp = CryptoUtils::xorStrings(node.a1, tau4_c);
                       
                        
                        if (CryptoUtils::computeDigest(tmp) == node.a5) {
                            flag = true;
                            res = CryptoUtils::xorStrings(tmp, h2);
                            break;
                        }
                    }
                    
                    if (flag) {
                        results.emplace_back(res, node.a4);
                    }
                    break;
                }
                std::string h2 = CryptoUtils::H2(z0, node.a3);
                size_t h2_num = CryptoUtils::stringToSize(h2);
                
                // 计算下一个地址
                size_t next = next_addr ^ h2_num;
                
                // 尝试所有状态密钥
                bool flag = false;
                std::string res;
                
                for (const auto& tau4_c : token.tau4) {
                    std::string tmp = CryptoUtils::xorStrings(node.a1, tau4_c);
                    if (CryptoUtils::computeDigest(tmp) == node.a5) {
                        flag = true;
                        res = CryptoUtils::xorStrings(tmp, h2);
                        break;
                    }
                }
                
                if (flag) {
                    results.emplace_back(res, node.a4);
                   
                } else {
                   
                }
                
                // 更新地址继续遍历
                addr = next;
                z0 = CryptoUtils::xorStrings(z1, h2);
            } catch (const std::exception& e) {
                std::cout << "Error processing node: " << e.what() << "\n";
                break;
            }
        }
        
        std::cout << "results: " << results.size() << std::endl;
        return results;
    }
    
    std::cout << "No matching keyword lists found\n";
    return results;
}

void EDBController::updateIndex(const Keyword& keyword, 
                              const std::vector<IndexNode>& newNodes, 
                              const LookupTable& newTable,
                              const std::vector<DocumentId>& newEncryptedDocs) {

    keywordLists_[keyword].encryptedIndex = newNodes;
    keywordLists_[keyword].lookupTable = newTable;
    keywordLists_[keyword].documents = newEncryptedDocs;
 
}

EncryptedList EDBController::getKeywordData(const Keyword& keyword) {
    auto it = keywordLists_.find(keyword);
    if (it != keywordLists_.end()) {
       
        return {
            it->second.encryptedIndex,
            it->second.lookupTable,
            it->second.documents
        };
    }
    return {}; // 返回空数据
}

