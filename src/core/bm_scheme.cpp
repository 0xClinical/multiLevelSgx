#include "core/bm_scheme.h"
#include <iostream>
#include <algorithm>
#include <random>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <bitset>
#include <numeric>  
#include "sgx_trts.h"  



class SGXRandomGenerator {
public:
    using result_type = uint32_t;
    
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return UINT32_MAX; }
    
    result_type operator()() {
        result_type value;
        sgx_read_rand((unsigned char*)&value, sizeof(value));
        return value;
    }
};

std::pair<EncryptedIndex, LookupTable> 
BMScheme::buildIndex(const Keyword keyword_hash,const std::vector<Document>& docs) {
   
    std::vector<IndexNode> A;  
    LookupTable T;          
    
 
    std::vector<std::string> L; 
    std::vector<size_t> X;       
    std::vector<size_t> N;       
    std::vector<std::string> digest;  
    
    
    std::vector<Document> sortedDocs = docs;
    std::sort(sortedDocs.begin(), sortedDocs.end(),
                [](const Document& a, const Document& b) {
                    return a.level > b.level;
                });
 
  
    N.resize(sortedDocs.size());
    std::iota(N.begin(), N.end(), 0); 
    X.resize(4);

    SGXRandomGenerator rng;
    std::shuffle(N.begin(), N.end(), rng);
   
    A.resize(sortedDocs.size());

   
    size_t loc = 0;
    AccessLevel current_level = 0; 

    L.reserve(sortedDocs.size());
   
    for (const auto& doc : sortedDocs) {
        loc++;
        // Lωi ← Lωi ∪ {F1(kλ(id),1, id)}
        L.push_back(CryptoUtils::F1(levelKeys_[doc.level].key1, doc.id));
        
       
        if (doc.level != current_level) {
            X[doc.level] = loc;  
            current_level = doc.level;
        }
    }

    for (size_t j = 0; j < N.size() - 1; j++) {
      
       
        std::string r = CryptoUtils::generateRandomString();
     
       
        std::string z = CryptoUtils::H1(levelKeys_[sortedDocs[j].level].key2, keyword_hash);
        std::string z_next = CryptoUtils::H1(levelKeys_[sortedDocs[j+1].level].key2, keyword_hash);
        
      
        std::string h2 = CryptoUtils::H2(z, r);
        size_t h2_num = CryptoUtils::stringToSize(h2);

       
        digest.push_back(CryptoUtils::computeDigest(
            CryptoUtils::xorStrings(h2, L[j])));
  
   
        IndexNode node;
      
        node.a1 = CryptoUtils::xorStrings(
            CryptoUtils::xorStrings(L[j], h2),
            CryptoUtils::H3(stateKeys_[sortedDocs[j].state], keyword_hash)
        );
        
    
        node.a2 = {N[j + 1], z_next};
      
        node.a2 = CryptoUtils::xorPair(node.a2, h2);
      
        node.a3 = r;
     
        node.a4 = CryptoUtils::F2(encapsulationKey_, std::to_string(sortedDocs[j].level));
        node.a5 = digest[j];

        A[N[j]] = node;
    }

    size_t last = N.size() - 1;
    std::string r_last = CryptoUtils::generateRandomString();
    std::string z_last = CryptoUtils::H1(
        levelKeys_[sortedDocs[last].level].key2, 
        keyword_hash
    );
    std::string h2_last = CryptoUtils::H2(z_last, r_last);
    
    digest.push_back(CryptoUtils::computeDigest(
        CryptoUtils::xorStrings(h2_last, L[last])));
        
    IndexNode last_node;
    last_node.a1 = CryptoUtils::xorStrings(
        CryptoUtils::xorStrings(L[last], h2_last),
        CryptoUtils::H3(stateKeys_[sortedDocs[last].state], keyword_hash)
    );
    last_node.a2 = {0, ""};  
    last_node.a3 = r_last;
    last_node.a4 = CryptoUtils::F2(encapsulationKey_, std::to_string(sortedDocs[last].level));
    last_node.a5 = digest[last];
    
    A[N[last]] = last_node;
    
   
    for (size_t level = 1; level < X.size(); level++) {
        if (X[level] != 0) {
            auto tau2 = CryptoUtils::H4(levelKeys_[level].key3, keyword_hash);
            std::string h5 = CryptoUtils::H5(levelKeys_[level].key4, keyword_hash);        
       
            size_t h5_num = CryptoUtils::stringToSize(h5);
            
            T[tau2] = N[X[level]-1] ^ h5_num;
          
        } else {
            T[CryptoUtils::H4(levelKeys_[level].key3, keyword_hash)] = 0;
        }
        
    }
    return {A, T};
}

std::vector<std::string> BMScheme::decryptSearchResults(
    const std::vector<std::pair<std::string, std::string>>& searchResults) {
    std::vector<std::string> serverIds;
    int count = 0;
    
    for (const auto& [res, z2] : searchResults) {
   
        try {
          
            std::string f2_inv = CryptoUtils::F2_inverse(encapsulationKey_, z2);
        
           
            AccessLevel fileLevel = static_cast<AccessLevel>(std::stoi(f2_inv));
           
            
            
            auto levelKeyIt = levelKeys_.find(fileLevel);
            if (levelKeyIt == levelKeys_.end()) {
               
                continue;
            }
            
            std::string fileId = CryptoUtils::F1_inverse(levelKeyIt->second.key1, res);
          
            serverIds.push_back(fileId);
            
        } catch (const std::exception& e) {
           
        }
    }
    

    return serverIds;
}

// 获取搜索令牌
SearchToken BMScheme::getSearchToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword) {
   
    AccessLevel level = userTable_[userId].level;
    LevelKey levelKey = levelKeys_[level];
   
    
   
    std::vector<std::string> stateKeys;
    State currentState = userTable_[userId].state;
    
    for (State s = 1; s <= currentState; s++) {
        stateKeys.push_back(stateKeys_[s]);
    }
    
    return generateToken(hashedKeyword, levelKey, stateKeys);
}

//使用token进行搜索
std::vector<std::string> BMScheme::searchWithToken(const std::string& userId, 
        const std::string& encryptedId, 
        const std::string& hashed_keyword, 
        const SearchToken& token,
        size_t max_doc) {
 
    

    std::vector<std::pair<std::string, std::string>> results = edb_controller.search(token, max_doc);
    
   
  
    std::vector<std::string> decryptedResults = decryptSearchResults(results);
   
  
    std::vector<std::string> localResults;
    for(const auto& doc : documentBatch_[hashed_keyword]){
        if(doc.state <= userTable_[userId].state && doc.level <= userTable_[userId].level){
            localResults.push_back(doc.id);
        }
    }
  
    localResults.insert(localResults.end(), decryptedResults.begin(), decryptedResults.end());
    
   
    if (max_doc > 0 && localResults.size() > max_doc) {
        localResults.resize(max_doc);
    }
    return localResults;
}


// 管理员批量上传文件到本地缓存
void BMScheme::uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs) {
    
    for (const auto& pair : pairs) {
        const auto& keyword = pair.first;
        const auto& doc = pair.second;
        uploadDocument(keyword, doc);
    }
}

// 单文件上传接口
void BMScheme::uploadDocument(const Keyword& keyword, const Document& doc) {
   
  
    Document updatedDoc = doc;
    if(updatedDoc.state == 0 || updatedDoc.state >= currentState_) {
        updatedDoc.state = currentState_;
    }
  
    documentBatch_[keyword].push_back(updatedDoc);
    
}

// 删除文档
void BMScheme::deleteDocument(const Keyword& keyword, DocumentId docId) {
   
    auto& docs = documentBatch_[keyword];
    auto originalSize = docs.size();
    docs.erase(
        std::remove_if(docs.begin(), docs.end(),
            [docId](const Document& d) { return d.id == docId; }),
        docs.end()
    );
    bool deletedFromCache = (docs.size() < originalSize);
    
  
    if (!deletedFromCache) {
      
        EncryptedList keywordData = edb_controller.getKeywordData(keyword);
        
        
        std::vector<Document> allDocs;
        for (const auto& encDoc : keywordData.documents) {
            Document decDoc = decryptDocument(encDoc);
            if (decDoc.id != docId) {  
                allDocs.push_back(std::move(decDoc));
            }
        }
        
       
        if (!allDocs.empty()) {
            std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, allDocs);
            EncryptedIndex newIndex = result.first;
            LookupTable newTable = result.second;
            
         
            std::vector<EncryptedDocument> encryptedDocs;
            encryptedDocs.reserve(allDocs.size());
            for (const auto& d : allDocs) {
                encryptedDocs.push_back(encryptDocument(d));
            }
            
            
            edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);
        }
    }
}


void BMScheme::deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs) {
   
    std::map<Keyword, std::vector<DocumentId>> keywordToDocIds;
    for (const auto& pair : pairs) {
        const auto& keyword = pair.first;
        const auto& docId = pair.second;
        keywordToDocIds[keyword].push_back(docId);
    }
    

    for (const auto& [keyword, docIds] : keywordToDocIds) {
        
        auto& docs = documentBatch_[keyword];
        auto originalSize = docs.size();
        docs.erase(
            std::remove_if(docs.begin(), docs.end(),
                [&docIds](const Document& d) {
                    return std::find(docIds.begin(), docIds.end(), d.id) != docIds.end();
                }),
            docs.end()
        );
        bool deletedFromCache = (docs.size() < originalSize);
       

        if (!deletedFromCache || docs.size() + docIds.size() > originalSize) {
           
            EncryptedList keywordData = edb_controller.getKeywordData(keyword);
           
            std::vector<Document> remainingDocs;
            for (const auto& encDoc : keywordData.documents) {
                Document decDoc = decryptDocument(encDoc);
                
                if (std::find(docIds.begin(), docIds.end(), decDoc.id) == docIds.end()) {
                    remainingDocs.push_back(std::move(decDoc));
                }
            }
        
          
            std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, remainingDocs);
            EncryptedIndex newIndex = result.first;
            LookupTable newTable = result.second;
            
            std::vector<EncryptedDocument> encryptedDocs;
            if (!remainingDocs.empty()) {
                encryptedDocs.reserve(remainingDocs.size());
                for (const auto& doc : remainingDocs) {
                    encryptedDocs.push_back(encryptDocument(doc));
                }
            }
   
            
            edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);
        }
    }
}


void BMScheme::rebuildAllIndices() {

    
    std::map<Keyword, std::vector<Document>> keywordMap;
    for (const auto& [keyword, docs] : documentBatch_) {
        if (!docs.empty()) {
            keywordMap[keyword] = docs;
        }
    }
    
    
    size_t completed = 0;
    for (const auto& [keyword, newDocs] : keywordMap) {
        try {
            rebuildIndexForKeyword(keyword, newDocs);
            completed++;
            
        } catch (const std::exception& e) {
            throw;
        }
    }
    
    documentBatch_.clear();

}
void BMScheme::rebuildIndexForKeyword(const Keyword& keyword, 
                                      const std::vector<Document>& newDocs) {
 
    
    EncryptedList keywordData = edb_controller.getKeywordData(keyword);

  
    std::vector<Document> allDocs = newDocs;
    for (const auto& encDoc : keywordData.documents) {
        allDocs.push_back(decryptDocument(encDoc));
    }
    
    
    std::pair<EncryptedIndex, LookupTable> result = buildIndex(keyword, allDocs);
    EncryptedIndex newIndex = result.first;
    LookupTable newTable = result.second;
    
  
    // 4. 加密新文档
  
    std::vector<DocumentId> encryptedDocs;
    for (const auto& doc : allDocs) {
        encryptedDocs.push_back(encryptDocument(doc));
    }
    edb_controller.updateIndex(keyword, newIndex, newTable, encryptedDocs);

}

// 加密单个文档
EncryptedDocument BMScheme::encryptDocument(const Document& doc) {
    SGXValue docJson;
    docJson["id"] = doc.id;
    docJson["level"] = static_cast<int>(doc.level);
    docJson["state"] = static_cast<int>(doc.state);
    docJson["isBogus"] = doc.isBogus;
    
    std::string jsonStr = docJson.dump();
    
    // 加密整个文档信息
    //auto encrypted = CryptoUtils::F1(encapsulationKey_, jsonStr);
    return jsonStr;
}

// 解密单个文档
Document BMScheme::decryptDocument(const EncryptedDocument& encryptedDoc) {
    try {
        // 解密文档
        std::string decrypted = encryptedDoc;
        //std::string decrypted = CryptoUtils::F1_inverse(
        //    encapsulationKey_,
        //    encryptedDoc
        //);
        
        try {
            // 使用我们的SGX兼容序列化库
            SGXValue docJson = sgx_serializer::parse(decrypted);
            
            return Document {
                docJson["id"].get_string(),
                static_cast<AccessLevel>(docJson["level"].get_int()),
                static_cast<State>(docJson["state"].get_int()),
                docJson["isBogus"].get_bool()
            };
        } catch (const std::exception& e) {
            throw;
        }
    } catch (const std::exception& e) {
        throw;
    }
}

void BMScheme::startStateKeyTimer() {
    stateKeyTimer_.reset(new Timer());
    stateKeyTimer_->start(stateKeyUpdateInterval_, [this]() {
        updateStateKey();
    });
}

void BMScheme::updateStateKey() {

    currentState_++;
    std::string newStateKey = CryptoUtils::generateRandomString();
    
   
    stateKeys_[currentState_] = newStateKey;
    
}

SearchToken BMScheme::generateToken(const Keyword& keyword, const LevelKey& levelKey, const std::vector<StateKey>& stateKeys) {
    
    SearchToken token;
    
    
    token.tau1 = CryptoUtils::H1(levelKey.key2, keyword);
    
    
  
    token.tau2 = CryptoUtils::H4(levelKey.key3, keyword);
    
    
  
    token.tau3 = CryptoUtils::H5(levelKey.key4, keyword);
    
    
    for (const auto& stateKey : stateKeys) {
        token.tau4.push_back(CryptoUtils::H3(stateKey, keyword));
    }
    
    size_t paddingCount = stateKeys_.size() - stateKeys.size();
    
    
    auto paddingKeys = generatePaddingStateKeys(paddingCount);
    for (const auto& key : paddingKeys) {
        token.tau4.push_back(CryptoUtils::H3(key, keyword));
    }
    
    shuffleTau4(token.tau4);
    
    return token;
}

void BMScheme::shuffleTau4(std::vector<std::string>& vec) {
    if (vec.size() <= 1) return;
    for (size_t i = vec.size() - 1; i > 0; --i) {
   
        uint32_t rand_idx = 0;
        sgx_status_t ret = sgx_read_rand((unsigned char*)&rand_idx, sizeof(rand_idx));
        
        if (ret != SGX_SUCCESS) {

            rand_idx = i * 0x5DEECE66DLL + 0xBLL;
        }
        
        rand_idx = rand_idx % (i + 1);
        
  
        if (rand_idx != i) {
            std::string temp = vec[i];
            vec[i] = vec[rand_idx];
            vec[rand_idx] = temp;
        }
    }
}

        
std::vector<std::string> BMScheme::generatePaddingStateKeys(size_t count) const {
    std::vector<std::string> paddingKeys;
        for (size_t i = 0; i < count; i++) {
            paddingKeys.push_back(CryptoUtils::generateRandomString());
        }
        return paddingKeys;
}