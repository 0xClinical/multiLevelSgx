#pragma once
#include <set>
#include <map>
#include <vector>
#include "utils/types.h"
#include "sgx_tae_service.h"  
#include "sgx_error.h"       

class Cluster {
public:
    
    Cluster(size_t threshold, size_t maxLevel) 
        : threshold_(threshold)
        , maxLevel_(maxLevel)
        , firstBatch_(true)
        , capacity_(0)
        , lastActivityTime_(0) {}  
    
 
    void addKeyword(const Keyword& keyword) {
        keywords_.insert(keyword);
    }
    

    void addDocument(Keyword keyword,const Document& doc) {
        documents_[keyword].push_back(doc);
        docCount_[keyword]++;
        
        capacity_++;
       
        uint8_t nonce_array[32];
        sgx_get_trusted_time(&lastActivityTime_, &nonce_array);
    }
    
  
    bool removeDocument(const Keyword& keyword, DocumentId docId) {
        auto it = documents_.find(keyword);
        if (it != documents_.end()) {
            it->second.erase(std::remove_if(it->second.begin(), it->second.end(),
                [docId](const Document& doc) { return doc.id == docId; }), it->second.end());
            return true;
        }
        return false;
    }

    size_t capacity() const { return capacity_; }
    
    
    size_t threshold() const { return threshold_; }
    
   
    bool containsKeyword(const Keyword& keyword) const {
        return keywords_.count(keyword) > 0;
    }
    
   
    const std::set<Keyword>& getKeywords() const { return keywords_; }
    
  
    size_t getKeywordCount(const Keyword& keyword) const {
        auto it = docCount_.find(keyword);
        return it != docCount_.end() ? it->second : 0;
    }
    
 
    std::vector<Document> getDocuments(const Keyword& keyword) const {
        auto it = documents_.find(keyword);
        return it != documents_.end() ? it->second : std::vector<Document>();
    }


    bool isFirstBatch() const { return firstBatch_; }
    
 
    void setNotFirstBatch() { firstBatch_ = false; }
    
  
    void clear() {
        documents_.clear();
        docCount_.clear();
        capacity_ = 0;
    }

  
    bool isInactive(uint32_t threshold_seconds) const {
        sgx_time_t current_time = 0;
        uint8_t nonce_array[32];
        if (sgx_get_trusted_time(&current_time, &nonce_array) != SGX_SUCCESS) {
      
            return false;
        }
  
        return (current_time - lastActivityTime_) > threshold_seconds;
    }

private:
    std::set<Keyword> keywords_;                              
    std::map<Keyword, std::vector<Document>> documents_;     
    std::map<Keyword, size_t> docCount_;                    
    size_t capacity_{0};                                    
    size_t threshold_;                                     
    size_t maxLevel_;                                        
    bool firstBatch_;                                       
    sgx_time_t lastActivityTime_;  
};