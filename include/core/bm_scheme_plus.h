#pragma once
#include "core/bm_scheme.h"
#include "core/cache_controller.h"
#include "utils/constants.h"
#include <memory>
#include <unordered_map>
#include "enclave/enclave_dataset_loader.h"
class BMSchemePlus : public BMScheme {
public:
        BMSchemePlus(bool isPersistentAdversary = false)
        : BMScheme()
        , isPersistentAdversary_(isPersistentAdversary)
        , refreshThreshold_(3) {

      
        g_dataset_loader = EnclaveDatasetLoader();
          
        cacheController_.reset(new CacheController());
        
        cacheController_->setRefreshCallback([this](Cluster& cluster) {
           
        if (cluster.capacity() == 0) {
            return;
        }

      
        if (cluster.isInactive(refreshThreshold_ * 60)) {  
           
            if (!isPersistentAdversary_) {
                bool skipCluster = false;
                for (const auto& keyword : cluster.getKeywords()) {
                    if (!searchTable_[keyword].flag) {
                        skipCluster = true;
                        break;
                    }
                }
                
                if (!skipCluster) {
                    auto results = padding(cluster);
                    
                    for (const auto& pair : results) {
                        const auto& keyword = pair.first;
                        const auto& docs = pair.second;
                        rebuildIndexForKeyword(keyword, docs);
                    }
                    cluster.clear();
                }
            }
        
            else {
                if (cluster.isFirstBatch()) {
                    bool allKeywordsPresent = true;
                    for (const auto& keyword : cluster.getKeywords()) {
                        if (!searchTable_[keyword].flag) {
                            allKeywordsPresent = false;
                            break;
                        }
                    }
                    
                    if (allKeywordsPresent) {
                        auto results = padding(cluster);
                        for (const auto& pair : results) {
                            const auto& keyword = pair.first;
                            const auto& docs = pair.second;
                            rebuildIndexForKeyword(keyword, docs);
                        }
                        cluster.setNotFirstBatch();
                        cluster.clear();
                    }
                } else {
                    auto results = padding(cluster);
                    for (const auto& pair : results) {
                        const auto& keyword = pair.first;
                        const auto& docs = pair.second;
                        rebuildIndexForKeyword(keyword, docs);
                    }
                        cluster.clear();
                    }
                }
            }
        });
    }

    
    void uploadDocument(const Keyword& keyword, const Document& doc) override;
    void uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs) override;

 
    void deleteDocument(const Keyword& keyword, DocumentId docId) override;
    void deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs) override;
  
    std::vector<std::string> searchWithToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword, const SearchToken& token, size_t max_doc = 0) override;

    void reencryptCluster(Cluster& cluster);
    
    
    void addDocumentToDeleteList(const DocumentId& docId) {
        documentsToDelete_[docId] = true;
    }

    CacheController& getCacheController() {
        return *cacheController_;
    }
    ~BMSchemePlus() {
        cacheController_->stopRefreshTimer();
    }
 
    void initializeClusters();

    Cluster* getClusterForKeyword(const Keyword& keyword) {
        auto it = keyword_to_cluster_.find(keyword);
        if (it != keyword_to_cluster_.end()) {
            return &clusters_[it->second];
        }
        return nullptr;
    }


    std::pair<bool, size_t> getClusterIndexForKeyword(const Keyword& keyword) const {
        for (size_t i = 0; i < clusters_.size(); ++i) {
            if (clusters_[i].containsKeyword(keyword)) {
                return {true, i};
            }
        }
        return {false, 0};
    }

  
    std::vector<Cluster>& getClusters() {
        return clusters_;
    }
   

private:
    EnclaveDatasetLoader g_dataset_loader;

    
    std::map<Keyword, DocumentList> paddingCheck(
    const std::vector<std::pair<Keyword, Document>>& pairs);

   
    std::map<Keyword, DocumentList> padding(
        const Cluster& cluster);

    bool isPersistentAdversary_;
    std::vector<Cluster> clusters_;   
    std::map<Keyword, SearchState> searchTable_;  
    std::map<DocumentId, bool> documentsToDelete_;  
    std::unique_ptr<CacheController> cacheController_;
    std::unordered_map<Keyword, size_t> keyword_to_cluster_; 
    int refreshThreshold_; 
};
