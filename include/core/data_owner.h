#pragma once
#include "utils/types.h"
#include <memory>
#include <random>
#include "core/cluster.h"
#include "core/bm_scheme.h"
#include "core/bm_scheme_plus.h"
#include "utils/dataset_loader.h"

class DataOwner {
public:
    DataOwner( const std::string& host = "127.0.0.1", int port = 8080)
             : host_(host), port_(port) {}
    
   
    std::string addAuthorizedUser(const std::string& userId, 
                          AccessLevel level,
                          State state);
    void revokeUser(const std::string& userId);
    
  
    OwnerSecretKey generateKeys(size_t numLevels, size_t numStates);
    void uploadKeysToEnclave(OwnerSecretKey secretKey);

    void addDocument(const Document& doc);
    void addDocuments(const std::vector<Document>& docs);
    void deleteDocument(const Document& doc);
    void deleteDocuments(const std::vector<Document>& docs);
    void requestRebuildIndices();
    
  
    LevelKey getLevelKey(int level) const;
    StateKey getStateKey(int stateId) const;
    std::string getEncapsulationKey() const;

   
    void updateLevelKeys(const std::map<AccessLevel, LevelKey>& levelKeys);
    void updateStateKeys(const std::map<State, StateKey>& stateKeys);
    void updateEncapsulationKey(const std::string& encapsulationKey);

  
    Document getDocument(const std::string& docId) const {
       
        std::string paddedId = docId;
        if (paddedId.find("wiki_") == 0) { 
            std::string numPart = paddedId.substr(5);  
           
            numPart.resize(27, '0');
            paddedId = "wiki_" + numPart;
        }
        
        std::cout << "Looking up document with ID: " << paddedId << "\n";
        
        auto it = documents_.find(paddedId);
        if (it == documents_.end()) {
            throw std::runtime_error("Document not found: " + paddedId);
        }
        return it->second;
    }
 
    User getUser(const std::string& userId) const {
        auto it = authorizedUsers_.find(userId);
        return (it != authorizedUsers_.end()) ? it->second : User();
    }
private:
    std::string host_;
    int port_;
    std::unordered_map<std::string, Document> documents_;  
    std::map<std::string, User> authorizedUsers_;
    std::map<AccessLevel, LevelKey> levelKeys_;
    std::map<State, StateKey> stateKeys_;
    std::string encapsulationKey_;
    
    std::string generateRandomKey(size_t length = 32) const;
    
};
