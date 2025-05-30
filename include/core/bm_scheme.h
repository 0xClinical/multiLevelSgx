#pragma once
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <mutex>
#include <iostream>
#include "utils/types.h"
#include "core/cluster.h"
#include "utils/timer.h"
#include "enclave/crypto_sgx.h"
#include "enclave/enclave_edb_controller.h"
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <bitset>
#ifdef SGX_ENCLAVE
#include "Enclave_t.h"
#endif



class BMScheme {
public:
    
    BMScheme() :  edb_controller() {
    }
    
    
    void updateLevelKeys(const std::map<AccessLevel, LevelKey>& levelKeys) {
        for (const auto& pair : levelKeys) {
            const auto& level = pair.first;
            const auto& key = pair.second;
            levelKeys_[level] = key;
        }
    }
    
    void updateStateKeys(const std::map<State, StateKey>& stateKeys) {
        for (const auto& pair : stateKeys) {
            const auto& state = pair.first;
            const auto& key = pair.second;
            stateKeys_[state] = key;
        }
    }
    
    void updateEncapsulationKey(const std::string& key) {
        encapsulationKey_ = key;
    }
    
   
    void updateUserTable(const std::map<std::string, User>& users) {
        for (const auto& pair : users) {
            const auto& id = pair.first;
            const auto& user = pair.second;
            userTable_[id] = user;
        }
    }
   
    void updateUser(const User& user) {
        userTable_[user.id] = user;
    }
   
    void addUser(const User& user) {
        userTable_[user.id] = user;
    }
   
    void deleteUser(const std::string& userId) {
        userTable_.erase(userId);
    }
   
    std::pair<std::vector<IndexNode>, LookupTable> 
    buildIndex(const Keyword keyword_hash, const std::vector<Document>& docs);
    
    
    virtual std::vector<std::string> searchWithToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword, const SearchToken& token, size_t max_doc = 0); 
  
    std::vector<std::string> decryptSearchResults(
        const std::vector<std::pair<std::string, std::string>>& searchResults);
    
    void updateKeys(const OwnerSecretKey& KO) {
        updateLevelKeys(KO.levelKeys);
        updateStateKeys(KO.stateKeys);
        updateEncapsulationKey(KO.encapsulationKey);
        currentState_ = KO.stateKeys.rbegin()->first;
    }
   
    SearchToken getSearchToken(const std::string& userId, const std::string& encryptedId, const std::string& hashedKeyword);
  
    virtual void uploadDocuments(const std::vector<std::pair<Keyword, Document>>& pairs);
   
    virtual void uploadDocument(const Keyword& keyword, const Document& doc);
  
    virtual void deleteDocument(const Keyword& keyword, DocumentId docId);
  
    virtual void deleteDocuments(const std::vector<std::pair<Keyword, DocumentId>>& pairs);
  
    virtual void rebuildAllIndices();

    
    virtual ~BMScheme() = default;

   
    void startStateKeyUpdateTimer(int intervalMinutes = 60) {
        stateKeyUpdateInterval_ = intervalMinutes;
        startStateKeyTimer();
    }
    
 
    void stopStateKeyUpdateTimer() {
        if (stateKeyTimer_) {
            stateKeyTimer_->stop();
        }
    }

protected:
    void rebuildIndexForKeyword(const Keyword& keyword, const std::vector<Document>& docs);    
   
    std::map<std::string, User> userTable_;              
    std::map<AccessLevel, LevelKey> levelKeys_;      
    std::map<State, StateKey> stateKeys_;           
    std::string encapsulationKey_;                 

    std::map<Keyword, std::vector<Document>> documentBatch_;


    SearchToken generateToken(
        const Keyword& keyword,
        const LevelKey& levelKey,
        const std::vector<StateKey>& stateKeys);
  
    std::vector<std::string> generatePaddingStateKeys(size_t count) const;

    
    void shuffleTau4(std::vector<std::string>& vec);

  
    static constexpr size_t REBUILD_THRESHOLD = 1000;  
    static constexpr size_t BATCH_SIZE = 1000; 
    
   
    EncryptedDocument encryptDocument(const Document& doc);
    Document decryptDocument(const EncryptedDocument& encryptedDoc);
    
    EnclaveEDBController edb_controller;
  

   
    void startStateKeyTimer();
    void updateStateKey();
    
    std::unique_ptr<Timer> stateKeyTimer_;
    int stateKeyUpdateInterval_{60};  
    State currentState_{0};           
};
