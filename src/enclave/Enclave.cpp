#include "Enclave_t.h"
#include "core/bm_scheme.h"
#include "core/bm_scheme_plus.h"
#include "enclave/enclave_edb_controller.h"
#include "enclave/enclave_dataset_loader.h"
#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include <set>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "utils/types.h"
#include "enclave/crypto_sgx.h"
#include "enclave/sgx_serializer.h"


// 全局实例
static std::unique_ptr<BMScheme> g_bm_scheme;

static std::unique_ptr<BMSchemePlus> g_bm_plus_scheme;

// 辅助函数 - 打印日志
void print_log(const std::string& message) {
   
    sgx_status_t ret = ocall_print_string(message.c_str());
    
}

/*--------------------------------BM--------------------------------*/
// BM 方案接口实现
sgx_status_t ecall_init_bm_scheme() {
    try {
        // 使用new代替make_unique
        g_bm_scheme.reset(new BMScheme());
        
        // 初始化密钥
        OwnerSecretKey keys;
        
        // 创建层级密钥 - 3个层级
        for (AccessLevel level = 1; level <= 3; level++) {
            LevelKey levelKey;
            levelKey.key1 = CryptoUtils::generateRandomString();
            levelKey.key2 = CryptoUtils::generateRandomString();
            levelKey.key3 = CryptoUtils::generateRandomString();
            levelKey.key4 = CryptoUtils::generateRandomString();
            keys.levelKeys[level] = levelKey;
        }
        
        // 创建状态密钥 - 10个状态
        for (State state = 1; state <= 10; state++) {
            keys.stateKeys[state] = CryptoUtils::generateRandomString();
        }
        
        // 设置封装密钥
        keys.encapsulationKey = CryptoUtils::generateRandomString();
        
        // 更新密钥
        g_bm_scheme->updateKeys(keys);
        
        print_log("BM scheme initialized successfully");
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error initializing BM scheme: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t ecall_bm_upload_document(
    const char* keyword,
    const char* doc_id,
    uint8_t level,
    uint8_t state
) {
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 创建文档对象
        Document doc;
        doc.id = doc_id;
        doc.level = level;
        doc.state = state;
        
        // 上传文档
        g_bm_scheme->uploadDocument(keyword, doc);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM方案上传文档
sgx_status_t ecall_bm_upload_documents(const char* keyword, const char* json_docs, size_t json_size) {
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        std::string key(keyword);
        std::string json_str(json_docs, json_size);
        
        SGXValue j = sgx_serializer::parse(json_str);
        
        std::vector<Document> docs;
        for (size_t i = 0; i < j.size(); i++) {
            const auto& doc_json = j[i];
            Document doc;
            doc.id = doc_json["id"].get_string();
            doc.level = static_cast<AccessLevel>(doc_json["level"].get_int());
            doc.state = static_cast<State>(doc_json["state"].get_int());
            doc.isBogus = doc_json["isBogus"].get_bool();
            docs.push_back(doc);
        }
        std::vector<std::pair<Keyword, Document>> pairs;
        for (const auto& doc : docs) {
            pairs.push_back(std::make_pair(key, doc));
        }
        // 使用g_bm_scheme上传文档
        g_bm_scheme->uploadDocuments(pairs);
        
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// 添加用户注册接口
sgx_status_t ecall_bm_add_user(
    const char* user_id,
    uint8_t level,
    uint8_t state,
    const char* public_key
) {
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 创建用户对象
        User user;
        user.id = user_id;
        user.level = level;
        user.state = state;
        user.publicKey = public_key;
        
        // 添加用户
        g_bm_scheme->addUser(user);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM方案搜索
sgx_status_t ecall_bm_search(const char* user_id, const char* encrypted_id, const char* keyword, size_t max_doc, char* result_buffer, size_t result_capacity, size_t* result_size) {
    if (!keyword || !result_buffer || !result_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        print_log("startsearch");
        SearchToken search_token = g_bm_scheme->getSearchToken(user_id, encrypted_id, keyword);
        print_log("searchwithtoken");
        std::vector<std::string> search_results = g_bm_scheme->searchWithToken(user_id, encrypted_id, keyword, search_token, max_doc);
        print_log("searchresults");
        // 创建JSON数组
        SGXValue j;
        for (const auto& doc_id : search_results) {
            j.push_back(doc_id);
        }
        
        std::string result_str = j.dump();
        *result_size = result_str.length();
        
        if (*result_size > result_capacity) {
            return SGX_ERROR_OUT_OF_MEMORY;
        }
        
        // 直接复制到提供的缓冲区
        memcpy(result_buffer, result_str.c_str(), *result_size);
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM方案删除文档
sgx_status_t ecall_bm_delete(const char* keyword, const char* doc_id) {
    if (!keyword || !doc_id) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        std::string key(keyword);
        std::string id(doc_id);
        
        // 使用g_bm_scheme删除文档
        g_bm_scheme->deleteDocument(key, id);
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t ecall_bm_rebuild_indices() {
    if (!g_bm_scheme) {
        print_log("BM Scheme not initialized");
        return SGX_ERROR_UNEXPECTED;
    }
    
    try {
        g_bm_scheme->rebuildAllIndices();
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error rebuilding indices: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM Plus 方案接口实现
sgx_status_t ecall_init_bm_plus_scheme() {
    try {
        g_bm_plus_scheme.reset(new BMSchemePlus());
        
        // 初始化密钥
        OwnerSecretKey keys;
        
        // 创建层级密钥 - 3个层级
        for (AccessLevel level = 1; level <= 3; level++) {
            LevelKey levelKey;
            levelKey.key1 = CryptoUtils::generateRandomString();
            levelKey.key2 = CryptoUtils::generateRandomString();
            levelKey.key3 = CryptoUtils::generateRandomString();
            levelKey.key4 = CryptoUtils::generateRandomString();
            keys.levelKeys[level] = levelKey;
        }
        
        // 创建状态密钥 - 10个状态
        for (State state = 1; state <= 10; state++) {
            keys.stateKeys[state] = CryptoUtils::generateRandomString();
        }
        
        // 设置封装密钥
        keys.encapsulationKey = CryptoUtils::generateRandomString();
        
        // 更新密钥
        g_bm_plus_scheme->updateKeys(keys);
        g_bm_plus_scheme->initializeClusters();
        print_log("BM++ scheme initialized successfully");
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error initializing BM Plus scheme: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}
sgx_status_t ecall_bm_delete_documents(const char* keyword, const char* doc_ids_json, size_t doc_count) {
    try {
        if (!g_bm_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        // 解析JSON字符串获取文档ID列表
        std::vector<std::pair<Keyword, DocumentId>> pairs;
        pairs.reserve(doc_count);
        // 使用SGX兼容的JSON解析
        SGXValue json = sgx_serializer::parse(doc_ids_json);
       
        for (size_t i = 0; i < json.size(); i++) {
            std::string doc_id = json[i].get_string();
            pairs.push_back(std::make_pair(keyword, doc_id));
        }
        g_bm_scheme->deleteDocuments(pairs);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error in ecall_bm_delete_documents: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    } catch (...) {
        print_log("Unknown error in ecall_bm_delete_documents");
        return SGX_ERROR_UNEXPECTED;
    }
}

/*--------------------------------BM++--------------------------------*/

sgx_status_t ecall_bm_plus_upload_document(
    const char* keyword,
    const char* doc_id,
    uint8_t level,
    uint8_t state
) {
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 创建文档对象
        Document doc;
        doc.id = doc_id;
        doc.level = level;
        doc.state = state;
        
        // 上传文档
        g_bm_plus_scheme->uploadDocument(keyword, doc);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM+方案上传文档
sgx_status_t ecall_bm_plus_upload_documents(const char* keyword, const char* docs_json, size_t docs_json_size) {
    if (!keyword || !docs_json) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 解析JSON字符串为文档列表
        std::string json_str(docs_json, docs_json_size);
        SGXValue j = sgx_serializer::parse(json_str);
        std::vector<Document> documents;
        
        for (size_t i = 0; i < j.size(); i++) {
            const auto& doc_json = j[i];
            Document doc;
            doc.id = doc_json["id"].get_string();
            doc.level = static_cast<AccessLevel>(doc_json["level"].get_int());
            doc.state = static_cast<State>(doc_json["state"].get_int());
            doc.isBogus = doc_json["isBogus"].get_bool();
            documents.push_back(doc);
        }
        
        // 使用g_bm_plus_scheme上传文档
        std::string key(keyword);
        std::vector<std::pair<Keyword, Document>> pairs;
        for (const auto& doc : documents) {
            pairs.push_back(std::make_pair(key, doc));
        }
        g_bm_plus_scheme->uploadDocuments(pairs);
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// 添加 BM++ 用户注册接口
sgx_status_t ecall_bm_plus_add_user(
    const char* user_id,
    uint8_t level,
    uint8_t state,
    const char* public_key
) {
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 创建用户对象
        User user;
        user.id = user_id;
        user.level = level;
        user.state = state;
        user.publicKey = public_key;
        
        // 添加用户
        g_bm_plus_scheme->addUser(user);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        return SGX_ERROR_UNEXPECTED;
    }
}

// BM+方案搜索
sgx_status_t ecall_bm_plus_search(const char* user_id, const char* encrypted_id, const char* keyword, size_t max_doc, char* result_buffer, size_t result_capacity, size_t* result_size) {
    if (!keyword || !result_buffer || !result_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        SearchToken search_token = g_bm_plus_scheme->getSearchToken(user_id, encrypted_id, keyword);
        std::vector<std::string> search_results = g_bm_plus_scheme->searchWithToken(user_id, encrypted_id, keyword, search_token, max_doc);
    
        
        // 创建JSON数组
        SGXValue result_json;
        for (const auto& doc_id : search_results) {
            result_json.push_back(doc_id);
        }
        
        std::string result_str = result_json.dump();
        *result_size = result_str.length();
        
        if (*result_size > result_capacity) {
            return SGX_ERROR_OUT_OF_MEMORY;
        }
        
        // 直接复制到提供的缓冲区
        memcpy(result_buffer, result_str.c_str(), *result_size);
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}


sgx_status_t ecall_bm_plus_rebuild_indices() {
    if (!g_bm_plus_scheme) {
        print_log("BM Plus Scheme not initialized");
        return SGX_ERROR_UNEXPECTED;
    }
    
    try {
        g_bm_plus_scheme->rebuildAllIndices();
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error rebuilding indices: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t ecall_bm_plus_initialize_clusters() {
    if (!g_bm_plus_scheme) {
        print_log("BM Plus Scheme not initialized");
        return SGX_ERROR_UNEXPECTED;
    }
    
    try {
        g_bm_plus_scheme->initializeClusters();
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error initializing clusters: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t ecall_bm_plus_reencrypt_cluster(uint32_t cluster_index) {
    if (!g_bm_plus_scheme) {
        print_log("BM Plus Scheme not initialized");
        return SGX_ERROR_UNEXPECTED;
    }
    
    try {
        auto& clusters = g_bm_plus_scheme->getClusters();
        if (cluster_index >= clusters.size()) {
            print_log("Invalid cluster index");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        
        g_bm_plus_scheme->reencryptCluster(clusters[cluster_index]);
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error reencrypting cluster: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}
// BM+方案删除文档
sgx_status_t ecall_bm_plus_delete(const char* keyword, const char* doc_id) {
    if (!keyword || !doc_id) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        std::string key(keyword);
        std::string id(doc_id);
        
        // 使用g_bm_plus_scheme删除文档
        g_bm_plus_scheme->deleteDocument(key, id);
        
        return SGX_SUCCESS;
    } catch (...) {
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t ecall_bm_plus_delete_documents(const char* keyword, const char* doc_ids_json, size_t doc_count) {
    try {
        if (!g_bm_plus_scheme) {
            return SGX_ERROR_UNEXPECTED;
        }
        
        // 解析JSON字符串获取文档ID列表
        std::vector<std::pair<Keyword, DocumentId>> pairs;
        pairs.reserve(doc_count);
        
        // 使用SGX兼容的JSON解析
        SGXValue json = sgx_serializer::parse(doc_ids_json);
        ocall_print_string(json[0].get_string().c_str());
        for (size_t i = 0; i < json.size(); i++) {
            std::string doc_id = json[i].get_string();
            pairs.push_back(std::make_pair(keyword, doc_id));
        }
        
        g_bm_plus_scheme->deleteDocuments(pairs);
        
        return SGX_SUCCESS;
    } catch (const std::exception& e) {
        print_log(std::string("Error in ecall_bm_plus_delete_documents: ") + e.what());
        return SGX_ERROR_UNEXPECTED;
    }
}



