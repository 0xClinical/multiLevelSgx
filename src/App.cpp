#include <chrono>
#include <fstream>
#include <iomanip>
#include <random>
#include <string>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <memory>
#include <vector>
#include <unistd.h>
#include <cstring>

// 首先包含SGX相关头文件
#include "sgx_urts.h"
#include "Enclave_u.h"  // 由 EDL 生成的接口

// 然后包含其他头文件
#include "test/test_bm.h"
#include "test/test_bm_plus.h"
#include "utils/crypto.h"
#include "utils/types.h"
#include "utils/dataset_loader.h"
#include "core/edb_controller.h"
#include "utils/constants.h"
#include "enclave/sgx_serializer.h"

// 防止包含Enclave_t.h
#define ENCLAVE_T_H__

// 全局变量
static sgx_enclave_id_t global_eid = 0;  // Enclave ID
static EDBController edb_controller;   // EDBController 实例

// 全局 DatasetLoader 实例
DatasetLoader dataset_loader(constants::BASE_DIR, constants::MIN_CLUSTER_SIZE_3);

// 辅助函数 - 初始化 Enclave
bool  initialize_enclave() {
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_status_t ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        std::cerr << "Failed to create enclave: " << std::hex << ret << std::endl;
        return false;
    }
    return true;
}

// OCALL 实现
void ocall_print_string(const char* str) {
    std::cout << "[Enclave] " << str << std::endl;
}


void ocall_edb_search(
    const char* token_data,
    size_t token_size,
    size_t max_doc,
    uint8_t* result_data,
    size_t max_result_size,
    size_t* actual_size
) {
    // 反序列化 SearchToken
    std::string json_str(token_data, token_size);
    SGXValue j = sgx_serializer::parse(json_str);
    
    SearchToken token;
    // 使用你定义的 ADL 序列化器
    token.tau1 = CryptoUtils::base64Decode(j["tau1"].get_string());
    token.tau2 = CryptoUtils::base64Decode(j["tau2"].get_string());
    token.tau3 = CryptoUtils::base64Decode(j["tau3"].get_string());
    token.tau4.clear();
    SGXValue tau4_array = j["tau4"];
    for (const auto& tau : tau4_array) {
        token.tau4.push_back(CryptoUtils::base64Decode(tau.get_string()));
    }
   
    // 直接使用传入的 max_doc 参数，不再从 token 中获取
    // 调用 EDBController 搜索
    auto results = edb_controller.search(token, max_doc);
    // 序列化结果 - 这是一个 vector<pair<string, string>>
    SGXValue result_json;
    for (const auto& result : results) {
        std::string doc_id = result.first;
        std::string access_level = result.second;
        SGXValue pair_json;
        pair_json["doc_id"] = doc_id;
        pair_json["access_level"] = access_level;
        result_json.push_back(pair_json);
    }
    
    std::string result_str = result_json.dump();
    *actual_size = std::min(result_str.size(), max_result_size);
    memcpy(result_data, result_str.c_str(), *actual_size);
}

void ocall_edb_update_index(
    const char* keyword,
    const char* nodes_data,
    size_t nodes_size,
    const char* table_data,
    size_t table_size,
    const char* docs_data,
    size_t docs_size

) {
    // 反序列化节点数据
    std::string nodes_json_str(reinterpret_cast<const char*>(nodes_data), nodes_size);
    SGXValue json_nodes = sgx_serializer::parse(nodes_json_str);
    
    std::vector<IndexNode> nodes;
    for (const auto& node_value : json_nodes) {
        IndexNode node;
        node.a1 = CryptoUtils::base64Decode(node_value["a1"].get_string());
        
        // 反序列化 a2 (pair)
        node.a2.first = std::stoull(CryptoUtils::base64Decode(node_value["a2_first"].get_string()));
        node.a2.second = CryptoUtils::base64Decode(node_value["a2_second"].get_string());
        
        node.a3 = CryptoUtils::base64Decode(node_value["a3"].get_string());
        node.a4 = CryptoUtils::base64Decode(node_value["a4"].get_string());
        node.a5 = CryptoUtils::base64Decode(node_value["a5"].get_string());
        
        nodes.push_back(node);
    }
    
    // 反序列化查找表
    std::string table_json_str(reinterpret_cast<const char*>(table_data), table_size);
    SGXValue table_json = sgx_serializer::parse(table_json_str);
    LookupTable table;

    // 使用keys()方法获取所有键，然后安全地访问每个值
    std::vector<std::string> keys = table_json.keys();
    for (const auto& key : keys) {
        auto actual_key = CryptoUtils::base64Decode(key);
        table[actual_key] = std::stoull(table_json[key].get_string());
    }
    
    
    // 反序列化加密文档
    std::string docs_json_str(reinterpret_cast<const char*>(docs_data), docs_size);
    SGXValue docs_json = sgx_serializer::parse(docs_json_str);
    
    std::vector<EncryptedDocument> docs;
    for (const auto& doc_json : docs_json) {
        docs.push_back(doc_json.get_string());
    }
    
    // 调用 EDBController 更新索引
    edb_controller.updateIndex(keyword, nodes, table, docs);
}

void ocall_edb_get_keyword_data(
    const char* keyword,
    uint8_t* data_buffer,
    size_t max_data_size,
    size_t* actual_size
) {
    
    // 调用 EDBController 获取关键词数据
    EncryptedList data = edb_controller.getKeywordData(keyword);
   
    // 序列化数据
    SGXValue j;
    // 序列化 IndexNode 列表
    SGXValue encryptedIndex;
    for (const auto& node : data.encryptedIndex) {
        SGXValue node_json;
        node_json["a1"] = node.a1;
        node_json["a2_first"] = node.a2.first;
        node_json["a2_second"] = node.a2.second;
        node_json["a3"] = node.a3;
        node_json["a4"] = node.a4;
        node_json["a5"] = node.a5;
        
        encryptedIndex.push_back(node_json);
    }
    j["encryptedIndex"] = encryptedIndex;
    
    // 序列化 LookupTable
    SGXValue lookupTable;
    for (const auto& [key, value] : data.lookupTable) {
        lookupTable[key] = std::to_string(value);
    }
    j["lookupTable"] = lookupTable;
    
    // 序列化 DocumentId 列表
    SGXValue docs_array;
    for (const auto& doc : data.documents) {
        docs_array.push_back(doc);
    }
    j["documents"] = docs_array;
    
    std::string json_str = j.dump();
    *actual_size = std::min(json_str.size(), max_data_size);
    memcpy(data_buffer, json_str.c_str(), *actual_size);
}

void ocall_dataset_get_bogus_document(
    const char* keyword,
    uint8_t max_state,
    uint8_t max_level,
    uint8_t* doc_buffer,
    size_t max_doc_size,
    size_t* actual_size
) {
    // 调用 DatasetLoader 获取虚假文档
    Document doc = dataset_loader.getBogusDocument(keyword, max_state, max_level);
    
    // 序列化文档
    SGXValue j;
    j["id"] = doc.id;
    j["level"] = doc.level;
    j["state"] = doc.state;
    j["is_bogus"] = doc.isBogus;
    
    std::string json_str = j.dump();
    *actual_size = std::min(json_str.size(), max_doc_size);
    memcpy(doc_buffer, json_str.c_str(), *actual_size);
}

void ocall_dataset_get_all_clusters(
    uint8_t* data_buffer,
    size_t max_data_size,
    size_t* actual_size
) {
    // 调用 DatasetLoader 获取所有簇
    auto clusters = dataset_loader.getAllClusters();
    
    // 序列化簇数据
    SGXValue j;
    for (const auto& cluster : clusters) {
        SGXValue cluster_json;
        
        // 序列化关键词列表
        SGXValue keywords_json;
        for (const auto& keyword : cluster.keywords) {
            keywords_json.push_back(keyword);
        }
        cluster_json["keywords"] = keywords_json;
        
        cluster_json["min_freq"] = (size_t)cluster.min_freq;
        cluster_json["max_freq"] = (size_t)cluster.max_freq;
        cluster_json["avg_freq"] = (size_t)cluster.avg_freq;
        cluster_json["threshold"] = (size_t)cluster.threshold;
        
        j.push_back(cluster_json);
    }
    
    std::string json_str = j.dump();
    *actual_size = std::min(json_str.size(), max_data_size);
    memcpy(data_buffer, json_str.c_str(), *actual_size);
}

void run_bm_test(sgx_enclave_id_t eid, const std::string& test_name) {
    TestBM test(eid);
    test.run(test_name);
}

void run_bm_plus_test(sgx_enclave_id_t eid, const std::string& test_name) {   
    TestBMPlus test(eid);
    test.run(test_name);
}

// 生成密钥对
sgx_status_t ocall_generate_key_pair(
    char* pubkey, 
    size_t* pubkey_len,
    char* privkey, 
    size_t* privkey_len
) {
    auto [pub, priv] = CryptoUtils::generateKeyPair();
    
    // 检查缓冲区大小
    if (pubkey && *pubkey_len >= pub.length()) {
        memcpy(pubkey, pub.c_str(), pub.length());
        *pubkey_len = pub.length();
    } else {
        *pubkey_len = pub.length();
    }
    
    if (privkey && *privkey_len >= priv.length()) {
        memcpy(privkey, priv.c_str(), priv.length());
        *privkey_len = priv.length();
    } else {
        *privkey_len = priv.length();
    }
    return SGX_SUCCESS;
}

// 签名数据
sgx_status_t ocall_sign_data(
    const char* data, 
    size_t data_len,
    const char* private_key, 
    size_t private_key_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(data, data_len);
    std::string key_str(private_key, private_key_len);
    
    std::string sig = CryptoUtils::signWithPrivateKey(data_str, key_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= sig.length()) {
        memcpy(result, sig.c_str(), sig.length());
        *out_len = sig.length();
    } else {
        *out_len = sig.length();
    }
    return SGX_SUCCESS;
}

// 验证签名
sgx_status_t ocall_verify_signature(
    int* result,
    const char* data, 
    size_t data_len,
    const char* signature, 
    size_t signature_len,
    const char* public_key, 
    size_t public_key_len
) {
    std::string data_str(data, data_len);
    std::string sig_str(signature, signature_len);
    std::string key_str(public_key, public_key_len);
    
    bool verify_result = CryptoUtils::verifySignature(data_str, sig_str, key_str);
    *result = verify_result ? 1 : 0;
    
    return SGX_SUCCESS;
}

// Base64编码
sgx_status_t ocall_base64_encode(
    const char* input, 
    size_t input_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(input, input_len);
    std::string encoded_str = CryptoUtils::base64Encode(data_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= encoded_str.length()) {
        memcpy(result, encoded_str.c_str(), encoded_str.length());
        *out_len = encoded_str.length();
    } else {
        *out_len = encoded_str.length();
    }
    return SGX_SUCCESS;
}

// Base64解码
sgx_status_t ocall_base64_decode(
    const char* input, 
    size_t input_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(input, input_len);
    std::string decoded_str = CryptoUtils::base64Decode(data_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= decoded_str.length()) {
        memcpy(result, decoded_str.c_str(), decoded_str.length());
        *out_len = decoded_str.length();
    } else {
        *out_len = decoded_str.length();
    }
    return SGX_SUCCESS;
}

// F2加密
sgx_status_t ocall_f2_encrypt(
    const char* input, 
    size_t input_len, 
    const char* key, 
    size_t key_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(input, input_len);
    std::string key_str(key, key_len);
    
    // 将输入字符串转换为整数级别
    int level = std::stoi(data_str);
    
    // 调用正确的F2函数
    std::string encrypted_str = CryptoUtils::F2(key_str, level);
    
    // 检查缓冲区大小
    if (result && *out_len >= encrypted_str.length()) {
        memcpy(result, encrypted_str.c_str(), encrypted_str.length());
        *out_len = encrypted_str.length();
    } else {
        *out_len = encrypted_str.length();
    }
    return SGX_SUCCESS;
}

// F2解密
sgx_status_t ocall_f2_decrypt(
    const char* encrypted, 
    size_t encrypted_len, 
    const char* key, 
    size_t key_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(encrypted, encrypted_len);
    std::string key_str(key, key_len);
    
    std::string decrypted_str = CryptoUtils::F2_inverse(key_str, data_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= decrypted_str.length()) {
        memcpy(result, decrypted_str.c_str(), decrypted_str.length());
        *out_len = decrypted_str.length();
    } else {
        *out_len = decrypted_str.length();
    }
    return SGX_SUCCESS;
}

// 生成随机数
sgx_status_t ocall_generate_random(
    size_t len,
    char* result, 
    size_t* out_len
) {
    std::string random = CryptoUtils::generateRandomString(len);
    
    // 检查缓冲区大小
    if (result && *out_len >= random.length()) {
        memcpy(result, random.c_str(), random.length());
        *out_len = random.length();
    } else {
        *out_len = random.length();
    }
    return SGX_SUCCESS;
}

// AES加密
sgx_status_t ocall_aes_encrypt(
    const char* data, 
    size_t data_len,
    const char* key, 
    size_t key_len,
    const char* iv, 
    size_t iv_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(data, data_len);
    std::string key_str(key, key_len);
    std::string iv_str(iv, iv_len);
    
    std::string encrypted_str = CryptoUtils::computeAES(data_str, key_str, iv_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= encrypted_str.length()) {
        memcpy(result, encrypted_str.c_str(), encrypted_str.length());
        *out_len = encrypted_str.length();
    } else {
        *out_len = encrypted_str.length();
    }
    return SGX_SUCCESS;
}

// AES解密
sgx_status_t ocall_aes_decrypt(
    const char* data, 
    size_t data_len,
    const char* key, 
    size_t key_len,
    const char* iv, 
    size_t iv_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(data, data_len);
    std::string key_str(key, key_len);
    std::string iv_str(iv, iv_len);
    
    std::string decrypted_str = CryptoUtils::computeAES_decrypt(data_str, key_str, iv_str);
    
    // 检查缓冲区大小
    if (result && *out_len >= decrypted_str.length()) {
        memcpy(result, decrypted_str.c_str(), decrypted_str.length());
        *out_len = decrypted_str.length();
    } else {
        *out_len = decrypted_str.length();
    }
    return SGX_SUCCESS;
}

// 将字符串转换为size_t
sgx_status_t ocall_string_to_size(
    const char* data, 
    size_t data_len,
    char* result, 
    size_t* out_len
) {
    std::string data_str(data, data_len);
    size_t size = CryptoUtils::stringToSize(data_str);
    std::string size_str = std::to_string(size);
    if (result && *out_len >= size_str.length()) {
        memcpy(result, size_str.c_str(), size_str.length());
        *out_len = size_str.length();
    }
    return SGX_SUCCESS;
}
// 主函数
int main(int argc, char* argv[]) {
    if (initialize_enclave()) {
        std::cout << "Enclave initialized successfully." << std::endl;
    } else {
        std::cerr << "Failed to initialize enclave." << std::endl;
        return 1;
    }
    
    // 根据命令行参数选择要运行的测试
    if (argc > 1) {
        std::string test_type = argv[1];
        std::string test_name = (argc > 2) ? argv[2] : "";

        if (test_type == "--test-bm") {
            std::cout << "Running BM test..." << std::endl;
            run_bm_test(global_eid, test_name);
        } else if (test_type == "--test-bm-plus") {
            std::cout << "Running BM++ test..." << std::endl;
            run_bm_plus_test(global_eid, test_name);
        } else {
            std::cout << "Unknown command: " << test_type << std::endl;
            std::cout << "Available commands: --test-bm [test_name], --test-bm-plus [test_name]" << std::endl;
        }
    } else {
        std::cout << "No command specified. Available commands: --test-bm [test_name], --test-bm-plus [test_name]" << std::endl;
    }
    
    sgx_destroy_enclave(global_eid);
    return 0;
}
