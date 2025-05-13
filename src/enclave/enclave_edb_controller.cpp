#include "enclave/enclave_edb_controller.h"
#include "Enclave_t.h"
#include "sgx_trts.h"

std::vector<std::pair<std::string, std::string>> EnclaveEDBController::search(const SearchToken& token, size_t max_doc) {
    // 序列化 SearchToken
    std::string token_data = serializeSearchToken(token);
    // 准备接收结果的缓冲区
    const size_t MAX_RESULT_SIZE = 400 * 1024 * 1024; // 200MB
    uint8_t* result_buffer = new uint8_t[MAX_RESULT_SIZE];
    size_t actual_size = 0;
    
    // 调用 OCALL 
    ocall_edb_search(token_data.c_str(), token_data.size(), max_doc,
                     result_buffer, MAX_RESULT_SIZE, &actual_size);
    // 反序列化结果
    std::vector<std::pair<std::string, std::string>> results;
    if (actual_size > 0) {
        results = deserializeSearchResults(result_buffer, actual_size);
        ocall_print_string("search results count:");
        ocall_print_string(std::to_string(results.size()).c_str());
    }
    delete[] result_buffer;
    return results;
}

void EnclaveEDBController::updateIndex(const Keyword& keyword, 
                const std::vector<IndexNode>& newNodes, 
                const LookupTable& newTable,
                const std::vector<EncryptedDocument>& newEncryptedDocs) {
    
    // 序列化数据
    std::string nodes_data = serializeIndexNodes(newNodes);

    std::string table_data = serializeLookupTable(newTable);
    std::string docs_data = serializeEncryptedDocuments(newEncryptedDocs);
    
    // 调用 OCALL
    ocall_edb_update_index(keyword.c_str(), 
                          nodes_data.c_str(), nodes_data.size(),
                          table_data.c_str(), table_data.size(),
                          docs_data.c_str(), docs_data.size());
}

EncryptedList EnclaveEDBController::getKeywordData(const Keyword& keyword) {
    // 准备接收数据的缓冲区
    const size_t MAX_DATA_SIZE = 400 * 1024 * 1024; // 400MB
    uint8_t* data_buffer = new uint8_t[MAX_DATA_SIZE];
    size_t actual_size = 0;
   
    // 调用 OCALL
    ocall_edb_get_keyword_data(keyword.c_str(), data_buffer, MAX_DATA_SIZE, &actual_size);

    // 反序列化数据
    EncryptedList result;
    if (actual_size > 0) {
        result = deserializeEncryptedList(data_buffer, actual_size);
    }
    delete[] data_buffer;
    return result;
}

std::string EnclaveEDBController::serializeSearchToken(const SearchToken& token) {
    SGXValue j;
    j["tau1"] = CryptoUtils::base64Encode(token.tau1);
    j["tau2"] = CryptoUtils::base64Encode(token.tau2);
    j["tau3"] = CryptoUtils::base64Encode(token.tau3);
    // 创建一个空数组
    SGXValue tau4_array;
    for (const auto& tau : token.tau4) {
        tau4_array.push_back(CryptoUtils::base64Encode(tau));
    }
    j["tau4"] = tau4_array;
    j["timestamp"] = 0;  // 使用当前时间或默认值
    std::string json_str = j.dump();
    return json_str;
}

std::vector<std::pair<std::string, std::string>> EnclaveEDBController::deserializeSearchResults(
    const uint8_t* data,const size_t size) {
    // 实现搜索结果的反序列化
    std::string json_str(reinterpret_cast<const char*>(data), size);
    SGXValue j = sgx_serializer::parse(json_str);
    
    std::vector<std::pair<std::string, std::string>> results;
    for (size_t i = 0; i < j.size(); i++) {
        const auto& item = j[i];
        results.emplace_back(item["doc_id"].get_string(), 
                            item["access_level"].get_string());
    }
    return results;
}

std::string EnclaveEDBController::serializeIndexNodes(const std::vector<IndexNode>& nodes) {
    // 创建一个空数组
    SGXValue j;
    
    for (const auto& node : nodes) {
        SGXValue node_json;
        node_json["a1"] = CryptoUtils::base64Encode(node.a1);
        node_json["a2_first"] = CryptoUtils::base64Encode(std::to_string(node.a2.first));
        node_json["a2_second"] = CryptoUtils::base64Encode(node.a2.second);
        node_json["a3"] = CryptoUtils::base64Encode(node.a3);
        node_json["a4"] = CryptoUtils::base64Encode(node.a4);
        node_json["a5"] = CryptoUtils::base64Encode(node.a5);
        j.push_back(node_json);
    }
    std::string json_str = j.dump();
    return json_str;
}

std::string EnclaveEDBController::serializeLookupTable(const LookupTable& table) {
    SGXValue j;
    
    for (const auto& pair : table) {
        const auto& key = CryptoUtils::base64Encode(pair.first);
        const auto& value = pair.second;
        j[key] = std::to_string(value);  // 转换为字符串
    }
    
    std::string json_str = j.dump();
    return json_str;
}

std::string EnclaveEDBController::serializeEncryptedDocuments(const std::vector<EncryptedDocument>& docs) {
    // 创建一个空数组
    SGXValue j;
    
    for (const auto& doc : docs) {
        j.push_back(doc);
    }
    
    std::string json_str = j.dump();
    return json_str;
}

EncryptedList EnclaveEDBController::deserializeEncryptedList(const uint8_t* data,const size_t size) {
    
    // 实现 EncryptedList 的反序列化
    std::string json_str(reinterpret_cast<const char*>(data), size);
    SGXValue j = sgx_serializer::parse(json_str);
    
    EncryptedList result;
    
    // 反序列化 IndexNode 列表
    SGXValue& encryptedIndex = j["encryptedIndex"];
    for (size_t i = 0; i < encryptedIndex.size(); i++) {
        const auto& node_json = encryptedIndex[i];
        IndexNode node;
        node.a1 = node_json["a1"].get_string();
        node.a2.first = node_json["a2_first"].get_size_t();
        node.a2.second = node_json["a2_second"].get_string();
        node.a3 = node_json["a3"].get_string();
        node.a4 = node_json["a4"].get_string();
        node.a5 = node_json["a5"].get_string();
        
        result.encryptedIndex.push_back(node);
    }
    
    // 反序列化 LookupTable
    for (const auto& key : j["lookupTable"].keys()) {
        auto value = j["lookupTable"][key];
        result.lookupTable[key] = std::stoull(value.get_string());
    }
    // 反序列化 Document 列表
    SGXValue& documents = j["documents"];
    for (size_t i = 0; i < documents.size(); i++) {
        const auto& doc = documents[i].get_string();
        result.documents.push_back(doc);
    }
    return result;
} 