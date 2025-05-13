#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include "enclave/sgx_serializer.h"

// 内部Base64编码/解码实现
namespace {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    // Base64编码实现
    std::string base64_encode(const std::string& input) {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];
        size_t in_len = input.size();
        const unsigned char* bytes_to_encode = reinterpret_cast<const unsigned char*>(input.c_str());
        
        while (in_len--) {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                
                for(i = 0; i < 4; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }
        
        if (i) {
            for(j = i; j < 3; j++)
                char_array_3[j] = '\0';
            
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            
            for (j = 0; j < i + 1; j++)
                ret += base64_chars[char_array_4[j]];
            
            while((i++ < 3))
                ret += '=';
        }
        
        return ret;
    }
    
    // Base64解码实现
    std::string base64_decode(const std::string& encoded_string) {
        size_t in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;
        
        std::string base64_chars_str = base64_chars;
        
        while (in_len-- && (encoded_string[in_] != '=') && 
               (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
            char_array_4[i++] = encoded_string[in_]; in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = base64_chars_str.find(char_array_4[i]);
                
                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
                
                for (i = 0; (i < 3); i++)
                    ret += char_array_3[i];
                i = 0;
            }
        }
        
        if (i) {
            for (j = 0; j < i; j++)
                char_array_4[j] = base64_chars_str.find(char_array_4[j]);
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            
            for (j = 0; (j < i - 1); j++) 
                ret += char_array_3[j];
        }
        
        return ret;
    }
}

// 基本类型别名
using DocumentId = std::string;           // 文档ID
using EncryptedDocument = std::string;    // 加密后的完整文档
using Keyword = std::string;     // ω
using AccessLevel = uint8_t;         // l
using State = uint8_t;       // st
using StateKey = std::string;
using LookupTable = std::map<std::string, size_t>;    // T 

// 索引节点结构
struct IndexNode {              // 数组A中的节点
    std::string a1;            // 加密的文件标识符
    std::pair<size_t, std::string> a2;  // 下一个节点地址和解密密钥
    std::string a3;            // 随机字符串 r
    std::string a4;            // 加密的访问级别
    std::string a5;            // 摘要值
};

// 每个关键字对应一个加密索引和查找表
struct EncryptedList {
    std::vector<IndexNode> encryptedIndex;     // A数组
    LookupTable lookupTable;                   // 查找表
    std::vector<EncryptedDocument> documents;       // SGX加密的完整文档列表
};

// 文档基本信息
struct Document {
    DocumentId id;
    AccessLevel level;    // λ(id)
    State state;   
    bool isBogus{false}; // 是否是虚假文档
};

// 关键词-文档对
struct KeywordDocumentPair {
    Keyword keyword;
    Document doc;
};

// 关键词到文档的映射
using KeywordDocumentMap = std::unordered_map<Keyword, std::vector<Document>>;

// 定义层级密钥结构
struct LevelKey {
    std::string key1;  // 第一个子密钥
    std::string key2;  // 第二个子密钥
    std::string key3;  // 第三个子密钥
    std::string key4;  // 第四个子密钥
};

// 搜索状态
struct SearchState {
    bool flag{false};    // 关键词是否出现过
    size_t count{0};     // 关键词出现次数
};

// 文档列表类型
using DocumentList = std::vector<Document>;
// 用户结构
struct User {
    std::string id;
    AccessLevel level;          // λ(u)
    State state;
    std::string publicKey;
    std::string privateKey = "";  //默认值为空
};

// 密钥结构
struct OwnerSecretKey {         // KO
    std::map<AccessLevel, LevelKey> levelKeys;      // {kl}l∈L
    std::map<State, StateKey> stateKeys;           // {st}
    std::string encapsulationKey;                     // ko
};

// 查询令牌结构
struct SearchToken {
    std::string tau1;                    // 用于解密第一个节点
    std::string tau2;                    // 用于定位查找表条目
    std::string tau3;                    // 用于解密起始节点位置
    std::vector<std::string> tau4;       // 状态密钥哈希值集合
    
    bool isEmpty() const {
        return tau1.empty() || tau2.empty() || tau3.empty() || tau4.empty();
    }
};

// 搜索结果结构
struct SearchResult {
    std::vector<DocumentId> documents;  // 匹配的文档ID列表
    bool success{true};                 // 搜索是否成功
    std::string error;                  // 错误信息（如果有）
};

struct ClusterData {
    std::vector<std::string> keywords;
    float min_freq;
    float max_freq;
    float avg_freq;
    uint32_t threshold;
};

// 集合类型别名
using UserTable = std::map<std::string, User>;        // 用户表
using EncryptedIndex = std::vector<IndexNode>;        // 加密索引

// 错误码
enum class SearchError {
    SUCCESS = 0,
    USER_NOT_AUTHORIZED = 1,
    INVALID_SIGNATURE = 2,
    INVALID_TOKEN = 3,
    SERVER_ERROR = 4
}; 

// SGX兼容的序列化函数
namespace SGXSerializer {
    // IndexNode序列化
    static std::string serialize(const IndexNode& node) {
        SGXValue obj;
        obj["a1"] = node.a1;
        
        SGXValue a2_array;
        a2_array.push_back(static_cast<int>(node.a2.first));
        a2_array.push_back(node.a2.second);
        obj["a2"] = a2_array;
        
        obj["a3"] = node.a3;
        obj["a4"] = node.a4;
        obj["a5"] = node.a5;
        
        return obj.dump();
    }
    
    // IndexNode反序列化
    static IndexNode deserialize_index_node(const std::string& json_str) {
        IndexNode node;
        SGXValue value = sgx_serializer::parse(json_str);
        
        node.a1 = value["a1"].get_string();
        node.a2.first = value["a2"][0].get_size_t();
        node.a2.second = value["a2"][1].get_string();
        node.a3 = value["a3"].get_string();
        node.a4 = value["a4"].get_string();
        node.a5 = value["a5"].get_string();
        
        return node;
    }
    
    // LevelKey序列化
    static std::string serialize(const LevelKey& key) {
        SGXValue obj;
        obj["key1"] = key.key1;
        obj["key2"] = key.key2;
        obj["key3"] = key.key3;
        obj["key4"] = key.key4;
        
        return obj.dump();
    }
    
    // LevelKey反序列化
    static LevelKey deserialize_level_key(const std::string& json_str) {
        LevelKey key;
        SGXValue value = sgx_serializer::parse(json_str);
        
        key.key1 = value["key1"].get_string();
        key.key2 = value["key2"].get_string();
        key.key3 = value["key3"].get_string();
        key.key4 = value["key4"].get_string();
        
        return key;
    }
    
    // Document序列化
    static std::string serialize(const Document& doc) {
        SGXValue obj;
        obj["id"] = doc.id;
        obj["level"] = static_cast<int>(doc.level);
        obj["state"] = static_cast<int>(doc.state);
        obj["isBogus"] = doc.isBogus;
        
        return obj.dump();
    }
    
    // Document反序列化
    static Document deserialize_document(const std::string& json_str) {
        Document doc;
        SGXValue value = sgx_serializer::parse(json_str);
        
        doc.id = value["id"].get_string();
        doc.level = value["level"].get_uint8();
        doc.state = value["state"].get_uint8();
        doc.isBogus = value["isBogus"].get_bool();
        
        return doc;
    }
    
    // SearchToken序列化
    static std::string serialize(const SearchToken& token) {
        SGXValue obj;
        obj["tau1"] = base64_encode(token.tau1);
        obj["tau2"] = base64_encode(token.tau2);
        obj["tau3"] = base64_encode(token.tau3);
        
        SGXValue tau4_array;
        for (const auto& tau : token.tau4) {
            tau4_array.push_back(base64_encode(tau));
        }
        obj["tau4"] = tau4_array;
        
        return obj.dump();
    }
    
    // SearchToken反序列化
    static SearchToken deserialize_search_token(const std::string& json_str) {
        SearchToken token;
        SGXValue value = sgx_serializer::parse(json_str);
        
        token.tau1 = base64_decode(value["tau1"].get_string());
        token.tau2 = base64_decode(value["tau2"].get_string());
        token.tau3 = base64_decode(value["tau3"].get_string());
        
        token.tau4.clear();
        SGXValue tau4_array = value["tau4"];
        for (size_t i = 0; i < tau4_array.size(); i++) {
            token.tau4.push_back(base64_decode(tau4_array[i].get_string()));
        }
        
        return token;
    }
    
    // User序列化
    static std::string serialize(const User& user) {
        SGXValue obj;
        obj["id"] = user.id;
        obj["level"] = static_cast<int>(user.level);
        obj["state"] = static_cast<int>(user.state);
        obj["publicKey"] = user.publicKey;
        
        return obj.dump();
    }
    
    // User反序列化
    static User deserialize_user(const std::string& json_str) {
        User user;
        SGXValue value = sgx_serializer::parse(json_str);
        
        user.id = value["id"].get_string();
        user.level = value["level"].get_uint8();
        user.state = value["state"].get_uint8();
        user.publicKey = value["publicKey"].get_string();
        
        return user;
    }
    
    // EncryptedList序列化
    static std::string serialize(const EncryptedList& list) {
        SGXValue obj;
        
        // 序列化加密索引
        SGXValue index_array;
        for (const auto& node : list.encryptedIndex) {
            index_array.push_back(serialize(node));
        }
        obj["encryptedIndex"] = index_array;
        
        // 序列化查找表
        SGXValue lookup_table;
        for (const auto& pair : list.lookupTable) {
            lookup_table[pair.first] = static_cast<int>(pair.second);
        }
        obj["lookupTable"] = lookup_table;
        
        // 序列化文档列表
        SGXValue docs_array;
        for (const auto& doc : list.documents) {
            docs_array.push_back(doc);
        }
        obj["documents"] = docs_array;
        
        return obj.dump();
    }
    
    // EncryptedList反序列化
    static EncryptedList deserialize_encrypted_list(const std::string& json_str) {
        EncryptedList list;
        SGXValue value = sgx_serializer::parse(json_str);
        
        // 反序列化加密索引
        SGXValue index_array = value["encryptedIndex"];
        for (size_t i = 0; i < index_array.size(); i++) {
            list.encryptedIndex.push_back(deserialize_index_node(index_array[i].get_string()));
        }
        
        // 反序列化查找表
        SGXValue lookup_table = value["lookupTable"];
        for (const auto& key : lookup_table.keys()) {
            list.lookupTable[key] = lookup_table[key].get_size_t();
        }
        
        // 反序列化文档列表
        SGXValue docs_array = value["documents"];
        for (size_t i = 0; i < docs_array.size(); i++) {
            list.documents.push_back(docs_array[i].get_string());
        }
        
        return list;
    }
}
