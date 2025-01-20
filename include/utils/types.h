#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <nlohmann/json.hpp>

// 安全参数
constexpr size_t SECURITY_PARAMETER = 256;  // κ

// 基本类型别名
using DocumentId = std::string;           // 文档ID
using EncryptedDocument = std::string;    // 加密后的完整文档
using Keyword = std::string;     // ω
using AccessLevel = int;         // l
using State = int;       // st
using StateKey = std::string;

// 文档结构
struct Document {
    DocumentId id;
    AccessLevel level;          // λ(id)
    std::set<Keyword> keywords;  // 使用set存储关键字
    State state;   
    bool isBogus{false};        // 是否是虚假文档
};

// 每个关键字对应一个加密索引和查找表
    struct EncryptedList {
        std::vector<IndexNode> encryptedIndex;     // A数组
        LookupTable lookupTable;                   // 查找表
        std::vector<EncryptedDocument> docs;       // SGX加密的完整文档列表
    };

// 定义层级密钥结构
struct LevelKey {
    std::string key1;  // 第一个子密钥
    std::string key2;  // 第二个子密钥
    std::string key3;  // 第三个子密钥
    std::string key4;  // 第四个子密钥
};

// 用户结构
struct User {
    std::string id;
    AccessLevel level;          // λ(u)
    State state;
    std::string publicKey;
};

// 密钥结构
struct OwnerSecretKey {         // KO
    std::map<AccessLevel, LevelKey> levelKeys;      // {kl}l∈L
    std::map<State, StateKey> stateKeys;           // {st}
    std::string encapsulationKey;                     // ko
};

// 索引节点结构
struct IndexNode {              // 数组A中的节点
    std::string a1;            // 加密的文件标识符
    std::pair<size_t, std::string> a2;  // 下一个节点地址和解密密钥
    std::string a3;            // 随机字符串 r
    std::string a4;            // 加密的访问级别
    std::string a5;            // 摘要值
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

// 集合类型别名
using KeywordDocumentMap = std::map<Keyword, std::vector<DocumentId>>;  // Dω
using LookupTable = std::map<std::string, size_t>;    // T 
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

// 为 IndexNode 添加序列化支持
namespace nlohmann {
    template<>
    struct adl_serializer<IndexNode> {
        static void to_json(json& j, const IndexNode& node) {
            j = json{
                {"a1", node.a1},
                {"a2", {node.a2.first, node.a2.second}},
                {"a3", node.a3},
                {"a4", node.a4},
                {"a5", node.a5}
            };
        }
        
        static void from_json(const json& j, IndexNode& node) {
            node.a1 = j.at("a1").get<std::string>();
            node.a2 = {j.at("a2")[0].get<size_t>(), j.at("a2")[1].get<std::string>()};
            node.a3 = j.at("a3").get<std::string>();
            node.a4 = j.at("a4").get<std::string>();
            node.a5 = j.at("a5").get<std::string>();
        }
    };

    // 为 LevelKey 添加序列化支持
    template<>
    struct adl_serializer<LevelKey> {
        static void to_json(json& j, const LevelKey& key) {
            j = json{
                {"key1", key.key1},
                {"key2", key.key2},
                {"key3", key.key3},
                {"key4", key.key4}
            };
        }
        
        static void from_json(const json& j, LevelKey& key) {
            key.key1 = j.at("key1").get<std::string>();
            key.key2 = j.at("key2").get<std::string>();
            key.key3 = j.at("key3").get<std::string>();
            key.key4 = j.at("key4").get<std::string>();
        }
    };

    // 为 Document 添加序列化支持
    template<>
    struct adl_serializer<Document> {
        static void to_json(json& j, const Document& doc) {
            j = json{
                {"id", doc.id},
                {"level", doc.level},
                {"keywords", doc.keywords},
                {"state", doc.state}
            };
        }
        
        static void from_json(const json& j, Document& doc) {
            doc.id = j.at("id").get<std::string>();
            doc.level = j.at("level").get<AccessLevel>();
            doc.keywords = j.at("keywords").get<std::set<Keyword>>();
            doc.state = j.at("state").get<State>();
        }
    };

    // 为 SearchToken 添加序列化支持
    template<>
    struct adl_serializer<SearchToken> {
        static void to_json(json& j, const SearchToken& token) {
            j = json{
                {"tau1", token.tau1},
                {"tau2", token.tau2},
                {"tau3", token.tau3},
                {"tau4", token.tau4}
            };
        }
        
        static void from_json(const json& j, SearchToken& token) {
            token.tau1 = j.at("tau1").get<std::string>();
            token.tau2 = j.at("tau2").get<std::string>();
            token.tau3 = j.at("tau3").get<std::string>();
            token.tau4 = j.at("tau4").get<std::vector<std::string>>();
        }
    };
} 