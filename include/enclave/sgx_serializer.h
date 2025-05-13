#pragma once
#include <string>
#include <vector>
#include <map>
#include <type_traits>

// SGX兼容的序列化库 - 简化版本
namespace sgx_serializer {

// 前向声明
class Value;

// 值类型枚举
enum class ValueType {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object
};

// 基础值类
class Value {
public:
    Value() : type_(ValueType::Null) {}
    Value(bool val) : type_(ValueType::Boolean), bool_value_(val) {}
    Value(int val) : type_(ValueType::Number), int_value_(val) {}
    Value(size_t val) : type_(ValueType::Number), int_value_(static_cast<int64_t>(val)) {}
    Value(uint8_t val) : type_(ValueType::Number), int_value_(val) {}

    // 使用模板处理所有整数类型
    template<typename T, 
             typename = typename std::enable_if<std::is_integral<T>::value && !std::is_same<T, bool>::value>::type>
    Value(T val) : type_(ValueType::Number), int_value_(static_cast<int64_t>(val)) {}

    Value(const std::string& val) : type_(ValueType::String), string_value_(val) {}
    Value(const char* val) : type_(ValueType::String), string_value_(val ? val : "") {}
    
    // 复制构造函数
    Value(const Value& other);
    
    // 赋值操作符
    Value& operator=(const Value& other);
    
    // 类型检查
    bool is_null() const { return type_ == ValueType::Null; }
    bool is_bool() const { return type_ == ValueType::Boolean; }
    bool is_number() const { return type_ == ValueType::Number; }
    bool is_string() const { return type_ == ValueType::String; }
    bool is_array() const { return type_ == ValueType::Array; }
    bool is_object() const { return type_ == ValueType::Object; }
    
    // 获取值
    bool get_bool() const { return bool_value_; }
    int64_t get_int() const { return int_value_; }
    size_t get_size_t() const { return static_cast<size_t>(int_value_); }
    uint8_t get_uint8() const { return static_cast<uint8_t>(int_value_); }
    std::string get_string() const { return string_value_; }
    
    // 数组操作
    void push_back(const Value& value);
    Value& operator[](size_t index);
    const Value& operator[](size_t index) const;
    size_t size() const;
    
    // 对象操作
    Value& operator[](const std::string& key);
    const Value& operator[](const std::string& key) const;
    std::vector<std::string> keys() const;
    
    // 简单序列化 - 不使用stringstream
    std::string dump() const;
    // 迭代器类型定义
    using iterator = std::vector<Value>::iterator;
    using const_iterator = std::vector<Value>::const_iterator;
    
    // 数组迭代器方法
    iterator begin() {
        return (type_ == ValueType::Array) ? array_value_.begin() : iterator();
    }
    
    iterator end() {
        return (type_ == ValueType::Array) ? array_value_.end() : iterator();
    }
    
    const_iterator begin() const {
        return (type_ == ValueType::Array) ? array_value_.begin() : const_iterator();
    }
    
    const_iterator end() const {
        return (type_ == ValueType::Array) ? array_value_.end() : const_iterator();
    }
    
    // C++11 兼容性
    const_iterator cbegin() const {
        return (type_ == ValueType::Array) ? array_value_.cbegin() : const_iterator();
    }
    
    const_iterator cend() const {
        return (type_ == ValueType::Array) ? array_value_.cend() : const_iterator();
    }
private:
    ValueType type_;
    bool bool_value_ = false;
    int64_t int_value_ = 0;
    std::string string_value_;
    std::vector<Value> array_value_;
    std::map<std::string, Value> object_value_;
    
    // 辅助函数
    static std::string escape_string(const std::string& s);
    static std::string to_string(int64_t value);
    static std::string to_string(bool value);
};

// 解析函数
Value parse(const std::string& json_str);

// 实现部分
inline Value::Value(const Value& other) : type_(other.type_) {
    switch (type_) {
        case ValueType::Boolean:
            bool_value_ = other.bool_value_;
            break;
        case ValueType::Number:
            int_value_ = other.int_value_;
            break;
        case ValueType::String:
            string_value_ = other.string_value_;
            break;
        case ValueType::Array:
            array_value_ = other.array_value_;
            break;
        case ValueType::Object:
            object_value_ = other.object_value_;
            break;
        default:
            break;
    }
}

inline Value& Value::operator=(const Value& other) {
    if (this != &other) {
        type_ = other.type_;
        switch (type_) {
            case ValueType::Boolean:
                bool_value_ = other.bool_value_;
                break;
            case ValueType::Number:
                int_value_ = other.int_value_;
                break;
            case ValueType::String:
                string_value_ = other.string_value_;
                break;
            case ValueType::Array:
                array_value_ = other.array_value_;
                break;
            case ValueType::Object:
                object_value_ = other.object_value_;
                break;
            default:
                break;
        }
    }
    return *this;
}

inline void Value::push_back(const Value& value) {
    if (type_ != ValueType::Array) {
        type_ = ValueType::Array;
        array_value_.clear();
    }
    array_value_.push_back(value);
}

inline Value& Value::operator[](size_t index) {
    if (type_ != ValueType::Array) {
        type_ = ValueType::Array;
        array_value_.clear();
    }
    if (index >= array_value_.size()) {
        array_value_.resize(index + 1);
    }
    return array_value_[index];
}

inline const Value& Value::operator[](size_t index) const {
    static Value null_value;
    if (type_ != ValueType::Array || index >= array_value_.size()) {
        return null_value;
    }
    return array_value_[index];
}

inline size_t Value::size() const {
    if (type_ == ValueType::Array) {
        return array_value_.size();
    } else if (type_ == ValueType::Object) {
        return object_value_.size();
    }
    return 0;
}

inline Value& Value::operator[](const std::string& key) {
    if (type_ != ValueType::Object) {
        type_ = ValueType::Object;
        object_value_.clear();
    }
    return object_value_[key];
}

inline const Value& Value::operator[](const std::string& key) const {
    static Value null_value;
    if (type_ != ValueType::Object) {
        return null_value;
    }
    auto it = object_value_.find(key);
    return (it != object_value_.end()) ? it->second : null_value;
}

inline std::vector<std::string> Value::keys() const {
    std::vector<std::string> result;
    if (type_ == ValueType::Object) {
        for (const auto& pair : object_value_) {
            result.push_back(pair.first);
        }
    }
    return result;
}

// 简单的整数到字符串转换 - 不使用stringstream
inline std::string Value::to_string(int64_t value) {
    if (value == 0) return "0";
    
    bool negative = value < 0;
    if (negative) value = -value;
    
    std::string result;
    while (value > 0) {
        char digit = '0' + (value % 10);
        result = digit + result;
        value /= 10;
    }
    
    if (negative) result = "-" + result;
    return result;
}

inline std::string Value::to_string(bool value) {
    return value ? "true" : "false";
}

inline std::string Value::escape_string(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '\"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c >= 0 && c < 32) {
                    // 简化处理控制字符
                    result += " ";
                } else {
                    result += c;
                }
        }
    }
    return result;
}

inline std::string Value::dump() const {
    switch (type_) {
        case ValueType::Null:
            return "null";
        case ValueType::Boolean:
            return to_string(bool_value_);
        case ValueType::Number:
            return to_string(int_value_);
        case ValueType::String:
            return "\"" + escape_string(string_value_) + "\"";
        case ValueType::Array: {
            std::string result = "[";
            for (size_t i = 0; i < array_value_.size(); ++i) {
                if (i > 0) result += ",";
                result += array_value_[i].dump();
            }
            result += "]";
            return result;
        }
        case ValueType::Object: {
            std::string result = "{";
            bool first = true;
            for (const auto& pair : object_value_) {
                if (!first) result += ",";
                first = false;
                result += "\"" + escape_string(pair.first) + "\":" + pair.second.dump();
            }
            result += "}";
            return result;
        }
    }
    return "null"; // 默认返回
}

} // namespace sgx_serializer

// 使用sgx_serializer替代nlohmann::json
using SGXValue = sgx_serializer::Value; 