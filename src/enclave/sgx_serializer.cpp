#include "enclave/sgx_serializer.h"
#include <stdexcept>
#include <sstream>
#include "simple_json.hpp"  // 添加json头文件

namespace sgx_serializer {

// 简单的JSON解析器实现
class Parser {
public:
    Parser(const std::string& json) : json_(json), pos_(0) {}
    
    Value parse() {
        skip_whitespace();
        Value result = parse_value();
        skip_whitespace();
        if (pos_ < json_.size()) {
            throw std::runtime_error("Unexpected trailing characters");
        }
        return result;
    }
    
private:
    const std::string& json_;
    size_t pos_;
    
    void skip_whitespace() {
        while (pos_ < json_.size() && (json_[pos_] == ' ' || json_[pos_] == '\t' || 
               json_[pos_] == '\n' || json_[pos_] == '\r')) {
            ++pos_;
        }
    }
    
    Value parse_value() {
        skip_whitespace();
        if (pos_ >= json_.size()) {
            throw std::runtime_error("Unexpected end of input");
        }
        
        char c = json_[pos_];
        if (c == 'n') return parse_null();
        if (c == 't' || c == 'f') return parse_bool();
        if (c == '"') return parse_string();
        if (c == '[') return parse_array();
        if (c == '{') return parse_object();
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        
        throw std::runtime_error(std::string("Unexpected character"));
    }
    
    Value parse_null() {
        if (pos_ + 4 <= json_.size() && json_.substr(pos_, 4) == "null") {
            pos_ += 4;
            return Value();
        }
        throw std::runtime_error("Expected 'null'");
    }
    
    Value parse_bool() {
        if (pos_ + 4 <= json_.size() && json_.substr(pos_, 4) == "true") {
            pos_ += 4;
            return Value(true);
        }
        if (pos_ + 5 <= json_.size() && json_.substr(pos_, 5) == "false") {
            pos_ += 5;
            return Value(false);
        }
        throw std::runtime_error("Expected 'true' or 'false'");
    }
    
    Value parse_number() {
        size_t start = pos_;
        bool is_negative = false;
        
        if (json_[pos_] == '-') {
            is_negative = true;
            ++pos_;
        }
        
        while (pos_ < json_.size() && json_[pos_] >= '0' && json_[pos_] <= '9') {
            ++pos_;
        }
        
        if (pos_ == start + (is_negative ? 1 : 0)) {
            throw std::runtime_error("Invalid number format");
        }
        
        // 简单解析整数
        int64_t value = 0;
        for (size_t i = start + (is_negative ? 1 : 0); i < pos_; ++i) {
            value = value * 10 + (json_[i] - '0');
        }
        
        if (is_negative) value = -value;
        return Value(value);
    }
    
    Value parse_string() {
        ++pos_; // Skip opening quote
        std::string result;
        
        while (pos_ < json_.size() && json_[pos_] != '"') {
            if (json_[pos_] == '\\') {
                ++pos_;
                if (pos_ >= json_.size()) {
                    throw std::runtime_error("Unexpected end of input in string");
                }
                
                switch (json_[pos_]) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    default: result += json_[pos_]; break;
                }
            } else {
                result += json_[pos_];
            }
            ++pos_;
        }
        
        if (pos_ >= json_.size() || json_[pos_] != '"') {
            throw std::runtime_error("Unterminated string");
        }
        
        ++pos_; // Skip closing quote
        return Value(result);
    }
    
    Value parse_array() {
        ++pos_; // Skip opening bracket
        Value array;
        
        skip_whitespace();
        if (pos_ < json_.size() && json_[pos_] == ']') {
            ++pos_;
            return array;
        }
        
        while (true) {
            skip_whitespace();
            array.push_back(parse_value());
            
            skip_whitespace();
            if (pos_ >= json_.size()) {
                throw std::runtime_error("Unterminated array");
            }
            
            if (json_[pos_] == ']') {
                ++pos_;
                break;
            }
            
            if (json_[pos_] != ',') {
                throw std::runtime_error("Expected ',' or ']'");
            }
            
            ++pos_; // Skip comma
        }
        
        return array;
    }
    
    Value parse_object() {
        ++pos_; // Skip opening brace
        Value object;
        
        skip_whitespace();
        if (pos_ < json_.size() && json_[pos_] == '}') {
            ++pos_;
            return object;
        }
        
        while (true) {
            skip_whitespace();
            
            if (pos_ >= json_.size() || json_[pos_] != '"') {
                throw std::runtime_error("Expected string key");
            }
            
            Value key = parse_string();
            
            skip_whitespace();
            if (pos_ >= json_.size() || json_[pos_] != ':') {
                throw std::runtime_error("Expected ':'");
            }
            
            ++pos_; // Skip colon
            skip_whitespace();
            
            object[key.get_string()] = parse_value();
            
            skip_whitespace();
            if (pos_ >= json_.size()) {
                throw std::runtime_error("Unterminated object");
            }
            
            if (json_[pos_] == '}') {
                ++pos_;
                break;
            }
            
            if (json_[pos_] != ',') {
                throw std::runtime_error("Expected ',' or '}'");
            }
            
            ++pos_; // Skip comma
        }
        
        return object;
    }
};

Value parse(const std::string& json_str) {
    // 使用我们自己的Parser类
    try {
        Parser parser(json_str);
        return parser.parse();
    } catch (const std::exception& e) {
        // 如果解析失败，返回一个空对象
        // 直接返回parse_object方法的结果，它会创建一个空对象
        return Parser("{}").parse();
    }
}

} // namespace sgx_serializer 