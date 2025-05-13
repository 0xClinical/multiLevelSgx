#pragma once
#include <string>
#include <vector>
#include <map>
#include <type_traits>

// 简化的json类型定义
class json {
public:
    static json array() { return json(); }
    static json parse(const std::string& str) { return json(); }
    
    json() {}
    json(const std::string& s) : string_value(s) {}
    json(int i) : int_value(i) {}
    json(size_t s) : size_t_value(s) {}
    json(float f) : float_value(f) {}
    json(double d) : float_value(d) {}
    json(unsigned int u) : uint_value(u) {}
    json(bool b) : bool_value(b) {}
    json(const std::vector<std::string>& v) : vector_value(v) {}
    
    // 使用重载函数
    std::string get_string() const {
        return string_value;
    }
    
    size_t get_size_t() const {
        return static_cast<size_t>(std::stoul(string_value));
    }
    
    int get_int() const {
        return std::stoi(string_value);
    }
    
    bool get_bool() const {
        return string_value == "true";
    }
    
    std::vector<std::string> get_vector() const {
        return vector_value;
    }
    
    json& operator[](const std::string& key) {
        return map_value[key];
    }
    
    json& operator[](size_t index) {
        while (array_value.size() <= index) array_value.push_back(json());
        return array_value[index];
    }
    
    json& operator=(const std::vector<std::string>& v) {
        vector_value = v;
        return *this;
    }
    
    json& operator=(const std::map<std::string, size_t>& m) {
        for (const auto& [k, v] : m) {
            map_value[k] = json(v);
        }
        return *this;
    }
    
    json& operator=(const std::pair<std::string, std::string>& p) {
        map_value["first"] = json(p.first);
        map_value["second"] = json(p.second);
        return *this;
    }
    
    void push_back(const json& value) {
        array_value.push_back(value);
    }
    
    std::string dump() const { return "{}"; }
    
    class iterator {
    public:
        iterator(std::map<std::string, json>::iterator it) : map_it(it) {}
        
        bool operator!=(const iterator& other) const { return map_it != other.map_it; }
        iterator& operator++() { ++map_it; return *this; }
        
        std::string key() const { return map_it->first; }
        json& value() { return map_it->second; }
        
    private:
        std::map<std::string, json>::iterator map_it;
    };
    
    iterator begin() { return iterator(map_value.begin()); }
    iterator end() { return iterator(map_value.end()); }
    
    size_t size() const { return array_value.size(); }
    
    const std::map<std::string, json>& get_map() const {
        return map_value;
    }
    
    std::map<std::string, json>& get_map() {
        return map_value;
    }
    
    const std::vector<json>& get_array() const {
        return array_value;
    }
    
    const json& at(const std::string& key) const {
        return map_value.at(key);
    }
    
    // 添加一个辅助方法，获取数组中的所有字符串
    std::vector<std::string> get_string_array() const {
        std::vector<std::string> result;
        for (const auto& item : array_value) {
            result.push_back(item.get_string());
        }
        return result;
    }
    
    template<typename T>
    T get() const {
        // 使用函数重载而不是类型检查
        return get_impl(static_cast<T*>(nullptr));
    }
    
private:
    std::string string_value;
    int int_value = 0;
    size_t size_t_value = 0;
    float float_value = 0.0f;
    unsigned int uint_value = 0;
    bool bool_value = false;
    std::vector<std::string> vector_value;
    std::map<std::string, json> map_value;
    std::vector<json> array_value;
    
    // 使用函数重载处理不同类型
    std::string get_impl(std::string*) const {
        return string_value;
    }
    
    size_t get_impl(size_t*) const {
        return static_cast<size_t>(std::stoul(string_value));
    }
    
    int get_impl(int*) const {
        return std::stoi(string_value);
    }
    
    bool get_impl(bool*) const {
        return string_value == "true";
    }
    
    std::vector<std::string> get_impl(std::vector<std::string>*) const {
        return vector_value;
    }
    
    // 默认情况
    template<typename T>
    T get_impl(T*) const {
        return T(string_value);
    }
}; 