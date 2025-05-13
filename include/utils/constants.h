#pragma once
#include <cstdint>  // 为 uint8_t, uint32_t 等
#include <cstddef>  // 为 size_t
namespace constants {
    // 簇相关常量
    constexpr uint32_t MIN_CLUSTER_SIZE_3 = 3;
    constexpr uint32_t MIN_CLUSTER_SIZE_10 = 10;
    constexpr uint32_t MIN_CLUSTER_SIZE_256 = 256;
    constexpr uint32_t MIN_CLUSTER_SIZE_512 = 512;
    
    // 文档相关常量
    constexpr uint8_t MIN_ACCESS_LEVEL = 1;
    constexpr uint8_t MAX_ACCESS_LEVEL = 3;
    constexpr uint8_t MIN_STATE = 1;
    constexpr uint8_t MAX_STATE = 10;
    
    // 其他常量
    constexpr size_t MAX_KEYWORDS = 5000;
    constexpr double FREQ_DIFF_THRESHOLD = 0.15;  // 频率差异阈值

    constexpr const char* BASE_DIR = "/app/data/processed";
} 