#pragma once

#include <iostream>
#include <fstream>
#include <memory>
#include <random>
#include <vector>
#include <string>
#include "utils/types.h"
#include "sgx_urts.h"
#include "utils/dataset_loader.h"

/**
 * @brief 测试BM方案性能的类
 * 
 * 该类实现了对BM方案的性能测试，包括上传、删除和搜索操作的性能测试。
 */
class TestBM {
public:
    /**
     * @brief 构造函数
     * 
     * @param eid SGX Enclave ID
     */
    TestBM(sgx_enclave_id_t eid);
    
    /**
     * @brief 运行所有测试
     */
    void run(std::string test_name);
    /**
     * @brief 运行基本测试
     */
    void runBasicTest();
    /**
     * @brief 测试上传文档的性能
     */
    void testUploadPerformance();
    
    /**
     * @brief 测试搜索文档的性能
     */
    void testSearchPerformance();
    
    /**
     * @brief 上传测试文档
     * 
     * @param keyword 关键词
     * @param doc_count 文档数量
     * @return std::vector<Document> 上传的文档列表
     */
    std::vector<Document> uploadTestDocuments(const std::string& keyword, size_t doc_count);
    
    /**
     * @brief 测试删除文档的性能
     * 
     * @param all_docs 所有文档列表
     */
    void testDeletePerformance(std::vector<Document>& all_docs);
    /**
     * @brief 测试top10关键字的搜索时间
     */
    void testTop10KeywordSearchPerformance();
    /**
     * @brief 测试top10关键字的搜索时间，分别在删除百分之25，50，75的文档以后
     */
    void testTop10KeywordSearchPerformanceAfterDelete();
private:
    /**
     * @brief 设置测试用户
     */
    void setupUsers();

    void warmSearch();
    void warmupUpload();
    /**
     * @brief 记录测试结果
     * 
     * @param testName 测试名称
     * @param docCount 文档数量
     * @param time 执行时间
     * @param unit 时间单位
     */
    void logResult(const std::string& testName, size_t docCount, double time, const std::string& unit);
    
    // SGX Enclave ID
    sgx_enclave_id_t enclaveId;
    
    // 随机数生成器
    std::mt19937 rng;
    
    // 数据集加载器
    DatasetLoader* datasetLoader;
    
    // 测试用户列表
    std::vector<User> users;
    
    // 测试关键词
    std::string testKeyword;
    
    // 日志文件
    std::ofstream log_file;
    
    // 测试配置
    struct TestConfig {
        size_t numKeywords = 10;
        size_t numDocuments = 1000000;
        size_t batchSize = 100000;
    } config;
};
