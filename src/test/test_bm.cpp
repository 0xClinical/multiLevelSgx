#include "test/test_bm.h"
#include "Enclave_u.h"
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include "utils/crypto.h"
#include <chrono>
#include "enclave/sgx_serializer.h"

TestBM::TestBM(sgx_enclave_id_t eid) : enclaveId(eid), rng(std::random_device()()) {
    // 初始化 BM 方案
    sgx_status_t retval;
    sgx_status_t status = ecall_init_bm_scheme(enclaveId, &retval);
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to initialize BM scheme: " << std::hex << status << std::endl;
        throw std::runtime_error("BM scheme initialization failed");
    }
    
    // 初始化数据集加载器
    datasetLoader = &dataset_loader;
    
    // 打开日志文件
    this->log_file.open("bm_test_results.csv");
    if (!log_file.is_open()) {
        throw std::runtime_error("Failed to open log file");
    }
    
    // 写入CSV头
    log_file << "TestName,DocCount,Time,Unit\n";
    
    // 设置测试用户
    setupUsers();
    
}

void TestBM::setupUsers() {
    std::cout << "Setting up test users..." << std::endl;
    
    // 只创建一个最高权限用户
    std::pair<std::string, std::string> pubkey_pair = CryptoUtils::generateKeyPair();
    std::vector<User> test_users = {
        {"user", 3, 10, pubkey_pair.first,pubkey_pair.second}  // 可搜索全部文档
    };
    // 注册用户
    for (const auto& user : test_users) {
        sgx_status_t retval;
        sgx_status_t status = ecall_bm_add_user(
            enclaveId,
            &retval,
            user.id.c_str(),
            user.level,
            user.state,
            user.publicKey.c_str()
        );
        
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to add user " << user.id << ": " << std::hex << status << std::endl;
        } else {
            std::cout << "Added user " << user.id << " with level " << (int)user.level 
                      << " and state " << (int)user.state << std::endl;
            users.push_back(user);
        }
    }
}

void TestBM::logResult(const std::string& testName, size_t docCount, double time, const std::string& unit) {
    log_file << testName << "," << docCount << "," << time << "," << unit << std::endl;
    std::cout << "Test: " << testName << ", Docs: " << docCount << ", Time: " 
              << std::fixed << std::setprecision(6) << time << " " << unit << std::endl;
}

void TestBM::run(std::string test_name) {
    if(test_name == "basic"){
        std::cout << "Running basic test..." << std::endl;
        runBasicTest();
    }else if(test_name == "top10"){
        std::cout << "Running top10 keyword search performance test..." << std::endl;
        testTop10KeywordSearchPerformance();
    }else if(test_name == "delete"){
        std::cout << "Running top10 keyword search performance after delete test..." << std::endl;
        testTop10KeywordSearchPerformanceAfterDelete();
    }
}
/*---------------------------------基本测试---------------------------------*/
void TestBM::runBasicTest(){
    //获取测试关键词
    auto top_keywords = datasetLoader->getTopKeywords(1);
    if (top_keywords.empty()) {
        throw std::runtime_error("No keywords found in dataset");
    }
    testKeyword = top_keywords[0].first;
    std::cout << "Using keyword: " << testKeyword << " for tests" << std::endl;
    //先上传一百万个文档,每次上传1000000个，每上传100000个输出进度
    std::vector<Document> all_docs;
    std::vector<Document> docs = uploadTestDocuments(testKeyword, 1000000);
    all_docs.insert(all_docs.end(), docs.begin(), docs.end());
        
    std::vector<size_t> batch_sizes = {10,100,1000,10000};
    //删除不同d值的文档
    for (size_t batch_size : batch_sizes) {
        sgx_status_t retval;
        std::cout << "Deleting " << batch_size << " documents" << std::endl;
        
        // 从all_docs中选择文档的id
        std::vector<std::string> doc_ids;
        doc_ids.reserve(batch_size);
        
        for (size_t i = 0; i < batch_size && !all_docs.empty(); i++) {
            doc_ids.push_back(all_docs[all_docs.size() - 1 - i].id);  // 总是取最后一个元素
            all_docs.erase(all_docs.begin() + all_docs.size() - 1 - i);   // 删除最后一个元素
        }

        // 将doc_ids转换为JSON字符串
        SGXValue doc_ids_json;
        for (const auto& id : doc_ids) {
            doc_ids_json.push_back(id);
        }
        std::string json_str = doc_ids_json.dump();
        std::cout << "Deleting " << doc_ids.size() << " documents" << std::endl;
        // 删除batch_size个文档
        if (!doc_ids.empty()) {
            sgx_status_t delete_status = ecall_bm_delete_documents(
                enclaveId,
                &retval,
                testKeyword.c_str(),
                json_str.c_str(),
                doc_ids.size()
            );
            if (delete_status != SGX_SUCCESS) {
                std::cerr << "Failed to delete documents: " << std::hex << delete_status << std::endl;
            }
        } else {
            std::cout << "No documents to delete" << std::endl;
        }
        
        // 运行上传性能测试
        warmupUpload();
        testUploadPerformance();
        
        if(batch_size == 1000){
            // 运行删除性能测试
            testDeletePerformance(all_docs);
        }
        std::cout << "Search performance test result for delete " << batch_size << " documents" << std::endl;
        // 运行搜索性能测试
        warmSearch();
        testSearchPerformance();
    }
}

std::vector<Document> TestBM::uploadTestDocuments(const std::string& keyword, size_t doc_count) {
    std::cout << "Uploading " << doc_count << " documents..." << std::endl;
    // 从数据集加载文档
    std::vector<Document> all_docs;
    try {
        // 获取关键词对应的所有文档
        if(doc_count == 0){
            all_docs = datasetLoader->getDocumentsByKeyword(keyword);
        }else{
            all_docs = datasetLoader->getDocumentsByKeyword(keyword,doc_count);
        }
        std::cout << "all_docs: " << all_docs.size() << std::endl;
        //将文档转换为JSON
        SGXValue docs_json;
        for (const auto& doc : all_docs) {
            SGXValue doc_json;
            doc_json["id"] = doc.id;
            doc_json["level"] = static_cast<int>(doc.level);
            doc_json["state"] = static_cast<int>(doc.state);
            doc_json["isBogus"] = doc.isBogus;
            docs_json.push_back(doc_json);
        }
        
        std::string docs_str = docs_json.dump();
        //上传到enclave
        sgx_status_t retval;
        sgx_status_t status = ecall_bm_upload_documents(
            enclaveId,
            &retval,
            keyword.c_str(),
            docs_str.c_str(),
            docs_str.size()
        );
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
        }
        //重建索引
        sgx_status_t rebuild_status = ecall_bm_rebuild_indices(enclaveId, &retval);
        if (rebuild_status != SGX_SUCCESS) {
            std::cerr << "Failed to rebuild indices: " << std::hex << rebuild_status << std::endl;
        }
        return all_docs;
    } catch (const std::exception& e) {
        std::cerr << "Error loading documents: " << e.what() << std::endl;
        return std::vector<Document>();
    }
    
    
}   
void TestBM::warmupUpload(){
    const size_t TOTAL_DOCUMENTS = 10;
    //从数据集中加载文档
    std::vector<Document> all_docs;
    for(size_t i = 0; i < TOTAL_DOCUMENTS; i++){
        Document doc = datasetLoader->getBogusDocument(testKeyword);
        all_docs.push_back(doc);
    }
    //将文档转换为JSON
    SGXValue docs_json ;
    for (const auto& doc : all_docs) {
        SGXValue doc_json;
        doc_json["id"] = doc.id;
        doc_json["level"] = static_cast<int>(doc.level);
        doc_json["state"] = static_cast<int>(doc.state);
        doc_json["isBogus"] = doc.isBogus;
        docs_json.push_back(doc_json);
    }
    std::string docs_str = docs_json.dump();
    //上传到enclave
    sgx_status_t retval;
    sgx_status_t status = ecall_bm_upload_documents(
        enclaveId,
        &retval,
        testKeyword.c_str(),
        docs_str.c_str(),
        docs_str.size()
    );
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
    }
    //重建索引
    sgx_status_t rebuild_status = ecall_bm_rebuild_indices(enclaveId, &retval);
    if (rebuild_status != SGX_SUCCESS) {
        std::cerr << "Failed to rebuild indices: " << std::hex << rebuild_status << std::endl;
    }
    //删除文档
    std::vector<const char*> doc_ids;
    doc_ids.reserve(all_docs.size());
    std::vector<std::string> doc_ids_str;
    doc_ids_str.reserve(all_docs.size());

    for (const auto& doc : all_docs) {
        doc_ids_str.push_back(doc.id);
    }

    for (const auto& id : doc_ids_str) {
        doc_ids.push_back(id.c_str());
    }
    //将doc_ids转换为JSON字符串
    SGXValue doc_ids_json;
    for (const auto& id : doc_ids) {
        doc_ids_json.push_back(id);
    }
    std::string json_str = doc_ids_json.dump();
    sgx_status_t delete_status = ecall_bm_delete_documents(
        enclaveId,
        &retval,
        testKeyword.c_str(),
        json_str.c_str(),
        doc_ids.size()
    );
    if (delete_status != SGX_SUCCESS) {
        std::cerr << "Failed to delete documents: " << std::hex << delete_status << std::endl;
    }
 
}
void TestBM::testUploadPerformance() {
    std::cout << "Testing upload performance..." << std::endl;
    
    // 上传十万个文档
    const size_t TOTAL_DOCUMENTS = 100000;
    //从数据集中加载文档
    std::vector<Document> all_docs;
    for(size_t i = 0; i < TOTAL_DOCUMENTS; i++){
        Document doc = datasetLoader->getBogusDocument(testKeyword);
        all_docs.push_back(doc);
    }
    //将文档转换为JSON
    SGXValue docs_json ;
    for (const auto& doc : all_docs) {
        SGXValue doc_json;
        doc_json["id"] = doc.id;
        doc_json["level"] = static_cast<int>(doc.level);
        doc_json["state"] = static_cast<int>(doc.state);
        doc_json["isBogus"] = doc.isBogus;
        docs_json.push_back(doc_json);
    }
    std::string docs_str = docs_json.dump();
    //上传到enclave
    sgx_status_t retval;
    //记录开始时间
    auto start = std::chrono::high_resolution_clock::now();
    sgx_status_t status = ecall_bm_upload_documents(
        enclaveId,
        &retval,
        testKeyword.c_str(),
        docs_str.c_str(),
        docs_str.size()
    );
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
    }
    //重建索引
    sgx_status_t rebuild_status = ecall_bm_rebuild_indices(enclaveId, &retval);
    if (rebuild_status != SGX_SUCCESS) {
        std::cerr << "Failed to rebuild indices: " << std::hex << rebuild_status << std::endl;
    }
    //记录结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    //平均时间
    double avg_time = duration.count() / TOTAL_DOCUMENTS;
    logResult("Upload_100000_Docs", TOTAL_DOCUMENTS, avg_time/1000, "ms/doc");
    //删除文档
    std::vector<const char*> doc_ids;
    doc_ids.reserve(all_docs.size());
    std::vector<std::string> doc_ids_str;
    doc_ids_str.reserve(all_docs.size());

    for (const auto& doc : all_docs) {
        doc_ids_str.push_back(doc.id);
    }

    for (const auto& id : doc_ids_str) {
        doc_ids.push_back(id.c_str());
    }
    //将doc_ids转换为JSON字符串
    SGXValue doc_ids_json;
    for (const auto& id : doc_ids) {
        doc_ids_json.push_back(id);
    }
    std::string json_str = doc_ids_json.dump();
    sgx_status_t delete_status = ecall_bm_delete_documents(
        enclaveId,
        &retval,
        testKeyword.c_str(),
        json_str.c_str(),
        doc_ids.size()
    );
    if (delete_status != SGX_SUCCESS) {
        std::cerr << "Failed to delete documents: " << std::hex << delete_status << std::endl;
    }
 
}

void TestBM::testDeletePerformance(std::vector<Document>& all_docs) {
    std::cout << "Testing delete performance..." << std::endl;
    
    // 确定要删除的文档数量
    size_t delete_count = std::min(static_cast<size_t>(1000), all_docs.size());
    std::vector<std::string> doc_ids;
    doc_ids.reserve(delete_count);
    
    // 从后向前获取文档ID
    for(size_t i = 0; i < delete_count; i++){
        if (i < all_docs.size()) {
            doc_ids.push_back(all_docs[all_docs.size() - 1 - i].id);
            all_docs.erase(all_docs.begin() + all_docs.size() - 1 - i);
        }
    }
    
    // 将doc_ids转换为JSON字符串
    SGXValue doc_ids_json;
    for (const auto& id : doc_ids) {
        doc_ids_json.push_back(id);
    }
    std::string json_str = doc_ids_json.dump();
    
    // 开始时间
    auto start = std::chrono::high_resolution_clock::now();

    sgx_status_t retval;
    sgx_status_t delete_status = ecall_bm_delete_documents(
        enclaveId, 
        &retval, 
        testKeyword.c_str(), 
        json_str.c_str(), 
        delete_count
    );
        
    if (delete_status != SGX_SUCCESS) {
        std::cerr << "Failed to delete documents: " << std::hex << delete_status << std::endl;
    }
    
    
    // 结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    
    // 平均时间(us)
    double avg_time = duration.count() / delete_count;
    logResult("Delete_" + std::to_string(delete_count) + "_Docs", delete_count, avg_time, "us/doc");
}
void TestBM::warmSearch(){
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 100 * 1024 * 1024; // 100MB
   
    size_t actual_size = 0;
    sgx_status_t retval;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    char* results_buffer = new char[MAX_RESULTS_SIZE];
   
    //搜索
    sgx_status_t status = ecall_bm_search(
        enclaveId,
        &retval,
        user.id.c_str(),
        encrypted_id.c_str(),
        testKeyword.c_str(),
        0,
        results_buffer,
        MAX_RESULTS_SIZE,
        &actual_size
    );
    
    delete[] results_buffer;
}
void TestBM::testSearchPerformance() {
    std::cout << "Testing search performance for keyword: " << testKeyword << std::endl;
    //分别搜索200000,400000,600000,800000,1000000个文档并记录搜索时间
    std::vector<size_t> doc_counts = {200000,400000,600000,800000,1000000};
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 500MB
   
    size_t actual_size = 0;
    sgx_status_t retval;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    for(size_t i = 0; i < doc_counts.size(); i++){
        char* results_buffer = new char[MAX_RESULTS_SIZE];
        //记录开始时间
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        sgx_status_t status = ecall_bm_search(
            enclaveId,
            &retval,
            user.id.c_str(),
            encrypted_id.c_str(),
            testKeyword.c_str(),
            doc_counts[i],
            results_buffer,
            MAX_RESULTS_SIZE,
            &actual_size
        );
        //记录结束时间
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::micro> duration = end - start;
        //输出消耗时间
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to search for keyword " << testKeyword << ": " << std::hex << status << std::endl;
        } else {
            // 解析结果数量
            try {
                std::string results_str(results_buffer, actual_size);
                SGXValue results_json = sgx_serializer::parse(results_str);
                size_t result_count = results_json.size();
                
                // 将时间从微秒转换为秒，保留小数
                double time_seconds = duration.count() / 1000000.0;
                
                std::cout << "Search_" + std::to_string(doc_counts[i]) + "_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << time_seconds << "s" << std::endl;
                
                logResult("Search_" + testKeyword + "_" + std::to_string(doc_counts[i]), 
                         doc_counts[i], time_seconds, "s");
            } catch (const std::exception& e) {
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }  
        // 释放缓冲区
        delete[] results_buffer;
    }
   
}

/*---------------------------------top10关键字搜索测试---------------------------------*/

void TestBM::testTop10KeywordSearchPerformance(){
     // 初始化 BM 方案
    sgx_status_t retval;
    sgx_status_t status = ecall_init_bm_scheme(enclaveId, &retval);
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to initialize BM scheme: " << std::hex << status << std::endl;
        throw std::runtime_error("BM scheme initialization failed");
    }
    //setupUsers();
    std::cout << "Testing top 10 keyword search performance..." << std::endl;
    //获取top10关键字
    auto top_keywords = datasetLoader->getTopKeywords(10);
    size_t actual_size = 0;
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 500MB
    User user = users[0];
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    for(size_t i = 0; i < top_keywords.size(); i++){
        char* results_buffer = new char[MAX_RESULTS_SIZE];
        std::string keyword = top_keywords[i].first;
        std::cout << "keyword: " << keyword << std::endl;
        //上传测试文档
        uploadTestDocuments(keyword, 0);
        //重建索引
        sgx_status_t rebuild_status = ecall_bm_rebuild_indices(enclaveId, &retval);
        if (rebuild_status != SGX_SUCCESS) {
            std::cerr << "Failed to rebuild indices: " << std::hex << rebuild_status << std::endl;
        }
        
        //测试搜索时间并记录
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        sgx_status_t status = ecall_bm_search(
            enclaveId,
            &retval,
            user.id.c_str(),
            encrypted_id.c_str(),
            keyword.c_str(),
            0,
            results_buffer,
            MAX_RESULTS_SIZE,
            &actual_size
        );
         //记录结束时间
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double, std::micro> duration = end - start;
        //输出消耗时间
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to search for keyword " << testKeyword << ": " << std::hex << status << std::endl;
        } else {
            // 解析结果数量
            try {
                std::string results_str(results_buffer, actual_size);
                SGXValue results_json = sgx_serializer::parse(results_str);
                size_t result_count = results_json.size();
                
                // 将时间从微秒转换为秒，保留小数
                double time_seconds = duration.count() / 1000000.0;
                
                std::cout << "Search_" + keyword + "_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << time_seconds << "s" << std::endl;
                
                logResult("Search_" + keyword, 
                         result_count, time_seconds, "s");
            } catch (const std::exception& e) {
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }  
        // 释放缓冲区
        delete[] results_buffer;
    }
}

/*---------------------------------top10关键字搜索测试---------------------------------*/
void TestBM::testTop10KeywordSearchPerformanceAfterDelete(){
    //获取top10关键字
    auto top_keywords = datasetLoader->getTopKeywords(10);
    std::map<std::string, std::vector<Document>> docs_map;
    //上传测试文档
    for(size_t i = 0; i < top_keywords.size(); i++){
        std::string keyword = top_keywords[i].first;
        std::cout << "Uploading " << keyword << " documents" << std::endl;
        std::vector<Document> docs = uploadTestDocuments(keyword, 0);
        docs_map[keyword] = docs;
    }
    sgx_status_t retval;
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 500MB
    size_t actual_size = 0;
    //删除百分之25，50，75的文档
    for(const auto& [keyword, docs] : docs_map){
            //分别在删除百分之25，50，75的文档以后测试这十个关键字的搜索时间
        for(size_t i = 1; i < 4; i++){
            //删除百分之25，50，75的文档
            std::vector<Document> delete_docs;
            for(size_t j = docs.size() * i / 4; j < docs.size() * (i + 1) / 4; j++){
                delete_docs.push_back(docs[j]);
            }
            //将delete_docs转换为JSON字符串
            SGXValue delete_docs_json;
            for(const auto& doc : delete_docs){
                delete_docs_json.push_back(doc.id);
            }
            std::string json_str = delete_docs_json.dump();
            sgx_status_t status = ecall_bm_delete_documents(
                    enclaveId,
                    &retval,
                    keyword.c_str(),
                    json_str.c_str(),
                    delete_docs.size()
                );
                if (status != SGX_SUCCESS) {
                    std::cerr << "Failed to delete documents: " << std::hex << status << std::endl;
                }
            //测试搜索时间
            std::cout << "Testing " << keyword << " after deleting " << i * 25 << "% of documents" << std::endl;
            std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
            char* results_buffer = new char[MAX_RESULTS_SIZE];
            auto start = std::chrono::high_resolution_clock::now();
            //搜索
            status = ecall_bm_search(
                enclaveId,
                &retval,
                user.id.c_str(),
                encrypted_id.c_str(),
                keyword.c_str(),
                0,
                results_buffer,
                MAX_RESULTS_SIZE,
                &actual_size
            );
            //记录结束时间
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::micro> duration = end - start;
            //输出消耗时间
            if (status != SGX_SUCCESS) {
                std::cerr << "Failed to search for keyword " << testKeyword << ": " << std::hex << status << std::endl;
            } else {
                // 解析结果数量
                try {
                    std::string results_str(results_buffer, actual_size);
                    SGXValue results_json = sgx_serializer::parse(results_str);
                    size_t result_count = results_json.size();

                    std::cout << "Search_" + keyword + "_Docs," 
                              << ", Time: " << duration.count()  << "us" << std::endl;
                    
                    logResult("Search_" + keyword, 
                             result_count, duration.count() , "us");
                } catch (const std::exception& e) {
                    std::cerr << "Error parsing search results: " << e.what() << std::endl;
                }
            }  
            // 释放缓冲区
            delete[] results_buffer;
        }   
            
           
        }
    
    
}