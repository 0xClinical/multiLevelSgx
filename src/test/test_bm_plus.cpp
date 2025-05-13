#include "test/test_bm_plus.h"
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

TestBMPlus::TestBMPlus(sgx_enclave_id_t eid) : enclaveId(eid), rng(std::random_device()()) {
    // 初始化 BM++ 方案
    sgx_status_t retval;
    sgx_status_t status = ecall_init_bm_plus_scheme(enclaveId, &retval);
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to initialize BM plus scheme: " << std::hex << status << std::endl;
        throw std::runtime_error("BM plus scheme initialization failed");
    }
    
    // 初始化数据集加载器
    datasetLoader = &dataset_loader;
    
    // 打开日志文件
    this->log_file.open("bm_plus_test_results.csv");
    if (!log_file.is_open()) {
        throw std::runtime_error("Failed to open log file");
    }
    
    // 写入CSV头
    log_file << "TestName,DocCount,Time,Unit\n";
    
    // 设置测试用户
    setupUsers();
    
    testClusterIndex = 0;
}

void TestBMPlus::setupUsers() {
    std::cout << "Setting up test users..." << std::endl;
    
    // 只创建一个最高权限用户
    std::pair<std::string, std::string> pubkey_pair = CryptoUtils::generateKeyPair();
    std::vector<User> test_users = {
        {"user", 3, 10, pubkey_pair.first,pubkey_pair.second}  // 可搜索全部文档
    };
    // 注册用户
    for (const auto& user : test_users) {
        sgx_status_t retval;
        sgx_status_t status = ecall_bm_plus_add_user(
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

void TestBMPlus::logResult(const std::string& testName, size_t docCount, double time, const std::string& unit) {
    // 写入CSV，保持原格式
    log_file << testName << "," << docCount << "," << time << "," << unit << std::endl;
    // 显示固定小数点格式，保留6位小数
    std::cout << "Test: " << testName << ", Docs: " << docCount << ", Time: " 
              << std::fixed << std::setprecision(6) << time << " " << unit << std::endl;
}

void TestBMPlus::run(std::string test_name) {
    if(test_name == "top10"){
        std::cout << "Running top10 cluster search test..." << std::endl;
        runTop10ClusterSearchTest();
    }else if(test_name == "basic"){
        std::cout << "Running basic test..." << std::endl;
        runBasicTest();
    }else if(test_name == "delete"){
        std::cout << "Running top10 keyword search performance after delete test..." << std::endl;
        runTop10SearchTest();
    }else{
        std::cout << "Invalid test name" << std::endl;
    }

}

/*---------------------------------基本测试---------------------------------*/

//运行基本测试(添加时间，删除时间，搜索时间)
void TestBMPlus::runBasicTest() {
    std::cout << "runBasicTest" << std::endl;
    auto cluster_data = datasetLoader->getAllClusters();
    //将第2个簇内的关键字的文档上传到enclave
    auto test_cluster = cluster_data[testClusterIndex];
    auto keywords = test_cluster.keywords;
    testKeyword = keywords[0];
    std::cout << "Using keyword: " << testKeyword << " for tests" << std::endl;
    //先上传一百万个文档,每次上传100000个，每上传100000个输出进度
    std::vector<Document> all_docs;
    for(auto& kw : keywords){
        if(kw == testKeyword){
            std::vector<Document> docs = uploadTestDocuments(kw, 0);
            all_docs.insert(all_docs.end(), docs.begin(), docs.end());
        }else{
            std::vector<Document> docs = uploadTestDocuments(kw, 0);
        }
    }
    std::vector<size_t> batch_sizes = {3,33,333,3333};
   for(size_t batch_size : batch_sizes){
        sgx_status_t retval;
        std::cout << "Deleting " << batch_size << " documents" << std::endl;
        
        // 从all_docs中选择文档的id
        std::vector<std::string> doc_ids;
        
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
            sgx_status_t delete_status = ecall_bm_plus_delete_documents(
                enclaveId,
                &retval,
                testKeyword.c_str(),
                json_str.c_str(),
                doc_ids.size()
            );
            if (delete_status != SGX_SUCCESS) {
                std::cerr << "Failed to delete documents: " << std::hex << delete_status << std::endl;
            }
            //重加密
            sgx_status_t reencrypt_status = ecall_bm_plus_reencrypt_cluster(enclaveId, &retval, testClusterIndex);
            if (reencrypt_status != SGX_SUCCESS) {
                std::cerr << "Failed to reencrypt cluster: " << std::hex << reencrypt_status << std::endl;
            }

        } else {
            std::cout << "No documents to delete" << std::endl;
        }
        
        // 运行上传性能测试
        testUploadPerformance();
        
        if(batch_size == 1000){
            // 运行删除性能测试
            testDeletePerformance(all_docs);
        }
        std::cout << "Search performance test result for delete " << batch_size << " documents" << std::endl;
        // 运行搜索性能测试
        testSearchPerformance();
   }
}

void TestBMPlus::testUploadPerformance() {
    std::cout << "Testing upload performance..." << std::endl;
    
    // 上传十万个文档
    const size_t TOTAL_DOCUMENTS = 10000;
    //从数据集中加载文档
    std::vector<Document> all_docs;
    for(size_t i = 0; i < TOTAL_DOCUMENTS; i++){
        Document doc = datasetLoader->getBogusDocument(testKeyword);
        doc.isBogus = false;
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
    sgx_status_t status = ecall_bm_plus_upload_documents(
        enclaveId,
        &retval,
        testKeyword.c_str(),
        docs_str.c_str(),
        docs_str.size()
    );
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
    }
    //记录结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> duration = end - start;
    //平均时间
    double avg_time = duration.count() / TOTAL_DOCUMENTS;
    logResult("Upload_10000_Docs", TOTAL_DOCUMENTS, avg_time/1000, "ms/doc");
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
    SGXValue doc_ids_json ;
    for (const auto& id : doc_ids) {
        doc_ids_json.push_back(id);
    }
    std::string json_str = doc_ids_json.dump();
    sgx_status_t delete_status = ecall_bm_plus_delete_documents(
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

void TestBMPlus::testDeletePerformance(std::vector<Document>& all_docs) {
    std::cout << "Testing delete performance..." << std::endl;
    
    // 确定要删除的文档数量
    size_t delete_count = std::min(static_cast<size_t>(100000), all_docs.size());
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
    sgx_status_t delete_status = ecall_bm_plus_delete_documents(
        enclaveId, 
        &retval, 
        testKeyword.c_str(), 
        json_str.c_str(), 
        delete_count
    );
    //重加密
    sgx_status_t reencrypt_status = ecall_bm_plus_reencrypt_cluster(enclaveId, &retval, testClusterIndex);
    if (reencrypt_status != SGX_SUCCESS) {
        std::cerr << "Failed to reencrypt cluster: " << std::hex << reencrypt_status << std::endl;
    }
        
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

void TestBMPlus::testSearchPerformance() {
  std::cout << "Testing search performance for keyword: " << testKeyword << std::endl;
    //分别搜索200000,400000,600000,800000,1000000个文档并记录搜索时间
    std::vector<size_t> doc_counts = {200000,400000,600000,800000,1000000};
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 100MB
   
    size_t actual_size = 0;
    sgx_status_t retval;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    for(size_t i = 0; i < doc_counts.size(); i++){
        char* results_buffer = new char[MAX_RESULTS_SIZE];
        //记录开始时间
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        sgx_status_t status = ecall_bm_plus_search(
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
                
                std::cout << "Search_" + std::to_string(doc_counts[i]) + "_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << duration.count()/1000000 << "s" << std::endl;
                
                logResult("Search_" + testKeyword + "_" + std::to_string(doc_counts[i]), 
                         result_count, duration.count()/1000000, "s");
            } catch (const std::exception& e) {
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }  
        // 释放缓冲区
        delete[] results_buffer;
    }
}
std::vector<Document> TestBMPlus::uploadTestDocuments(const std::string& keyword, size_t doc_count) {
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
        sgx_status_t status = ecall_bm_plus_upload_documents(
            enclaveId,
            &retval,
            keyword.c_str(),
            docs_str.c_str(),
            docs_str.size()
        );
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
        }
        return all_docs;
    } catch (const std::exception& e) {
        std::cerr << "Error loading documents: " << e.what() << std::endl;
        return std::vector<Document>();
    }
    
    
}   


/*---------------------------------流式上传文档测试内存---------------------------------*/

//流式上传所有文档并测试sgx的内存变化以及edb的内存变化数据（线性）
void TestBMPlus::runMemoryTest(){
    //  重新初始化 BM++ 方案
    sgx_status_t retval;
    sgx_status_t status = ecall_init_bm_plus_scheme(enclaveId, &retval);
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to initialize BM plus scheme: " << std::hex << status << std::endl;
        throw std::runtime_error("BM plus scheme initialization failed");
    }
    setupUsers();
    //流式上传所有文档
    streamUploadDocuments();
}
///流式上传文档到enclave
void TestBMPlus::streamUploadDocuments() {
    std::vector<Document> all_docs = datasetLoader->getAllDocuments();
    std::cout << "Streaming upload all documents..." << std::endl;
    //将文档打乱之后转换为JSON
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(all_docs.begin(), all_docs.end(), g);
    for (const auto& doc : all_docs) {
        std::string keyword = datasetLoader->getKeywordById(doc.id);
        if(keyword.empty()){
            std::cerr << "Failed to get keyword for document: " << doc.id << std::endl;
            continue;
        }
        sgx_status_t retval;
        sgx_status_t status = ecall_bm_plus_upload_document(
            enclaveId,
            &retval,
            keyword.c_str(),
            doc.id.c_str(),
            doc.level,
            doc.state
        );

        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
        }
    }
} 

/*---------------------------------top10关键字搜索测试---------------------------------*/

//测试top10关键字的搜索时间
void TestBMPlus::runTop10SearchTest(){
    Top10SearchPreparation();
    Top10SearchPerformance();
}
//准备工作，初始化bm++以及上传文档
void TestBMPlus::Top10SearchPreparation(){
     //  重新初始化 BM++ 方案
    sgx_status_t retval;
    sgx_status_t status = ecall_init_bm_plus_scheme(enclaveId, &retval);
    if (status != SGX_SUCCESS) {
        std::cerr << "Failed to initialize BM plus scheme: " << std::hex << status << std::endl;
        throw std::runtime_error("BM plus scheme initialization failed");
    }
    setupUsers();
    
    //获取所有簇，并对每一个簇内的关键字上传他们的所有文档
    auto cluster_data = datasetLoader->getAllClusters();
    for(size_t i = 0; i < 2; i++){
        auto cluster = cluster_data[i];
        for(const auto& keyword : cluster.keywords){
            std::vector<Document> docs = datasetLoader->getDocumentsByKeyword(keyword);
            //将文档转换为JSON
            SGXValue docs_json;
            for (const auto& doc : docs) {
                SGXValue doc_json;
                doc_json["id"] = doc.id;
                doc_json["level"] = static_cast<int>(doc.level);
                doc_json["state"] = static_cast<int>(doc.state);
                doc_json["isBogus"] = doc.isBogus;
                docs_json.push_back(doc_json);
            }
            std::string docs_str = docs_json.dump();
            //上传到enclave
            sgx_status_t status = ecall_bm_plus_upload_documents(
                enclaveId,
                &retval,
                keyword.c_str(),
                docs_str.c_str(),
                docs_str.size()
            );
            if (status != SGX_SUCCESS) {
                std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
            }
        }


    }


}
//测试top10关键字的搜索时间
void TestBMPlus::Top10SearchPerformance(){
    sgx_status_t retval;
    //分别在删除百分之25，50，75的文档以后测试这十个关键字的搜索时间
    auto cluster_data = datasetLoader->getAllClusters();
    for (size_t i = 0; i < 2; i++)
    {
        auto cluster = cluster_data[i];
        for(const auto& keyword : cluster.keywords){
            std::vector<Document> docs = datasetLoader->getDocumentsByKeyword(keyword);
            std::cout << "keyword: " << keyword << " docs size: " << docs.size() << std::endl;
        }
    }
    
    for(size_t i = 0; i < 2; i++){
        auto cluster = cluster_data[i];
        for(size_t j = 0; j < 3; j++){
            for(const auto& keyword : cluster.keywords){
                //删除百分之25，50，75的文档
                std::vector<Document> docs = datasetLoader->getDocumentsByKeyword(keyword);
                std::cout << "keyword: " << keyword << " docs size: " << docs.size() << std::endl;
                 //将删除的文档转换为JSON
                SGXValue delete_docs_json;
                for(size_t k = docs.size() * j / 4; k < docs.size() * (j + 1) / 4; k++){
                    SGXValue doc_json;
                    doc_json["id"] = docs[k].id;
                    delete_docs_json.push_back(doc_json);
                }
                std::string delete_docs_str = delete_docs_json.dump();
                //删除文档
                sgx_status_t status = ecall_bm_plus_delete_documents(
                    enclaveId,
                    &retval,
                    keyword.c_str(),
                    delete_docs_str.c_str(),
                    delete_docs_str.size()
                );
                if (status != SGX_SUCCESS) {
                    std::cerr << "Failed to delete documents: " << std::hex << status << std::endl;
                }
                
            }
           
            sgx_status_t reencrypt_status = ecall_bm_plus_reencrypt_cluster(enclaveId, &retval, i);
            if (reencrypt_status != SGX_SUCCESS) {
                std::cerr << "Failed to reencrypt cluster: " << std::hex << reencrypt_status << std::endl;
            }
            
            //测试簇中搜索时间
            std::cout << "Testing cluster " << i << " after deleting " << (j+1) * 25 << "% of documents" << std::endl;
            testTop10SearchPerformance(cluster.keywords);
        }
    }
}
void TestBMPlus::testTop10SearchPerformance(std::vector<std::string> keywords){
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 100MB
    size_t actual_size = 0;
    sgx_status_t retval;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    //搜索top10关键字
    for(const auto& keyword : keywords){
        std::cout << "Searching for keyword: " << keyword << std::endl;
         char* results_buffer = new char[MAX_RESULTS_SIZE];
        //记录开始时间
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        sgx_status_t status = ecall_bm_plus_search(
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
            std::cerr << "Failed to search for keyword " << keyword << ": " << std::hex << status << std::endl;
        } else {
            // 解析结果数量
            try {
                std::string results_str(results_buffer, actual_size);
                SGXValue results_json = sgx_serializer::parse(results_str);
                size_t result_count = results_json.size();
                
                std::cout << "Search_" << keyword <<"_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << duration.count() << "us" << std::endl;
                
                logResult("Search_" + keyword + "_" + "max", 
                         result_count, duration.count(), "us");
            } catch (const std::exception& e) {
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }  
        // 释放缓冲区
        delete[] results_buffer;
    }
}
    
/*---------------------------------top10簇搜索测试---------------------------------*/

//测试top10簇的搜索时间
void TestBMPlus::runTop10ClusterSearchTest(){
    Top10ClusterSearchPreparation();
    //Top10ClusterSearchPerformance();
}
//准备工作，初始化bm++以及上传文档
void TestBMPlus::Top10ClusterSearchPreparation(){
    //  重新初始化 BM++ 方案
    sgx_status_t retval;
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 100MB
    size_t actual_size = 0;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    //获取前10个簇，并对每一个簇内的关键字上传他们的所有文档
    auto cluster_data = datasetLoader->getAllClusters();
    for(size_t i = 5; i < 10; i++){
         //  重新初始化 BM++ 方案
        sgx_status_t status = ecall_init_bm_plus_scheme(enclaveId, &retval);
        if (status != SGX_SUCCESS) {
            std::cerr << "Failed to initialize BM plus scheme: " << std::hex << status << std::endl;
            throw std::runtime_error("BM plus scheme initialization failed");
        }
        setupUsers();
        auto cluster = cluster_data[i];
        for(const auto& keyword : cluster.keywords){
            std::vector<Document> docs = datasetLoader->getDocumentsByKeyword(keyword);
            //将文档转换为JSON
            SGXValue docs_json;
            for (const auto& doc : docs) {
                SGXValue doc_json;
                doc_json["id"] = doc.id;
                doc_json["level"] = static_cast<int>(doc.level);
                doc_json["state"] = static_cast<int>(doc.state);
                doc_json["isBogus"] = doc.isBogus;
                docs_json.push_back(doc_json);
            }
            std::string docs_str = docs_json.dump();
            //上传到enclave
            sgx_status_t status = ecall_bm_plus_upload_documents(
                enclaveId,
                &retval,
                keyword.c_str(),
                docs_str.c_str(),
                docs_str.size()
            );
            if (status != SGX_SUCCESS) {
                std::cerr << "Failed to upload documents: " << std::hex << status << std::endl;
            }
        }
        //搜索该簇
         std::string keyword = cluster.keywords[0];
        char* results_buffer = new char[MAX_RESULTS_SIZE];
        //记录开始时间
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        status = ecall_bm_plus_search( 
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
            std::cerr << "Failed to search for cluster " << keyword << ": " << std::hex << status << std::endl;
        } else {
            // 解析结果数量
            try {
                std::string results_str(results_buffer, actual_size);
                SGXValue results_json = sgx_serializer::parse(results_str);
                size_t result_count = results_json.size();
                
                std::cout << "Search for cluster " << std::to_string(i) << "_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << duration.count()/1000000 << "s" << std::endl;
            } catch (const std::exception& e) { 
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }
        // 释放缓冲区
        delete[] results_buffer;
    }
}
//测试top10簇的搜索时间
void TestBMPlus::Top10ClusterSearchPerformance(){
    std::cout << "Testing top 10 clusters search performance..." << std::endl;
    //获取top10簇
    auto cluster_data = datasetLoader->getAllClusters();
    User user = users[0];
    const size_t MAX_RESULTS_SIZE = 500 * 1024 * 1024; // 100MB
    size_t actual_size = 0;
    sgx_status_t retval;
    //生成加密id
    std::string encrypted_id = CryptoUtils::signWithPrivateKey(user.id, user.privateKey);
    //搜索top10簇，随机使用一个关键字去搜索
    for(size_t i = 5; i < 10; i++){
        auto cluster = cluster_data[i];
        std::string keyword = cluster.keywords[0];
        char* results_buffer = new char[MAX_RESULTS_SIZE];
        //记录开始时间
        auto start = std::chrono::high_resolution_clock::now();
        //搜索
        sgx_status_t status = ecall_bm_plus_search( 
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
            std::cerr << "Failed to search for cluster " << keyword << ": " << std::hex << status << std::endl;
        } else {
            // 解析结果数量
            try {
                std::string results_str(results_buffer, actual_size);
                SGXValue results_json = sgx_serializer::parse(results_str);
                size_t result_count = results_json.size();
                
                std::cout << "Search for cluster " << std::to_string(i) << "_Docs," 
                          << " Results: " << result_count
                          << ", Time: " << duration.count()/1000000 << "s" << std::endl;
            } catch (const std::exception& e) { 
                std::cerr << "Error parsing search results: " << e.what() << std::endl;
            }
        }
        // 释放缓冲区
        delete[] results_buffer;
    }
}