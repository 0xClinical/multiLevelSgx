cmake_minimum_required(VERSION 3.10)
project(SecureSearch)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找OpenSSL包
find_package(OpenSSL REQUIRED)

# 添加源文件
file(GLOB_RECURSE SOURCES "src/*.cpp")

# 创建可执行文件
add_executable(${PROJECT_NAME} ${SOURCES})

# 添加头文件路径
target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/include/core
        ${PROJECT_SOURCE_DIR}/include/utils
)

# 链接OpenSSL
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        OpenSSL::SSL 
        OpenSSL::Crypto
)
# 查找 Google Test
set(GTEST_ROOT /opt/homebrew/Cellar/googletest/1.14.0)
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# 添加测试可执行文件
add_executable(runTests test/test_sgx_enclave.cpp test/test_cloud_server.cpp test/test_data_owner.cpp test/test_authorized_user.cpp test/test_crypto.cpp)

# 链接 Google Test 库
target_link_libraries(runTests ${GTEST_LIBRARIES} pthread)

# 添加 httplib
find_package(httplib REQUIRED)

# 添加 nlohmann_json
find_package(nlohmann_json REQUIRED)

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    httplib::httplib
    nlohmann_json::nlohmann_json
)

