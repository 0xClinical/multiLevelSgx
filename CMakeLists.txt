cmake_minimum_required(VERSION 3.10)
project(SGX_BM_Test)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# SGX SDK路径
set(SGX_SDK_PATH $ENV{SGX_SDK})
if(SGX_SDK_PATH STREQUAL "")
    set(SGX_SDK_PATH "/opt/intel/sgxsdk")
endif()

# SGX模式（SIM或HW）
set(SGX_MODE $ENV{SGX_MODE})
if(SGX_MODE STREQUAL "")
    set(SGX_MODE "SIM")
endif()

# SGX库路径
set(SGX_ARCH "x64")
set(SGX_LIBRARY_PATH ${SGX_SDK_PATH}/lib64)
set(SGX_INCLUDE_PATH ${SGX_SDK_PATH}/include)

# 查找必要的包
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 下载nlohmann/json
if(NOT EXISTS ${PROJECT_SOURCE_DIR}/include/nlohmann/json.hpp)
    message(STATUS "Downloading nlohmann/json.hpp...")
    file(MAKE_DIRECTORY ${PROJECT_SOURCE_DIR}/include/nlohmann)
    file(DOWNLOAD
        https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
        ${PROJECT_SOURCE_DIR}/include/nlohmann/json.hpp
        SHOW_PROGRESS
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download json.hpp")
    endif()
endif()

# 下载cpp-httplib
if(NOT EXISTS ${PROJECT_SOURCE_DIR}/include/httplib.h)
    message(STATUS "Downloading cpp-httplib...")
    file(DOWNLOAD
        https://github.com/yhirose/cpp-httplib/raw/master/httplib.h
        ${PROJECT_SOURCE_DIR}/include/httplib.h
        SHOW_PROGRESS
        STATUS DOWNLOAD_STATUS
    )
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    if(NOT STATUS_CODE EQUAL 0)
        message(FATAL_ERROR "Failed to download httplib.h")
    endif()
endif()

# 设置编译选项
if(SGX_MODE STREQUAL "HW")
    set(SGX_URTS_LIB sgx_urts)
    set(SGX_USVC_LIB sgx_uae_service)
    set(SGX_TRTS_LIB sgx_trts)
    set(SGX_TSVC_LIB sgx_tservice)
else()
    set(SGX_URTS_LIB sgx_urts_sim)
    set(SGX_USVC_LIB sgx_uae_service_sim)
    set(SGX_TRTS_LIB sgx_trts_sim)
    set(SGX_TSVC_LIB sgx_tservice_sim)
endif()

# 生成Enclave_u.h和Enclave_u.c
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Enclave_u.c ${CMAKE_CURRENT_BINARY_DIR}/Enclave_u.h
    COMMAND ${SGX_SDK_PATH}/bin/x64/sgx_edger8r --untrusted ${PROJECT_SOURCE_DIR}/src/enclave/Enclave.edl --search-path ${SGX_SDK_PATH}/include --search-path ${PROJECT_SOURCE_DIR}/src/enclave
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${PROJECT_SOURCE_DIR}/src/enclave/Enclave.edl
)

# 生成Enclave_t.h和Enclave_t.c
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Enclave_t.c ${CMAKE_CURRENT_BINARY_DIR}/Enclave_t.h
    COMMAND ${SGX_SDK_PATH}/bin/x64/sgx_edger8r --trusted ${PROJECT_SOURCE_DIR}/src/enclave/Enclave.edl --search-path ${SGX_SDK_PATH}/include --search-path ${PROJECT_SOURCE_DIR}/src/enclave
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${PROJECT_SOURCE_DIR}/src/enclave/Enclave.edl
)

# 添加不可信部分的源文件
set(APP_SRC
    src/App.cpp
    src/core/edb_controller.cpp
    src/utils/crypto.cpp
    src/enclave/sgx_serializer.cpp
    src/test/test_bm.cpp
    src/test/test_bm_plus.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/Enclave_u.c
)

# 添加Enclave源文件
set(ENCLAVE_SRC
    src/enclave/Enclave.cpp
    src/enclave/enclave_edb_controller.cpp
    src/enclave/enclave_dataset_loader.cpp
    src/enclave/crypto_sgx.cpp
    src/enclave/sgx_serializer.cpp
    src/core/bm_scheme.cpp
    src/core/bm_scheme_plus.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/Enclave_t.c
)

# 添加不可信应用程序
add_executable(sgx_app ${APP_SRC})
target_include_directories(sgx_app PRIVATE
    ${SGX_INCLUDE_PATH}
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# 为不可信应用程序添加编译选项
target_compile_options(sgx_app PRIVATE
    -fPIC
    -Wno-attributes
)

# 链接不可信应用程序
target_link_libraries(sgx_app
    /opt/intel/sgxsdk/sdk_libs/libsgx_urts_sim.so
    /opt/intel/sgxsdk/sdk_libs/libsgx_uae_service_sim.so
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    -ldl
)

# 添加Enclave库
add_library(enclave SHARED ${ENCLAVE_SRC})
target_include_directories(enclave PRIVATE
    ${SGX_INCLUDE_PATH}
    ${SGX_INCLUDE_PATH}/tlibc
    ${SGX_INCLUDE_PATH}/libcxx
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
)

# 为Enclave添加编译选项和定义
target_compile_options(enclave PRIVATE
    -nostdinc
    -fvisibility=hidden
    -fpie
    -fstack-protector
    -fno-builtin-printf
    -DNDEBUG
    -DEDGER8R_TRUSTED
    -std=c++17
)

target_compile_definitions(enclave PRIVATE
    SGX_ENCLAVE
    SGX_EDGELESS_MAX_BUFFER_SIZE=154857600  # 150MB
    SGX_MAX_EPC_PAGES=131072
)

# 为App添加编译选项和定义
target_compile_definitions(sgx_app PRIVATE
    # 不定义SGX_ENCLAVE
)

# 链接Enclave
target_link_libraries(enclave
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH}
    -Wl,--whole-archive -l${SGX_TRTS_LIB} -Wl,--no-whole-archive
    -Wl,--start-group 
    -lsgx_tstdc 
    -lsgx_tcxx 
    -lsgx_tcrypto 
    -lsgx_tservice
    -l${SGX_TSVC_LIB}
    -Wl,--end-group
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic
    -Wl,--defsym,__ImageBase=0
)

# 生成Enclave签名文件
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so
    COMMAND ${SGX_SDK_PATH}/bin/x64/sgx_sign sign -key ${PROJECT_SOURCE_DIR}/src/enclave/Enclave_private.pem -enclave ${CMAKE_CURRENT_BINARY_DIR}/libenclave.so -out ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so -config ${PROJECT_SOURCE_DIR}/src/enclave/Enclave.config.xml
    DEPENDS enclave
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# 添加自定义目标，生成签名的Enclave
add_custom_target(enclave_signed ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so)

# 添加安装规则
install(TARGETS sgx_app DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/enclave.signed.so DESTINATION lib)

# 添加SGX SDK库路径
link_directories(
    /opt/intel/sgxsdk/lib64
    /opt/intel/sgxssl/lib64
    ${SGX_LIBRARY_PATH}
)

# 添加SGX库路径
link_directories(${SGX_SDK_PATH}/lib64)
link_directories(${SGX_SDK_PATH}/lib)
link_directories(${SGX_SDK_PATH}/sdk_libs)
link_directories(/usr/lib/x86_64-linux-gnu)

# 查找SGX库
find_library(SGX_URTS_LIB sgx_urts_sim PATHS ${SGX_SDK_PATH}/sdk_libs ${SGX_SDK_PATH}/lib64 ${SGX_SDK_PATH}/lib /usr/lib/x86_64-linux-gnu)
find_library(SGX_UAE_SERVICE_LIB sgx_uae_service_sim PATHS ${SGX_SDK_PATH}/sdk_libs ${SGX_SDK_PATH}/lib64 ${SGX_SDK_PATH}/lib /usr/lib/x86_64-linux-gnu)