# FindSGX.cmake

# 设置 SGX SDK 路径
if(NOT DEFINED SGX_SDK)
    set(SGX_SDK /opt/intel/sgxsdk)
endif()

if(DEFINED ENV{SGX_SDK})
    set(SGX_SDK $ENV{SGX_SDK})
endif()

# 设置 SGX 模式（模拟器或硬件）
if(NOT DEFINED SGX_MODE)
    set(SGX_MODE SIM)
endif()

if(DEFINED ENV{SGX_MODE})
    set(SGX_MODE $ENV{SGX_MODE})
endif()

# 设置架构
set(SGX_ARCH x64)

message(STATUS "Using SGX SDK: ${SGX_SDK}")
message(STATUS "SGX Mode: ${SGX_MODE}")

# 检查 SGX SDK 是否存在
if(NOT EXISTS ${SGX_SDK})
    message(WARNING "Intel SGX SDK not found at ${SGX_SDK}, assuming Docker environment")
endif()

# 设置编译器和链接器标志
if(${SGX_MODE} STREQUAL "HW")
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

# 设置包含路径和库路径
set(SGX_INCLUDE_DIR ${SGX_SDK}/include)
set(SGX_LIBRARY_DIR ${SGX_SDK}/lib64)

# 设置工具路径
set(SGX_EDGER8R ${SGX_SDK}/bin/x64/sgx_edger8r)
set(SGX_SIGN ${SGX_SDK}/bin/x64/sgx_sign)

# 导出变量
set(SGX_FOUND TRUE)
set(SGX_INCLUDE_DIRS ${SGX_INCLUDE_DIR})
set(SGX_LIBRARY_DIRS ${SGX_LIBRARY_DIR}) 