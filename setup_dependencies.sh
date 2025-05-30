#!/bin/bash

echo "==== 正在设置 SGX BM 项目的依赖项 ===="

# 创建必要的目录
mkdir -p include/nlohmann

# 下载 httplib.h
echo "正在下载 httplib.h..."
curl -s -o include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
if [ $? -ne 0 ] || [ ! -s include/httplib.h ]; then
    echo "下载 httplib.h 失败！"
    echo "尝试手动下载..."
    wget -q -O include/httplib.h https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
    if [ $? -ne 0 ] || [ ! -s include/httplib.h ]; then
        echo "使用 wget 下载 httplib.h 也失败了！"
        exit 1
    fi
fi

echo "成功下载 httplib.h (大小: $(wc -c < include/httplib.h) 字节)"

# 下载 nlohmann/json.hpp
echo "正在下载 nlohmann/json.hpp..."
curl -s -o include/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
if [ $? -ne 0 ] || [ ! -s include/nlohmann/json.hpp ]; then
    echo "下载 nlohmann/json.hpp 失败！"
    echo "尝试手动下载..."
    wget -q -O include/nlohmann/json.hpp https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
    if [ $? -ne 0 ] || [ ! -s include/nlohmann/json.hpp ]; then
        echo "使用 wget 下载 nlohmann/json.hpp 也失败了！"
        exit 1
    fi
fi

echo "成功下载 nlohmann/json.hpp (大小: $(wc -c < include/nlohmann/json.hpp) 字节)"

# 验证文件是否有效
echo "正在验证文件..."

if grep -q "class Server" include/httplib.h; then
    echo "httplib.h 文件有效"
else
    echo "httplib.h 文件无效，请手动下载"
    exit 1
fi

if grep -q "class basic_json" include/nlohmann/json.hpp; then
    echo "json.hpp 文件有效"
else
    echo "json.hpp 文件无效，请手动下载"
    exit 1
fi

echo "所有依赖项设置完成！"
echo "现在可以运行以下命令构建项目："
echo "mkdir -p build && cd build && cmake .. && make" 