#!/bin/bash

echo "===== 启动 SGX BM 搜索服务测试客户端 ====="
echo "确保 BM 服务器运行在 http://localhost:8080"
echo "确保 BM++ 服务器运行在 http://localhost:8081"
echo ""

cd bm-search-app

# 检查是否已安装依赖
if [ ! -d "node_modules" ]; then
  echo "正在安装依赖..."
  npm install
  if [ $? -ne 0 ]; then
    echo "依赖安装失败，请手动运行 npm install"
    exit 1
  fi
fi

echo "启动前端应用..."
npm start

echo "前端应用已启动，请访问 http://localhost:3000" 