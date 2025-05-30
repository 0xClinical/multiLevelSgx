FROM tozd/sgx:ubuntu-bionic

# 设置环境变量
ENV SGX_SDK=/opt/intel/sgxsdk
ENV PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
ENV PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$SGX_SDK/pkgconfig
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs
# 强制使用模拟器模式
ENV SGX_MODE=SIM

# 替换为中国科技大学镜像源
RUN sed -i 's/http:\/\/archive.ubuntu.com\/ubuntu\//http:\/\/mirrors.ustc.edu.cn\/ubuntu\//g' /etc/apt/sources.list \
    && sed -i 's/http:\/\/security.ubuntu.com\/ubuntu\//http:\/\/mirrors.ustc.edu.cn\/ubuntu\//g' /etc/apt/sources.list

# 安装必要的包
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libcrypto++-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 加载 SGX SDK 环境
RUN echo "source /opt/intel/sgxsdk/environment" >> ~/.bashrc

# 复制项目文件
COPY . .

# 创建一个更可靠的构建脚本
RUN echo '#!/bin/bash\n\
echo "Starting build process..."\n\
source /opt/intel/sgxsdk/environment\n\
echo "Cleaning build directory..."\n\
rm -rf build\n\
mkdir -p build\n\
cd build\n\
echo "Running CMake..."\n\
cmake .. || { echo "CMake failed"; exit 1; }\n\
echo "Running Make..."\n\
make || { echo "Make failed"; exit 1; }\n\
echo "Build completed successfully."\n\
echo "Available executables:"\n\
find . -type f -executable -not -path "*/\\.*"\n\
echo ""\n\
echo "Usage instructions:"\n\
echo "1. To run the BM test: ./sgx_app --test-bm"\n\
echo "2. To run the BM server: ./bm_server [--port PORT]"\n\
echo "3. To run the BM++ server: ./bm_server_plus [--port PORT]"\n\
' > /app/build.sh && \
chmod +x /app/build.sh

# 创建运行服务器的脚本
RUN echo '#!/bin/bash\n\
cd /app/build\n\
# 运行 BM 服务器\n\
./bm_server --port 8080\n\
' > /app/run_bm_server.sh && \
chmod +x /app/run_bm_server.sh

RUN echo '#!/bin/bash\n\
cd /app/build\n\
# 运行 BM++ 服务器\n\
./bm_server_plus --port 8081\n\
' > /app/run_bm_plus_server.sh && \
chmod +x /app/run_bm_plus_server.sh

# 设置入口点为bash，这样容器启动时会给你一个shell
ENTRYPOINT ["/bin/bash"]

# 默认命令为空，这样你可以在运行容器时指定命令
CMD [] 


