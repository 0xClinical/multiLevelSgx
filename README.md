# SGX 加密搜索项目文档

## 项目简介
本项目实现了一个基于 Intel SGX 的加密搜索系统，包含两个主要方案：BM 和 BM++。该系统在可信执行环境（TEE）中执行加密搜索操作，确保数据隐私和安全。

## 系统要求
- Intel SGX 支持（或使用模拟器模式）
- Ubuntu 18.04 或更高版本
- Docker（推荐使用）

## 数据集准备

### 1. 处理 Enron 数据集
在运行测试之前，需要先处理 Enron 数据集：

1. 进入数据集处理目录：
```bash
cd tools/dataset
```

2. 运行数据处理脚本：
```bash
python process_enron.py
```

这个脚本会：
- 解析原始 Enron 邮件数据集
- 提取关键词和文档信息
- 生成加密搜索所需的测试数据
- 在 `data/processed/cluster_3` 目录下生成以下文件：
  - `metadata.bin`: 数据集元数据
  - `keywords.bin`: 关键词列表
  - `clusters.bin`: 簇化信息
  - `keyword_doc_pairs.bin`: 关键词-文档对数据
  - `cluster_info.json`: 簇的详细信息
  - `cluster_thresholds.png`: 簇阈值分布图
  - `top_10_keywords.txt`: 前10个最频繁关键词

### 2. 验证数据集
处理完成后，检查 `data/processed/cluster_3` 目录下是否生成了所需的数据文件：
```bash
ls -l data/processed/cluster_3/
```

## 完整运行流程

1. 处理数据集：
```bash
cd tools/dataset
python process_enron.py
cd ../..  # 返回项目根目录
```

2. 构建 Docker 镜像：
```bash
docker build -t sgx-search .
```

3. 运行容器：
```bash
docker run -it sgx-search
```

4. 在容器内构建项目：
```bash
./build.sh
```

5. 运行测试：
```bash
cd build
# 运行 BM 测试
./sgx_app --test-bm [test_name]

# 运行 BM++ 测试
./sgx_app --test-bm-plus [test_name]
```

## 数据集说明
- 数据集基于 Enron 邮件数据集
- 处理后的数据包含：
  - 关键词频率统计
  - 文档-关键词映射
  - 文档访问级别信息（1-3级）
  - 文档状态信息（1-10级）
  - 簇化信息（用于 BM++）
  - 簇阈值分布图

## 注意事项
1. 确保 Python 环境已安装必要的依赖：
```bash
pip install pandas numpy
```

2. 数据集处理可能需要一定时间，请耐心等待
3. 确保有足够的磁盘空间存储处理后的数据
4. 如果数据集处理失败，检查：
   - Python 依赖是否正确安装
   - 原始数据集文件是否存在
   - 磁盘空间是否充足

## 常见问题
1. 数据集处理失败：
   - 检查 Python 版本（建议使用 Python 3.6+）
   - 确认所有依赖已正确安装
   - 查看错误日志了解具体原因

2. 数据文件缺失：
   - 重新运行 `process_enron.py`
   - 检查 `data/` 目录权限
   - 确保有足够的磁盘空间

3. 测试运行失败：
   - 确认数据集已正确处理
   - 检查数据文件路径是否正确
   - 验证数据文件格式是否符合要求

## 测试类型
项目支持以下测试类型：

### BM 测试
运行命令：`./sgx_app --test-bm [test_name]`

可选的测试名称：
- `basic`: 运行基础功能测试，验证基本的加密搜索功能
  ```bash
  ./sgx_app --test-bm basic
  ```

- `top10`: 运行前10个最频繁关键词的搜索性能测试
  ```bash
  ./sgx_app --test-bm top10
  ```

- `delete`: 运行删除操作后的搜索性能测试
  ```bash
  ./sgx_app --test-bm delete
  ```

### BM++ 测试
运行命令：`./sgx_app --test-bm-plus [test_name]`

可选的测试名称：
- `basic`: 运行基础功能测试，验证簇化搜索功能
  ```bash
  ./sgx_app --test-bm-plus basic
  ```

- `top10`: 运行前10个最大簇的搜索性能测试
  ```bash
  ./sgx_app --test-bm-plus top10
  ```

- `delete`: 运行删除操作后的簇化搜索性能测试
  ```bash
  ./sgx_app --test-bm-plus delete
  ```

### 测试说明
1. 基础数据测试（basic）：
   - 测试系统的上传时间
   - 测试系统的删除时间
   - 测试系统的搜索时间

2. top10关键字测试（top10）：
   - 测试系统对最频繁的10个关键词/簇的搜索性能
 

3. 删除后的搜索测试（delete）：
   - 测试删除不同文档比例后的top10关键字的搜索性能

### 运行示例
```bash
# 运行 BM 方案的基础功能测试
./sgx_app --test-bm basic

# 运行 BM++ 方案的性能测试
./sgx_app --test-bm-plus top10

# 运行 BM 方案的删除测试
./sgx_app --test-bm delete
```