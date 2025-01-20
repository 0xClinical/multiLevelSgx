# Wikipedia Dataset Processing Tool

这个工具用于处理维基百科数据集，生成用于搜索系统的标准化数据集。

## 功能特点

- 自动下载最新的维基百科数据转储
- 使用 WikiExtractor 提取文本内容
- 使用 Porter Stemmer 进行词干提取
- 生成唯一的32字节文件标识符
- 支持三级访问权限分配
- 自动生成关键词-文档对
- 提供详细的数据集统计信息

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用方法

1. 运行处理脚本

```bash
python process_wiki.py
```


2. 脚本会：
   - 自动下载维基百科数据（如果需要）
   - 提取并处理文本
   - 生成处理后的数据集
   - 显示处理进度和统计信息

## 输出格式

处理后的数据集将保存为 JSON 格式：

```json
{
  "id": "wiki_article_id", // 维基百科文章的原始ID
  "keywords": ["keyword1", "keyword2", "keyword3"], // 关键词列表
  "level": "level", // 访问级别
  "state": 0, // 状态
  "content": "processed_text", // 处理后的文本
}
```

