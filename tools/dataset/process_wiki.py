import os
import json
import nltk
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
import random
from tqdm import tqdm
import requests
import subprocess
import tempfile
from collections import Counter

class WikiDataProcessor:
    def __init__(self):
        # 初始化Porter词干提取器
        self.stemmer = PorterStemmer()
        
        # 确保下载所有必要的 NLTK 数据
        required_packages = ['punkt', 'punkt_tab']
        for package in required_packages:
            try:
                nltk.data.find(f'tokenizers/{package}')
            except LookupError:
                print(f"Downloading {package}...")
                nltk.download(package, quiet=False)
        
        # 设置访问级别
        self.access_levels = [1, 2, 3, 4, 5]  # 1最低，5最高
        self.target_keywords = 500  # 目标关键词数量
    def process_wiki_dump(self, input_file, output_dir, max_articles=10000):
        # 创建临时目录存放提取的文本
        with tempfile.TemporaryDirectory() as temp_dir:
            print("Extracting wiki text...")
            
            # 使用命令行方式运行 WikiExtractor
            subprocess.run([
                'wikiextractor',
                '--output', temp_dir,
                '--bytes', '1M',
                '--json',
                '--processes', '4',
                input_file
            ])
            
            # 第一遍：收集关键词频率
            print("First pass: collecting keyword frequencies...")
            keyword_counts = Counter()
            article_count = 0
            
            # 遍历提取的文件
            for root, _, files in os.walk(temp_dir):
                for filename in files:
                    if article_count >= max_articles:
                        break
                        
                    if filename.startswith('wiki_'):
                        filepath = os.path.join(root, filename)
                        with open(filepath, 'r', encoding='utf-8') as f:
                            for line in f:
                                if article_count >= max_articles:
                                    break
                                    
                                try:
                                    article = json.loads(line)
                                    keywords = self._extract_keywords(article['text'])
                                    keyword_counts.update(keywords)
                                    article_count += 1
                                except json.JSONDecodeError:
                                    continue
            
            # 选择最常用的关键词
            top_keywords = set(k for k, _ in keyword_counts.most_common(self.target_keywords))
            print(f"Selected {len(top_keywords)} most common keywords")
            
            # 第二遍：只使用选定的关键词构建数据集
            print("Second pass: building dataset with selected keywords...")
            keyword_file_pairs = {}
            article_count = 0
            
            # 遍历提取的文件
            for root, _, files in os.walk(temp_dir):
                for filename in files:
                    if article_count >= max_articles:
                        break
                        
                    if filename.startswith('wiki_'):
                        filepath = os.path.join(root, filename)
                        with open(filepath, 'r', encoding='utf-8') as f:
                            for line in f:
                                if article_count >= max_articles:
                                    break
                                    
                                try:
                                    article = json.loads(line)
                                    doc_id = self._generate_file_id(article['id'])
                                    keywords = self._extract_keywords(article['text'])
                                    
                                    # 只保留选定的关键词
                                    filtered_keywords = keywords & top_keywords
                                    
                                    for keyword in filtered_keywords:
                                        if keyword not in keyword_file_pairs:
                                            keyword_file_pairs[keyword] = set()
                                        keyword_file_pairs[keyword].add(doc_id)
                                    
                                    article_count += 1
                                    if article_count % 100 == 0:
                                        print(f"Processed {article_count} articles")
                                        
                                except json.JSONDecodeError:
                                    continue
            
            # 生成最终数据集
            dataset = self._generate_dataset(keyword_file_pairs)
            
            # 保存数据集
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, 'processed_wiki_dataset.json')
            self._save_dataset(dataset, output_file)
            
            print(f"Dataset saved to {output_file}")
            print(f"Total articles processed: {article_count}")
        
    def _extract_keywords(self, text):
        """提取和处理关键词"""
        try:
            # 使用简单的分词方式，避免依赖复杂的NLTK功能
            words = text.lower().split()
            # 词干提取
            stemmed_words = set(self.stemmer.stem(word) for word in words 
                              if word.isalnum() and len(word) > 2)
            return stemmed_words
        except Exception as e:
            print(f"Warning: Error in keyword extraction: {e}")
            return set()
        
    def _generate_dataset(self, keyword_file_pairs):
        dataset = {
            'keyword_docs': {},   # 关键词到文档ID的映射
            'docs_metadata': {}   # 文档的元数据
        }
        
        # 遍历每个关键词及其对应的文档
        for keyword, doc_ids in keyword_file_pairs.items():
            # 正确存储：关键词作为键，文档ID列表作为值
            dataset['keyword_docs'][keyword] = list(doc_ids)
            
            # 为每个文档添加元数据
            for doc_id in doc_ids:
                if doc_id not in dataset['docs_metadata']:
                    dataset['docs_metadata'][doc_id] = {
                        'id': doc_id,                    # 文档ID
                        'keywords': [],                  # 该文档的关键词列表
                        'level': random.choice(self.access_levels),
                        'state': 0
                    }
                # 将当前关键词添加到文档的关键词列表中
                dataset['docs_metadata'][doc_id]['keywords'].append(keyword)

        return dataset
        
    def _print_stats(self, dataset):
        """打印详细的数据集统计信息"""
        # 计算关键词-文件对的总数
        total_pairs = sum(len(doc_ids) for doc_ids in dataset['keyword_docs'].values())
        
        # 计算唯一文件数
        unique_files = len(dataset['docs_metadata'])
        
        # 计算唯一关键词数
        unique_keywords = len(dataset['keyword_docs'])
        
        print("\nDataset Statistics:")
        print(f"Total keyword/file pairs: {total_pairs:,}")
        print(f"Total unique files: {unique_files:,}")
        print(f"Total unique keywords: {unique_keywords:,}")
        
        # 计算每个访问级别的文件数量
        level_distribution = {}
        for doc_meta in dataset['docs_metadata'].values():
            level = doc_meta['level']
            level_distribution[level] = level_distribution.get(level, 0) + 1
        
        print("\nAccess Level Distribution:")
        for level in sorted(level_distribution.keys()):
            count = level_distribution[level]
            percentage = (count / unique_files) * 100
            print(f"Level {level}: {count:,} files ({percentage:.2f}%)")
        
        # 计算关键词分布统计
        keyword_counts = [(k, len(v)) for k, v in dataset['keyword_docs'].items()]
        keyword_counts.sort(key=lambda x: x[1], reverse=True)
        
        print("\nTop 10 Keywords by Document Count:")
        for keyword, count in keyword_counts[:10]:
            print(f"{keyword}: {count:,} documents")
        
        # 计算平均每个文档的关键词数
        total_keywords_in_docs = sum(len(meta['keywords']) 
                                   for meta in dataset['docs_metadata'].values())
        avg_keywords_per_doc = total_keywords_in_docs / unique_files
        
        print(f"\nAverage keywords per document: {avg_keywords_per_doc:.2f}")

    def _save_dataset(self, dataset, output_file):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2)
        
        # 保存后打印统计信息
        self._print_stats(dataset)
            
    def _generate_file_id(self, article_id):
        """生成标准化的文件标识符
        
        Args:
            article_id: 维基百科文章的原始ID
            
        Returns:
            32字节的文件标识符
        """
        # 确保ID是字符串
        base_id = str(article_id)
        
        # 添加前缀以标识来源
        prefix = "wiki_"
        
        # 如果ID太长，进行哈希处理
        if len(prefix + base_id) > 32:
            import hashlib
            # 使用MD5生成固定长度的哈希值
            hashed = hashlib.md5(base_id.encode()).hexdigest()
            # 组合前缀和哈希值的一部分，确保总长度不超过32字节
            file_id = f"{prefix}{hashed[:26]}"  # prefix(5) + hash(26) = 31字节
        else:
            # 如果原始ID够短，直接使用并补齐
            file_id = f"{prefix}{base_id:0<{27}}"  # 用0补齐到32字节
        
        assert len(file_id) <= 32, f"File ID length exceeds 32 bytes: {len(file_id)}"
        return file_id

def download_wiki_dump(output_path):
    """下载维基百科数据集"""
    url = "https://dumps.wikimedia.org/simplewiki/latest/simplewiki-latest-pages-articles.xml.bz2"
    
    # 创建目录
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 如果文件已存在，询问是否重新下载
    if os.path.exists(output_path):
        response = input(f"File {output_path} already exists. Download again? (y/n): ")
        if response.lower() != 'y':
            print("Using existing file...")
            return
    
    print(f"Downloading Wikipedia dump from {url}")
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    
    with open(output_path, 'wb') as file, tqdm(
        desc="Downloading",
        total=total_size,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as pbar:
        for data in response.iter_content(chunk_size=1024):
            size = file.write(data)
            pbar.update(size)
            
    print(f"Download completed: {output_path}")

if __name__ == "__main__":
    # 设置路径
    WIKI_DUMP = "../../data/raw/wiki_dump.xml.bz2"
    OUTPUT_DIR = "../../data/processed"
    
    # 下载数据集
    download_wiki_dump(WIKI_DUMP)
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 处理数据集
    processor = WikiDataProcessor()
    processor.process_wiki_dump(WIKI_DUMP, OUTPUT_DIR)
