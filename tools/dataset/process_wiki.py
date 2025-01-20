import os
import json
import nltk
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
from wikiextractor import WikiExtractor
import random
from tqdm import tqdm
import requests
import bz2

class WikiDataProcessor:
    def __init__(self):
        # 初始化Porter词干提取器
        self.stemmer = PorterStemmer()
        # 下载必要的NLTK数据
        nltk.download('punkt')
        # 设置访问级别
        self.access_levels = [1, 2, 3, 4, 5]  # 1最低，5最高
        
    def process_wiki_dump(self, input_file, output_dir):
        # 1. 使用WikiExtractor提取文本
        extractor = WikiExtractor({
            'input': input_file,
            'output': output_dir + '/extracted',
            'bytes': '1M',
            'links': True,
            'sections': True,
            'lists': True
        })
        extractor.extract()
        
        # 2. 处理提取的文本
        keyword_file_pairs = {}  # {keyword: set(file_ids)}
        file_metadata = {}       # {file_id: {keywords: set(), content: str}}
        
        # 遍历提取的文件
        for root, _, files in os.walk(output_dir + '/extracted'):
            for file in tqdm(files, desc="Processing wiki files"):
                if file.startswith('wiki_'):
                    self._process_file(os.path.join(root, file), 
                                    keyword_file_pairs, 
                                    file_metadata)
        
        # 3. 生成最终数据集
        dataset = self._generate_dataset(keyword_file_pairs, file_metadata)
        
        # 4. 保存数据集
        self._save_dataset(dataset, output_dir + '/processed_wiki_dataset.json')
        
        # 5. 打印统计信息
        self._print_stats(keyword_file_pairs, file_metadata)
        
    def _process_file(self, filepath, keyword_file_pairs, file_metadata):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    article = json.loads(line)
                    doc_id = self._generate_file_id(article['id'])
                    
                    # 提取并处理关键词
                    keywords = self._extract_keywords(article['text'])
                    
                    # keyword_file_pairs 用于统计每个关键词对应的文档数量
                    # 这对于评估数据集的分布很有用
                    for keyword in keywords:
                        if keyword not in keyword_file_pairs:
                            keyword_file_pairs[keyword] = set()
                        keyword_file_pairs[keyword].add(doc_id)
                    
                    # 只存储必要的元数据
                    file_metadata[doc_id] = {
                        'keywords': keywords,
                        'level': random.choice(self.access_levels)
                    }
                    
                except json.JSONDecodeError:
                    continue
                
    def _extract_keywords(self, text):
        # 分词
        tokens = word_tokenize(text.lower())
        # 词干提取
        stemmed_words = [self.stemmer.stem(word) for word in tokens]
        # 过滤关键词
        keywords = set(word for word in stemmed_words 
                      if word.isalnum() and len(word) > 2)
        return keywords
        
    def _generate_dataset(self, keyword_file_pairs, file_metadata):
        dataset = []
        for file_id, meta in file_metadata.items():
            doc = {
                'id': file_id,
                'keywords': list(meta['keywords']),
                'level': meta['level'],
                'state': 0
            }
            dataset.append(doc)
        return dataset
        
    def _save_dataset(self, dataset, output_file):
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2)
            
    def _print_stats(self, keyword_file_pairs, file_metadata):
        total_pairs = sum(len(files) for files in keyword_file_pairs.values())
        print(f"\nDataset Statistics:")
        print(f"Total keyword/file pairs: {total_pairs}")
        print(f"Total unique files: {len(file_metadata)}")
        print(f"Total unique keywords: {len(keyword_file_pairs)}")
        
        # 打印访问级别分布
        level_dist = {}
        for meta in file_metadata.values():
            level = meta['level']
            level_dist[level] = level_dist.get(level, 0) + 1
        print("\nAccess Level Distribution:")
        for level, count in sorted(level_dist.items()):
            print(f"Level {level}: {count} files")

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
    url = "https://dumps.wikimedia.org/enwiki/latest/enwiki-latest-pages-articles.xml.bz2"
    
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
