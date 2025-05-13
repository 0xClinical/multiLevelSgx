import os
import json
import nltk
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
import random
from tqdm import tqdm
import requests
import email
import tarfile
import hashlib
from collections import Counter
import pandas as pd
from typing import Dict, Set, List, Tuple
import matplotlib.pyplot as plt
import struct
import pickle

class EnronDataProcessor:
    def __init__(self):
        self.stemmer = PorterStemmer()
        self.access_levels = [1, 2, 3]  # 1-3级
        self.states = list(range(1, 11))  # 1-10的状态
        self.target_keywords = 5000
        self.cluster_sizes = [3]  # 最小簇大小
        
        # 确保下载必要的NLTK数据
        required_packages = ['punkt']
        for package in required_packages:
            try:
                nltk.data.find(f'tokenizers/{package}')
            except LookupError:
                print(f"Downloading {package}...")
                nltk.download(package, quiet=True)
        
        # 添加停用词列表
        self.stopwords = set([
            # 常见英文停用词
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to',
            'is', 'are', 'was', 'were', 'be', 'been', 'being',
            'i', 'you', 'he', 'she', 'it', 'we', 'they',
            'my', 'your', 'his', 'her', 'its', 'our', 'their',
            'this', 'that', 'these', 'those',
            'am', 'is', 'are', 'was', 'were',
            'has', 'have', 'had',
            'do', 'does', 'did',
            'will', 'would', 'shall', 'should',
            'can', 'could', 'may', 'might',
            
            # 邮件相关停用词
            'email', 'mail', 'from', 'to', 'cc', 'bcc',
            'subject', 'date', 'time', 'day', 'week', 'month', 'year',
            'send', 'sent', 'forward', 'forwarded', 'reply',
            'please', 'thank', 'thanks', 'regard', 'regards', 'sincerely',
            'dear', 'hi', 'hello', 'hey',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december'
        ])
        
        # 对停用词进行词干提取
        self.stopwords = set(self.stemmer.stem(word) for word in self.stopwords)
    
    def download_dataset(self, output_path: str) -> str:
        """下载Enron数据集"""
        url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
        
        if os.path.exists(output_path):
            print(f"Found existing dataset at {output_path}")
            return output_path
        
        print(f"Downloading Enron dataset from {url}")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
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
        return output_path

    def process_dataset(self, input_file: str, output_dir: str):
        """处理Enron数据集"""
        print("\nProcessing Enron dataset...")
        
        # 第一遍：收集关键词频率
        print("\nFirst pass: collecting keyword frequencies...")
        keyword_counts = Counter()
        email_count = 0
        doc_lengths = []  # 记录文档长度
        
        with tarfile.open(input_file, 'r:gz') as tar:
            members = [m for m in tar.getmembers() if m.isfile() and m.name.endswith('.')]
            
            for member in tqdm(members, desc="Collecting keywords"):
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    
                    content = f.read().decode('utf-8', errors='ignore')
                    msg = email.message_from_string(content)
                    
                    email_body = self._get_email_body(msg)
                    keywords = self._extract_keywords(email_body)
                    
                    doc_lengths.append(len(keywords))
                    keyword_counts.update(keywords)
                    email_count += 1
                    
                except Exception as e:
                    print(f"Error processing {member.name}: {e}")
                    continue
        
        # 分析关键词统计
        print("\nKeyword Statistics:")
        print(f"Total unique keywords before filtering: {len(keyword_counts)}")
        
        # 选择最常用的关键词
        top_keywords = dict(keyword_counts.most_common(self.target_keywords))
        print(f"Selected top {len(top_keywords)} keywords")
        
        # 显示top 10关键词及其频率
        print("\nTop 10 Keywords by Frequency:")
        for keyword, count in keyword_counts.most_common(10):
            print(f"{keyword}: {count:,} occurrences")
        
        # 保存top 10关键词到文件
        top_10_keywords = [k for k, _ in keyword_counts.most_common(10)]
        with open(os.path.join(output_dir, 'top_10_keywords.txt'), 'w') as f:
            json.dump(top_10_keywords, f, indent=2)
        
        # 第二遍：构建数据集
        print("\nSecond pass: building dataset...")
        keyword_file_pairs: Dict[str, Set[str]] = {}
        email_count = 0
        
        with tarfile.open(input_file, 'r:gz') as tar:
            for member in tqdm(members, desc="Building dataset"):
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    
                    content = f.read().decode('utf-8', errors='ignore')
                    msg = email.message_from_string(content)
                    
                    doc_id = self._generate_file_id(member.name)
                    email_body = self._get_email_body(msg)
                    keywords = self._extract_keywords(email_body)
                    
                    # 只保留选定的关键词
                    filtered_keywords = keywords & set(top_keywords.keys())
                    
                    for keyword in filtered_keywords:
                        if keyword not in keyword_file_pairs:
                            keyword_file_pairs[keyword] = set()
                        keyword_file_pairs[keyword].add(doc_id)
                    
                    email_count += 1
                    
                except Exception as e:
                    print(f"Error processing {member.name}: {e}")
                    continue
        
        # 为每个簇大小生成数据集
        for cluster_size in self.cluster_sizes:
            print(f"\nGenerating dataset for cluster size {cluster_size}...")
            keyword_docs, clusters = self._generate_dataset(keyword_file_pairs, cluster_size)
            self._save_binary_dataset(keyword_docs, clusters, output_dir, cluster_size)
            self.save_cluster_info(keyword_docs, clusters, cluster_size)
        
        # 生成详细的统计报告
        self._generate_statistics_report(keyword_counts, keyword_file_pairs, output_dir)

    def _get_email_body(self, msg: email.message.Message) -> str:
        """提取邮件正文"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        return body

    def _extract_keywords(self, text: str) -> Set[str]:
        """提取和处理关键词，过滤停用词"""
        try:
            # 分词并进行词干提取
            words = word_tokenize(text.lower())
            stemmed_words = set()
            for word in words:
                if (word.isalnum() and                  # 只保留字母数字
                    len(word) > 2 and                   # 去掉太短的词
                    not word.isnumeric() and           # 去掉纯数字
                    not word.isdigit()):               # 去掉数字
                    stemmed = self.stemmer.stem(word)
                    if stemmed not in self.stopwords:   # 过滤停用词
                        stemmed_words.add(stemmed)
            return stemmed_words
        except Exception as e:
            print(f"Warning: Error in keyword extraction: {e}")
            return set()

    def _generate_file_id(self, file_path: str) -> str:
        """生成文件ID"""
        hasher = hashlib.md5()
        hasher.update(file_path.encode('utf-8'))
        return hasher.hexdigest()

    def _generate_dataset(self, keyword_file_pairs: Dict[str, Set[str]], min_cluster_size: int):
        """生成数据集和簇信息"""
        # 计算关键词实际频率
        keyword_freqs = {k: len(v) for k, v in keyword_file_pairs.items()}
        
        # 计算总的关键词文档对数量
        total_pairs = sum(len(docs) for docs in keyword_file_pairs.values())
        print(f"\nTotal keyword-document pairs: {total_pairs:,}")
        
        # 按频率降序排序关键词
        sorted_keywords = sorted(keyword_freqs.items(), key=lambda x: x[1], reverse=True)
        
        # 初始化簇
        clusters = []
        current_cluster = []
        
        for keyword, freq in sorted_keywords:
            # 如果当前簇为空，初始化新簇
            if not current_cluster:
                current_cluster = [keyword]
                continue
            
            # 计算与当前簇第一个词（最大频率）的比值
            first_freq = keyword_freqs[current_cluster[0]]
            freq_ratio = freq / first_freq
            
            # 如果频率比过小且簇已经达到最小大小，开始新的簇
            if freq_ratio < 0.7 and len(current_cluster) >= min_cluster_size:
                # 计算簇中关键词的频率统计
                cluster_freqs = [keyword_freqs[k] for k in current_cluster]
                avg_freq = sum(cluster_freqs) / len(cluster_freqs)
                max_freq = max(cluster_freqs)
                min_freq = min(cluster_freqs)
                
                clusters.append({
                    'keywords': current_cluster,
                    'avg_freq': avg_freq,
                    'max_freq': max_freq,
                    'min_freq': min_freq,
                    'threshold': avg_freq/2  # 将平均频率除以10作为阈值
                })
                current_cluster = [keyword]
            # 否则继续添加到当前簇
            else:
                current_cluster.append(keyword)
        
        # 处理最后一个簇
        if current_cluster and len(current_cluster) >= min_cluster_size:
            cluster_freqs = [keyword_freqs[k] for k in current_cluster]
            
            avg_freq = sum(cluster_freqs) / len(cluster_freqs)
            max_freq = max(cluster_freqs)
            min_freq = min(cluster_freqs)
            
            clusters.append({
                'keywords': current_cluster,
                'avg_freq': avg_freq,
                'max_freq': max_freq,
                'min_freq': min_freq,
                'threshold': avg_freq // 10
            })
        
        # 打印簇的分布情况
        print(f"\nCluster distribution for size {min_cluster_size}:")
        for i, cluster in enumerate(clusters):
            cluster_pairs = sum(len(keyword_file_pairs[kw]) for kw in cluster['keywords'])
            print(f"Cluster {i}:")
            print(f"  Keywords: {len(cluster['keywords'])}")
            print(f"  Frequency range: {cluster['min_freq']:,}-{cluster['max_freq']:,}")
            print(f"  Average frequency: {cluster['avg_freq']:.1f}")
            print(f"  Scaled threshold: {cluster['threshold']:,}")
            print(f"  Total pairs: {cluster_pairs:,}")
        
        # 为每个文档生成属性
        doc_properties = {}
        for keyword, doc_ids in keyword_file_pairs.items():
            for doc_id in doc_ids:
                if doc_id not in doc_properties:
                    doc_properties[doc_id] = (
                        random.choice(self.access_levels),
                        random.choice(self.states)
                    )
        
        # 重组关键词/文档对映射
        keyword_docs = {}
        for keyword, doc_ids in keyword_file_pairs.items():
            keyword_docs[keyword] = [
                (doc_id, *doc_properties[doc_id])
                for doc_id in doc_ids
            ]
        
        return keyword_docs, {i: cluster for i, cluster in enumerate(clusters)}

    def _save_binary_dataset(self, keyword_docs: Dict[str, List[Tuple]], clusters: Dict[int, dict], 
                            output_dir: str, cluster_size: int):
        """以二进制格式保存数据集"""
        cluster_dir = os.path.join(output_dir, f'cluster_{cluster_size}')
        os.makedirs(cluster_dir, exist_ok=True)

        # 1. 创建关键词到ID的映射
        all_keywords = sorted(keyword_docs.keys())
        keyword_to_id = {kw: idx for idx, kw in enumerate(all_keywords)}

        # 2. 保存元数据
        total_pairs = sum(len(docs) for docs in keyword_docs.values())
        with open(os.path.join(cluster_dir, 'metadata.bin'), 'wb') as f:
            f.write(struct.pack('III',
                total_pairs,           # 总关键词/文档对数
                len(all_keywords),     # 关键词数量
                cluster_size          # 簇大小
            ))

        # 3. 保存关键词列表
        with open(os.path.join(cluster_dir, 'keywords.bin'), 'wb') as f:
            f.write(struct.pack('I', len(all_keywords)))
            for keyword in all_keywords:
                encoded = keyword.encode('utf-8')
                f.write(struct.pack('I', len(encoded)))
                f.write(encoded)

        # 4. 保存簇信息
        with open(os.path.join(cluster_dir, 'clusters.bin'), 'wb') as f:
            f.write(struct.pack('I', len(clusters)))
            for cluster_id, cluster in clusters.items():
                # 写入簇中的关键词
                keyword_ids = [keyword_to_id[kw] for kw in cluster['keywords']]
                f.write(struct.pack('I', len(keyword_ids)))
                for kid in keyword_ids:
                    f.write(struct.pack('I', kid))
                
                # 写入频率统计
                f.write(struct.pack('fffi', 
                    float(cluster['min_freq']), 
                    float(cluster['max_freq']),
                    float(cluster['avg_freq']),  # 添加平均频率
                    int(cluster['threshold'])    # 添加阈值
                ))

        # 5. 保存关键词/文档对数据
        with open(os.path.join(cluster_dir, 'keyword_doc_pairs.bin'), 'wb') as f:
            f.write(struct.pack('I', total_pairs))
            for keyword, docs in keyword_docs.items():
                kid = keyword_to_id[keyword]
                for doc_id, level, state in docs:
                    # 写入关键词ID
                    f.write(struct.pack('I', kid))
                    # 写入文档ID
                    doc_id_bytes = doc_id.encode('utf-8')
                    f.write(struct.pack('I', len(doc_id_bytes)))
                    f.write(doc_id_bytes)
                    # 写入文档属性
                    f.write(struct.pack('BB', level, state))

        print(f"\nDataset saved to {cluster_dir}")
        print(f"Total keyword-document pairs: {total_pairs:,}")
        print(f"Total keywords: {len(all_keywords):,}")

    def _generate_statistics_report(self, keyword_counts: Counter, 
                                 keyword_file_pairs: Dict[str, Set[str]], 
                                 output_dir: str):
        """生成简化的统计报告"""
        stats = {
            'total_unique_keywords': len(keyword_counts),
            'total_keyword_doc_pairs': sum(len(docs) for docs in keyword_file_pairs.values()),
            'max_keyword_frequency': max(keyword_counts.values()),
            'min_keyword_frequency': min(keyword_counts.values()),
        }
        
        print("\nDataset Statistics:")
        print(f"Total unique keywords: {stats['total_unique_keywords']:,}")
        print(f"Total keyword-document pairs: {stats['total_keyword_doc_pairs']:,}")
        print(f"Keyword frequency range: {stats['min_keyword_frequency']} - {stats['max_keyword_frequency']}")

    def save_cluster_info(self, keyword_docs, clusters, min_cluster_size):
        """保存簇信息到文件并生成可视化"""
        # 准备输出目录
        output_dir = f"../../data/processed/cluster_{min_cluster_size}"
        os.makedirs(output_dir, exist_ok=True)
        
        # 准备数据
        cluster_data = []
        thresholds = []
        cluster_ids = []
        
        # 收集数据
        for cluster_id, cluster in clusters.items():
            cluster_pairs = sum(len(keyword_docs[kw]) for kw in cluster['keywords'])
            cluster_info = {
                'id': cluster_id,
                'keyword_count': len(cluster['keywords']),
                'min_freq': cluster['min_freq'],
                'max_freq': cluster['max_freq'],
                'avg_freq': cluster['avg_freq'],
                'threshold': cluster['threshold'],
                'total_pairs': cluster_pairs,
                'keywords': list(cluster['keywords'])
            }
            cluster_data.append(cluster_info)
            thresholds.append(cluster['threshold'])
            cluster_ids.append(cluster_id)
        
        # 按平均频率排序
        cluster_data.sort(key=lambda x: x['avg_freq'])
        sorted_thresholds = [c['threshold'] for c in cluster_data]
        sorted_ids = [c['id'] for c in cluster_data]
        
        # 保存簇信息到JSON文件
        with open(os.path.join(output_dir, "cluster_info.json"), 'w') as f:
            json.dump(cluster_data, f, indent=2)
        
        # 生成直方图
        plt.figure(figsize=(12, 6))
        plt.bar(range(len(sorted_thresholds)), sorted_thresholds)
        plt.title(f'Cluster Thresholds (min_cluster_size={min_cluster_size})')
        plt.xlabel('Cluster ID (sorted by frequency)')
        plt.ylabel('Threshold')
        
        # 添加具体数值标签
        for i, v in enumerate(sorted_thresholds):
            plt.text(i, v, f'{v:,.0f}', ha='center', va='bottom')
        
        # 添加原始簇ID标签
        plt.xticks(range(len(sorted_ids)), sorted_ids, rotation=45)
        
        # 保存图片
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "cluster_thresholds.png"), dpi=300, bbox_inches='tight')
        plt.close()
        
        # 打印簇的分布情况
        print(f"\nCluster distribution for size {min_cluster_size}:")
        for cluster in cluster_data:  # 使用排序后的数据
            print(f"Cluster {cluster['id']}:")
            print(f"  Keywords: {cluster['keyword_count']}")
            print(f"  Frequency range: {cluster['min_freq']:,}-{cluster['max_freq']:,}")
            print(f"  Average frequency: {cluster['avg_freq']:.1f}")
            print(f"  Scaled threshold: {cluster['threshold']:,}")
            print(f"  Total pairs: {cluster['total_pairs']:,}")

if __name__ == "__main__":
    # 设置路径
    DATA_DIR = "../../data/raw"
    OUTPUT_DIR = "../../data/processed"
    ENRON_FILE = os.path.join(DATA_DIR, "enron_mail.tar.gz")
    
    # 创建处理器
    processor = EnronDataProcessor()
    
    # 下载数据集
    input_file = processor.download_dataset(ENRON_FILE)
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 处理数据集
    processor.process_dataset(input_file, OUTPUT_DIR) 