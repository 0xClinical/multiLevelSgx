import { User, Document } from '../services/api';

// 生成随机 ID
export const generateRandomId = (prefix: string): string => {
  return `${prefix}_${Math.random().toString(36).substring(2, 10)}`;
};

// 生成随机公钥（模拟）
export const generateRandomPublicKey = (): string => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

// 生成随机私钥（模拟）
export const generateRandomPrivateKey = (): string => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 64; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

// 生成测试用户
export const generateTestUser = (): User & { privateKey: string } => {
  const id = generateRandomId('user');
  const publicKey = generateRandomPublicKey();
  const privateKey = generateRandomPrivateKey();
  
  return {
    id,
    level: Math.floor(3), // 随机 0-4 级别
    state: Math.floor(10), // 随机 0-2 状态
    publicKey,
    privateKey
  };
};

// 生成测试文档
export const generateTestDocument = (): Document => {
  return {
    id: generateRandomId('doc'),
    level: Math.floor(Math.random() * 3) + 1, // 随机 1-3 级别
    state: Math.floor(Math.random() * 10) + 1, // 随机 1-10 状态
    isBogus: Math.random() > 0.8 // 20% 的概率是 bogus 文档
  };
};

// 生成多个测试文档
export const generateMultipleTestDocuments = (count: number): Document[] => {
  const documents: Document[] = [];
  for (let i = 0; i < count; i++) {
    documents.push(generateTestDocument());
  }
  return documents;
};

// 生成测试关键词
export const generateTestKeyword = (): string => {
  const keywords = [
    'security', 'privacy', 'encryption', 'search', 'sgx', 
    'machine_learning', 'blockchain', 'ai', 'network', 'database',
    'algorithm', 'system', 'cloud', 'iot', 'mobile', 'web',
    'cryptography', 'protocol', 'authentication', 'authorization'
  ];
  return keywords[Math.floor(Math.random() * keywords.length)];
}; 