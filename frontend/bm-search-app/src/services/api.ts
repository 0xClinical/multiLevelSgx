import axios from 'axios';

// BM 服务器 API（使用代理）
const bmApi = axios.create({
  baseURL: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

// BM++ 服务器 API（直接访问）
const bmPlusApi = axios.create({
  baseURL: 'http://localhost:8081',
  headers: {
    'Content-Type': 'application/json',
  },
});

// 定义用户接口
export interface User {
  id: string;
  level: number;
  state: number;
  publicKey: string;
}

// 定义文档接口
export interface Document {
  id: string;
  level: number;
  state: number;
  isBogus?: boolean;
}

// BM 服务器 API 函数
export const bmServices = {
  // 添加用户
  addUser: (user: User) => {
    return bmApi.post('/add-user', user);
  },

  // 上传单个文档
  uploadDocument: (keyword: string, document: Document) => {
    return bmApi.post('/upload-document', { keyword, document });
  },

  // 批量上传文档
  uploadDocuments: (keyword: string, documents: Document[]) => {
    return bmApi.post('/upload-documents', { keyword, documents });
  },

  // 删除单个文档
  deleteDocument: (keyword: string, documentId: string) => {
    return bmApi.delete('/delete-document', { 
      data: { keyword, document_id: documentId } 
    });
  },

  // 批量删除文档
  deleteDocuments: (keyword: string, documentIds: string[]) => {
    return bmApi.delete('/delete-documents', { 
      data: { keyword, document_ids: documentIds } 
    });
  },

  // 搜索文档
  search: (userId: string, privateKey: string, keyword: string, maxDoc?: number) => {
    return bmApi.post('/search', { userId, privateKey, keyword, maxDoc });
  },

  // 重建索引
  rebuildIndices: () => {
    return bmApi.post('/rebuild-indices');
  }
};

// BM++ 服务器 API 函数
export const bmPlusServices = {
  // 添加用户
  addUser: (user: User) => {
    return bmPlusApi.post('/add-user', user);
  },

  // 上传单个文档
  uploadDocument: (keyword: string, document: Document) => {
    return bmPlusApi.post('/upload-document', { keyword, document });
  },

  // 批量上传文档
  uploadDocuments: (keyword: string, documents: Document[]) => {
    return bmPlusApi.post('/upload-documents', { keyword, documents });
  },

  // 删除单个文档
  deleteDocument: (keyword: string, documentId: string) => {
    return bmPlusApi.delete('/delete-document', { 
      data: { keyword, document_id: documentId } 
    });
  },

  // 批量删除文档
  deleteDocuments: (keyword: string, documentIds: string[]) => {
    return bmPlusApi.delete('/delete-documents', { 
      data: { keyword, document_ids: documentIds } 
    });
  },

  // 搜索文档
  search: (userId: string, privateKey: string, keyword: string, maxDoc?: number) => {
    return bmPlusApi.post('/search', { userId, privateKey, keyword, maxDoc });
  },

  // 重建索引
  rebuildIndices: () => {
    return bmPlusApi.post('/rebuild-indices');
  },

  // 重加密簇
  reencryptCluster: (clusterIndex: number) => {
    return bmPlusApi.post('/reencrypt-cluster', { cluster_index: clusterIndex });
  }
}; 