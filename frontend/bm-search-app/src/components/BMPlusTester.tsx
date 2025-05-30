import React, { useState } from 'react';
import { Button, Container, Form, Card, Row, Col, ListGroup, Alert, Spinner } from 'react-bootstrap';
import { bmPlusServices } from '../services/api';
import { 
  generateTestUser, 
  generateTestDocument, 
  generateMultipleTestDocuments, 
  generateTestKeyword 
} from '../utils/testUtils';

const BMPlusTester: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'danger' }>({ text: '', type: 'success' });
  const [result, setResult] = useState<any>(null);

  // 当前的测试用户
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [currentKeyword, setCurrentKeyword] = useState<string>('');
  const [currentDocuments, setCurrentDocuments] = useState<any[]>([]);
  const [clusterIndex, setClusterIndex] = useState<number>(0);

  // 显示结果消息
  const showMessage = (text: string, type: 'success' | 'danger') => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: '', type: 'success' }), 5000);
  };

  // 添加用户
  const handleAddUser = async () => {
    setLoading(true);
    try {
      const user = generateTestUser();
      const response = await bmPlusServices.addUser(user);
      setCurrentUser(user);
      showMessage(`用户添加成功: ${user.id}`, 'success');
      setResult(response.data);
    } catch (error) {
      console.error('添加用户失败:', error);
      showMessage('添加用户失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 上传单个文档
  const handleUploadDocument = async () => {
    if (!currentUser) {
      showMessage('请先添加用户', 'danger');
      return;
    }

    setLoading(true);
    try {
      const keyword = generateTestKeyword();
      const document = generateTestDocument();
      const response = await bmPlusServices.uploadDocument(keyword, document);
      
      setCurrentKeyword(keyword);
      setCurrentDocuments([...currentDocuments, document]);
      
      showMessage(`文档上传成功: ${document.id}`, 'success');
      setResult(response.data);
    } catch (error) {
      console.error('上传文档失败:', error);
      showMessage('上传文档失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 批量上传文档
  const handleUploadMultipleDocuments = async () => {
    if (!currentUser) {
      showMessage('请先添加用户', 'danger');
      return;
    }

    setLoading(true);
    try {
      const keyword = generateTestKeyword();
      const documents = generateMultipleTestDocuments(5);
      const response = await bmPlusServices.uploadDocuments(keyword, documents);
      
      setCurrentKeyword(keyword);
      setCurrentDocuments([...currentDocuments, ...documents]);
      
      showMessage(`批量上传成功: ${documents.length} 个文档`, 'success');
      setResult(response.data);
    } catch (error) {
      console.error('批量上传文档失败:', error);
      showMessage('批量上传文档失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 删除文档
  const handleDeleteDocument = async () => {
    if (currentDocuments.length === 0) {
      showMessage('没有可删除的文档', 'danger');
      return;
    }

    setLoading(true);
    try {
      // 删除最后一个文档
      const documentToDelete = currentDocuments[currentDocuments.length - 1];
      const response = await bmPlusServices.deleteDocument(currentKeyword, documentToDelete.id);
      
      // 更新当前文档列表
      setCurrentDocuments(currentDocuments.slice(0, -1));
      
      showMessage(`文档删除成功: ${documentToDelete.id}`, 'success');
      setResult(response.data);
    } catch (error) {
      console.error('删除文档失败:', error);
      showMessage('删除文档失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 搜索文档
  const handleSearch = async () => {
    if (!currentUser || !currentKeyword) {
      showMessage('请先添加用户并上传文档', 'danger');
      return;
    }

    setLoading(true);
    try {
      const response = await bmPlusServices.search(
        currentUser.id, 
        currentUser.privateKey, 
        currentKeyword
      );
      
      showMessage('搜索成功', 'success');
      setResult(response.data);
    } catch (error) {
      console.error('搜索失败:', error);
      showMessage('搜索失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 重建索引
  const handleRebuildIndices = async () => {
    setLoading(true);
    try {
      const response = await bmPlusServices.rebuildIndices();
      showMessage('索引重建成功', 'success');
      setResult(response.data);
    } catch (error) {
      console.error('重建索引失败:', error);
      showMessage('重建索引失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 重加密簇
  const handleReencryptCluster = async () => {
    setLoading(true);
    try {
      const response = await bmPlusServices.reencryptCluster(clusterIndex);
      showMessage(`簇 ${clusterIndex} 重加密成功`, 'success');
      setResult(response.data);
      // 更新簇索引，简单地+1，如果达到一个假设的最大值（10）就回到0
      setClusterIndex((clusterIndex + 1) % 10);
    } catch (error) {
      console.error('重加密簇失败:', error);
      showMessage('重加密簇失败', 'danger');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container className="mt-4">
      <h2>BM++ 服务器测试</h2>

      {message.text && (
        <Alert variant={message.type} className="mt-3">
          {message.text}
        </Alert>
      )}

      <Row className="mt-4">
        <Col md={6}>
          <Card>
            <Card.Header>测试操作</Card.Header>
            <Card.Body>
              <Button 
                variant="primary" 
                onClick={handleAddUser} 
                disabled={loading}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '添加用户'}
              </Button>

              <Button 
                variant="success" 
                onClick={handleUploadDocument} 
                disabled={loading || !currentUser}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '上传单个文档'}
              </Button>

              <Button 
                variant="info" 
                onClick={handleUploadMultipleDocuments} 
                disabled={loading || !currentUser}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '批量上传文档'}
              </Button>

              <Button 
                variant="warning" 
                onClick={handleDeleteDocument} 
                disabled={loading || currentDocuments.length === 0}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '删除文档'}
              </Button>

              <Button 
                variant="success" 
                onClick={handleSearch} 
                disabled={loading || !currentUser || !currentKeyword}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '搜索文档'}
              </Button>

              <Button 
                variant="secondary" 
                onClick={handleRebuildIndices} 
                disabled={loading}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : '重建索引'}
              </Button>

              <Button 
                variant="dark" 
                onClick={handleReencryptCluster} 
                disabled={loading}
                className="m-2"
              >
                {loading ? <Spinner animation="border" size="sm" /> : `重加密簇 (${clusterIndex})`}
              </Button>
            </Card.Body>
          </Card>

          <Card className="mt-3">
            <Card.Header>当前状态</Card.Header>
            <Card.Body>
              <div>
                <strong>用户:</strong> {currentUser ? currentUser.id : '无'}
              </div>
              <div>
                <strong>关键词:</strong> {currentKeyword || '无'}
              </div>
              <div>
                <strong>文档数量:</strong> {currentDocuments.length}
              </div>
              <div>
                <strong>当前簇索引:</strong> {clusterIndex}
              </div>
            </Card.Body>
          </Card>
        </Col>

        <Col md={6}>
          <Card>
            <Card.Header>测试结果</Card.Header>
            <Card.Body>
              {result ? (
                <pre style={{ maxHeight: '400px', overflow: 'auto' }}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              ) : (
                <p>无结果数据</p>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {currentDocuments.length > 0 && (
        <Card className="mt-4">
          <Card.Header>当前文档列表</Card.Header>
          <Card.Body>
            <ListGroup>
              {currentDocuments.map((doc, index) => (
                <ListGroup.Item key={index}>
                  ID: {doc.id}, 级别: {doc.level}, 状态: {doc.state}
                  {doc.isBogus && <span className="text-danger"> (伪造文档)</span>}
                </ListGroup.Item>
              ))}
            </ListGroup>
          </Card.Body>
        </Card>
      )}
    </Container>
  );
};

export default BMPlusTester; 