# SGX BM 搜索服务测试前端

这个目录包含了用于测试 SGX BM 和 BM++ 搜索服务的前端应用程序。

## 目录结构

- `bm-search-app/` - React 应用程序源代码
- `start-frontend.sh` - 快速启动脚本

## 运行前提

- 确保 BM 服务器运行在 http://localhost:8080
- 确保 BM++ 服务器运行在 http://localhost:8081
- Node.js 16+ 和 npm 已安装

## 快速启动

使用提供的脚本启动前端应用：

```bash
./start-frontend.sh
```

## 手动启动

如果脚本不起作用，您可以手动启动前端：

```bash
cd bm-search-app
npm install
npm start
```

## 使用方法

1. 访问 http://localhost:3000
2. 使用顶部导航栏在 BM 和 BM++ 测试器之间切换
3. 按照界面上的按钮执行各种操作
4. 查看右侧面板中的 API 调用结果

## 故障排除

- 如果遇到 CORS 错误，请确保服务器已正确配置 CORS 或使用代理
- 如果连接被拒绝，请确认服务器是否在正确的端口上运行
- 详细的使用说明请参考 `bm-search-app/README.md` 