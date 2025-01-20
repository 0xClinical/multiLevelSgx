#include "core/data_owner.h"
#include "core/sgx_enclave.h"
#include "core/cloud_server/edb_controller.h"
#include "core/token_generator.h"
#include "core/authorized_user.h"

int main() {
    // 初始化系统组件
    DataOwner dataOwner;
    SGXEnclave enclave;
    CloudServer server;
    TokenGenerator tokenGen;
    
    // 1. Data Owner上传文档和用户信息
    dataOwner.uploadToEnclave();
    
    // 2. 用户发起搜索请求
    AuthorizedUser user("user1");
    std::string keyword = "example";
    
    // 3. 验证用户身份
    std::string signature = user.sign();
    if (!enclave.verifyUser(user.getId(), signature)) {
        return -1;
    }
    
    // 4. 生成搜索令牌
    SearchToken token = tokenGen.generateToken(keyword, 
                                             user.getLevelKey(),
                                             user.getStatusKey());
    
    // 5. 执行搜索
    auto results = server.search(token);
    
    // 6. SGX Enclave处理结果
    auto finalResults = enclave.processSearch(token);
    
    return 0;
}
