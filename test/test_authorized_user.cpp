#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>
#include "core/authorized_user.h"
#include "core/sgx_enclave.h"
#include "core/cloud_server.h"

TEST(AuthorizedUserTest, SearchFiles) {
    auto sgx = std::make_shared<SGXEnclave>();
    auto server = std::make_shared<CloudServer>();
    AuthorizedUser user("user1", "privateKey", sgx, server);
    
    std::string keyword = "testKeyword";
    std::vector<std::string> results = user.searchFiles(keyword);
    EXPECT_FALSE(results.empty());
}
