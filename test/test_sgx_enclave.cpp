#include <gtest/gtest.h>
#include "core/sgx_enclave.h"

TEST(SGXEnclaveTest, AddAndRevokeUser) {
    SGXEnclave sgx;
    sgx.addUser({"user1", AccessLevel::HIGH, State::ACTIVE, "publicKey", 0});
    EXPECT_TRUE(sgx.isAuthorized("user1"));
    
    sgx.removeUser("user1");
    EXPECT_FALSE(sgx.isAuthorized("user1"));
}

TEST(SGXEnclaveTest, GenerateSearchToken) {
    SGXEnclave sgx;
    sgx.addUser({"user1", AccessLevel::HIGH, State::ACTIVE, "publicKey", 0});
    uint64_t nonce = sgx.getNextNonce("user1");
    std::string signature = "validSignature";  // Assume a valid signature
    SearchToken token = sgx.generateSearchToken("user1", signature, nonce, "keyword");
    EXPECT_FALSE(token.isEmpty());
}
