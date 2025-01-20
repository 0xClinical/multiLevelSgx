#include <gtest/gtest.h>
#include "utils/crypto.h"

TEST(CryptoUtilsTest, GenerateKeyPair) {
    auto [publicKey, privateKey] = CryptoUtils::generateKeyPair();
    EXPECT_FALSE(publicKey.empty());
    EXPECT_FALSE(privateKey.empty());
}

TEST(CryptoUtilsTest, ComputeDigest) {
    std::string data = "testData";
    std::string digest = CryptoUtils::computeDigest(data);
    EXPECT_FALSE(digest.empty());
}
