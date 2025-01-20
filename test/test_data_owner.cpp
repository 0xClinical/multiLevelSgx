#include <gtest/gtest.h>
#include "core/data_owner.h"

TEST(DataOwnerTest, AddAndRevokeUser) {
    DataOwner owner;
    owner.addAuthorizedUser("user1", AccessLevel::HIGH, State::ACTIVE);
    EXPECT_TRUE(owner.isAuthorized("user1"));
    
    owner.revokeUser("user1");
    EXPECT_FALSE(owner.isAuthorized("user1"));
}

TEST(DataOwnerTest, AddDocument) {
    DataOwner owner;
    Document doc = {"doc1", AccessLevel::HIGH, State::ACTIVE, {"keyword1", "keyword2"}};
    owner.addDocument(doc);
    // Verify document addition logic
}
