#include <gtest/gtest.h>
#include "core/cloud_server.h"

TEST(CloudServerTest, StoreAndRetrieveFile) {
    CloudServer server;
    server.storeEncryptedFile("file1", "encryptedContent");
    EXPECT_EQ(server.getEncryptedFile("file1"), "encryptedContent");
}

TEST(CloudServerTest, UpdateIndex) {
    CloudServer server;
    std::vector<IndexNode> nodes = { /* ... populate with test data ... */ };
    LookupTable table = { /* ... populate with test data ... */ };
    server.updateIndex(nodes, table);
    EXPECT_EQ(server.getEncryptedIndex().size(), nodes.size());
}
