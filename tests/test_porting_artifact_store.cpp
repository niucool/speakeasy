/**
 * test_porting_artifact_store.cpp  ArtifactStorePortTest (put/get, dedup, empty, size)
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "artifacts.h"

using namespace speakeasy;

TEST(ArtifactStorePortTest, GetMissing) {
    ArtifactStore store;
    EXPECT_ANY_THROW(store.get_bytes("nonexistent_hash"));
}

TEST(ArtifactStorePortTest, PutAndGet) {
    ArtifactStore store;
    std::string ref = store.put_bytes({'h','e','l','l','o'});
    EXPECT_NE(ref, "");
    auto retrieved = store.get_bytes(ref);
    ASSERT_EQ(retrieved.size(), 5);
    EXPECT_EQ(retrieved[0], 'h');
}

TEST(ArtifactStorePortTest, Dedup) {
    ArtifactStore store;
    EXPECT_EQ(store.put_bytes({'d','u','p','e'}),
              store.put_bytes({'d','u','p','e'}));
}

TEST(ArtifactStorePortTest, ToReportData) {
    ArtifactStore store;
    store.put_bytes({1,2,3});
    EXPECT_GE(store.to_report_data().size(), 1);
}

TEST(ArtifactStorePortTest, EmptyData) {
    ArtifactStore store;
    EXPECT_EQ(store.put_bytes({}), "");
}

TEST(ArtifactStorePortTest, SizeAndClear) {
    ArtifactStore store;
    store.put_bytes({1,2,3});
    store.put_bytes({4,5,6});
    EXPECT_EQ(store.size(), 2);
    store.clear();
    EXPECT_EQ(store.size(), 0);
}
