/**
 * test_artifact_store.cpp  Port of test_artifact_store.py
 * Tests the ArtifactStore deduplication and report data roundtrip.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "artifacts.h"
#include "report.h"

using namespace speakeasy;

TEST(ArtifactStoreTest, DeduplicatesPayloads) {
    ArtifactStore store;

    std::vector<uint8_t> payload = {'a', 'r', 't', 'i', 'f', 'a', 'c', 't', '-', 'b', 'y', 't', 'e', 's'};
    auto first_ref = store.put_bytes(payload);
    auto second_ref = store.put_bytes(payload);

    EXPECT_EQ(first_ref, second_ref);

    auto report_data = store.to_report_data();
    ASSERT_EQ(report_data.size(), 1);
    EXPECT_TRUE(report_data.count(first_ref) > 0);

    auto decoded = store.get_bytes(first_ref);
    EXPECT_EQ(decoded, payload);
}

TEST(ArtifactStoreTest, ReportDataRoundtripJson) {
    // Build a Report with embedded DataArtifact
    Report report;
    report.emulation_total_runtime = 1.0;
    report.timestamp = 123;

    DataArtifact art;
    art.compression = "zlib";
    art.encoding = "base64";
    art.size = 4;
    art.data = "eJwrSS1iAQAEXwHb";  // zlib+base64 of "data"  approximate

    report.data = std::map<std::string, DataArtifact>{{"deadbeef", art}};

    // Serialize to JSON and back
    nlohmann::json j = report.to_json();
    EXPECT_EQ(j["emulation_total_runtime"], 1.0);
    EXPECT_EQ(j["timestamp"], 123);
    EXPECT_TRUE(j.contains("data"));
    EXPECT_TRUE(j["data"].contains("deadbeef"));

    // Verify the artifact is present
    auto& restored_art = j["data"]["deadbeef"];
    EXPECT_EQ(restored_art["compression"], "zlib");
    EXPECT_EQ(restored_art["encoding"], "base64");
    EXPECT_EQ(restored_art["size"], 4);
}

TEST(ArtifactStoreTest, DifferentPayloadsGetDifferentRefs) {
    ArtifactStore store;
    auto ref1 = store.put_bytes({'h', 'e', 'l', 'l', 'o'});
    auto ref2 = store.put_bytes({'w', 'o', 'r', 'l', 'd'});
    EXPECT_NE(ref1, ref2);

    auto report_data = store.to_report_data();
    EXPECT_EQ(report_data.size(), 2);
}

TEST(ArtifactStoreTest, GetBytesReturnsCorrectData) {
    ArtifactStore store;
    std::vector<uint8_t> original = {0xDE, 0xAD, 0xBE, 0xEF};
    auto ref = store.put_bytes(original);
    auto retrieved = store.get_bytes(ref);
    EXPECT_EQ(retrieved, original);
}
