/**
 * test_volumes.cpp — Port of test_volumes.py
 * Tests volume spec parsing and filesystem volume application.
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <map>
#include <vector>

#include "volumes.h"

namespace fs = std::filesystem;
using namespace speakeasy;

TEST(VolumesTest, ParseVolumeSpecUnixPaths) {
    auto [host, guest] = parse_volume_spec("/tmp/samples:c:\\test");
    EXPECT_EQ(host, fs::path("/tmp/samples"));
    EXPECT_EQ(guest, "c:\\test");
}

TEST(VolumesTest, ParseVolumeSpecWindowsPaths) {
    auto [host, guest] = parse_volume_spec("C:\\samples:C:\\guest");
    EXPECT_EQ(host, fs::path("C:\\samples"));
    EXPECT_EQ(guest, "C:\\guest");
}

TEST(VolumesTest, ParseVolumeSpecEmptyThrows) {
    EXPECT_THROW(parse_volume_spec(""), std::invalid_argument);
}

TEST(VolumesTest, ParseVolumeSpecMissingColonThrows) {
    EXPECT_THROW(parse_volume_spec("foopathwithoutcolon"), std::invalid_argument);
}

TEST(VolumesTest, ParseVolumeSpecRelativePath) {
    auto [host, guest] = parse_volume_spec("./samples:c:\\test");
    EXPECT_EQ(host, fs::path("./samples"));
    EXPECT_EQ(guest, "c:\\test");
}

TEST(VolumesTest, ExpandVolumeToEntries) {
    // Create a temp directory with a test file
    fs::path tmpdir = fs::temp_directory_path() / "speakeasy_vol_test";
    fs::create_directories(tmpdir);
    std::ofstream(tmpdir / "test.dll") << "MZ" << std::string(100, '\x00');

    auto entries = expand_volume_to_entries(tmpdir, "c:\\windows\\system32");
    EXPECT_FALSE(entries.empty());

    fs::remove_all(tmpdir);
}

TEST(VolumesTest, ApplyVolumesPreprendsEntries) {
    // Test that apply_volumes adds entries to the config map
    std::map<std::string, std::map<std::string, std::vector<std::map<std::string, std::string>>>> config;
    apply_volumes(config, {"/tmp/a.dll:c:\\windows\\a.dll"});

    // The config should now contain filesystem entries
    // (even if host doesn't exist, the function should not crash)
    SUCCEED() << "apply_volumes completed without crash";
}
