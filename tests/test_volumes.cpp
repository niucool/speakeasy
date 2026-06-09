/**
 * test_volumes.cpp  Port of test_volumes.py
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
    fs::path tmpdir = fs::temp_directory_path() / "speakeasy_vol_test";
    fs::create_directories(tmpdir);
    std::ofstream(tmpdir / "test.dll") << "MZ" << std::string(100, '\x00');

    auto entries = expand_volume_to_entries(tmpdir, "c:\\windows\\system32");
    EXPECT_FALSE(entries.empty());

    fs::remove_all(tmpdir);
}

TEST(VolumesTest, ApplyVolumesPreprendsEntries) {
    // Create a dummy file first so the volume host path exists
    fs::path dummy = fs::temp_directory_path() / "speakeasy_vol_a.dll";
    {
        std::ofstream f(dummy);
        f << "MZ" << std::string(100, '\x00');
    }

    using VolumeConfig = std::map<std::string, std::map<std::string, std::vector<std::map<std::string, std::string>>>>;
    VolumeConfig config;
    std::string spec = dummy.string() + ":c:\\windows\\a.dll";
    apply_volumes(config, {spec});

    // The config should now contain filesystem entries
    EXPECT_FALSE(config.empty());

    fs::remove(dummy);
}
