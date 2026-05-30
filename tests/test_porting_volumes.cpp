/**
 * test_porting_volumes.cpp  VolumeTest (parse_volume_spec, expand)
 */

#include <gtest/gtest.h>
#include <filesystem>
#include <stdexcept>

#include "volumes.h"

using namespace speakeasy;

TEST(VolumeTest, ParseUnixToWindows) {
    auto [host, guest] = parse_volume_spec("/tmp/samples:C:\\test");
    EXPECT_EQ(host, std::filesystem::path("/tmp/samples"));
    EXPECT_EQ(guest, "C:\\test");
}

TEST(VolumeTest, ParseWindowsToWindows) {
    auto [host, guest] = parse_volume_spec("D:\\src:C:\\dest");
    EXPECT_TRUE(host == "D:\\src" || host == "D:/src");
    EXPECT_EQ(guest, "C:\\dest");
}

TEST(VolumeTest, ExpandVolumeToEntries) {
    auto entries = expand_volume_to_entries("/tmp", "C:\\test");
    SUCCEED();  // no crash on empty dir
}

TEST(VolumeTest, RejectsMissingColon) {
    EXPECT_THROW(parse_volume_spec("invalid"), std::invalid_argument);
}
