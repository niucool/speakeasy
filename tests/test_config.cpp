/**
 * test_config.cpp — Unit tests for configuration module
 */

#include <gtest/gtest.h>
#include "config.h"
#include "errors.h"
#include "report.h"
#include "volumes.h"
#include "struct.h"

using namespace speakeasy;

// ── Config tests ─────────────────────────────────────────────

TEST(ConfigTest, DefaultConfig) {
    SpeakeasyConfig cfg = default_config();
    EXPECT_EQ(cfg.emu_engine, "unicorn");
    EXPECT_EQ(cfg.system, "windows");
    EXPECT_EQ(cfg.timeout, 60);
    EXPECT_EQ(cfg.max_api_count, 10000);
    EXPECT_EQ(cfg.os_ver.name, "windows");
    EXPECT_EQ(cfg.os_ver.major, 6);
    EXPECT_EQ(cfg.os_ver.minor, 1);
    EXPECT_EQ(cfg.os_ver.build, 7601);
}

TEST(ConfigTest, ValidateConfig) {
    SpeakeasyConfig cfg = default_config();
    EXPECT_NO_THROW(validate_config(cfg));
}

TEST(ConfigTest, InvalidEngine) {
    SpeakeasyConfig cfg = default_config();
    cfg.emu_engine = "qemu";
    EXPECT_THROW(validate_config(cfg), ConfigError);
}

// ── Report tests ─────────────────────────────────────────────

TEST(ReportTest, DataArtifactJson) {
    DataArtifact art;
    art.compression = "none";
    art.encoding = "base64";
    art.size = 100;
    art.data = "dGVzdA==";  // "test" in base64

    nlohmann::json j = art.to_json();
    EXPECT_EQ(j["compression"], "none");
    EXPECT_EQ(j["encoding"], "base64");
    EXPECT_EQ(j["size"], 100);
    EXPECT_EQ(j["data"], "dGVzdA==");
}

TEST(ReportTest, EmuReportJson) {
    Report report;
    report.sha256 = "abc123";
    report.filetype = "dll";
    report.arch = "x86";

    nlohmann::json j = report.to_json();
    EXPECT_EQ(j["sha256"], "abc123");
    EXPECT_EQ(j["filetype"], "dll");
    EXPECT_EQ(j["arch"], "x86");
}

// ── Volumes tests ────────────────────────────────────────────

TEST(VolumesTest, ParseVolumeSpec) {
    auto [host, guest] = parse_volume_spec("/tmp/samples:C:\\guest");
    EXPECT_EQ(host, "/tmp/samples");
    EXPECT_EQ(guest, "C:\\guest");
}

TEST(VolumesTest, ParseVolumeSpecWindows) {
    auto [host, guest] = parse_volume_spec("C:\\samples:C:\\guest");
    EXPECT_EQ(guest, "C:\\guest");
}

TEST(VolumesTest, ParseEmptySpec) {
    EXPECT_THROW(parse_volume_spec(""), std::invalid_argument);
}

TEST(VolumesTest, ParseMissingColon) {
    EXPECT_THROW(parse_volume_spec("foo"), std::invalid_argument);
}

// ── Struct tests ─────────────────────────────────────────────

TEST(StructTest, HexFormat) {
    EXPECT_EQ(hex_str(0x7c000000), "0x7C000000");
    EXPECT_EQ(hex_str(0, false), "0");
}

TEST(StructTest, EmuPtr) {
    EmuPtr<int> ptr(0x00400000);
    EXPECT_EQ(ptr.address, 0x00400000ULL);
    EXPECT_FALSE(ptr.is_null());

    EmuPtr<int> null_ptr;
    EXPECT_EQ(null_ptr.address, 0);
    EXPECT_TRUE(null_ptr.is_null());
}

TEST(StructTest, EmuEnum) {
    EmuEnum e;
    e.set("FOO", 1);
    e.set("BAR", 2);
    EXPECT_EQ(e.get("FOO"), 1);
    EXPECT_EQ(e.get("BAR"), 2);
    EXPECT_TRUE(e.has("FOO"));
    EXPECT_FALSE(e.has("BAZ"));
}
