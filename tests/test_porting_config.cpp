/**
 * test_porting_config.cpp  ConfigTest (defaults, JSON round-trip, merge, validate, legacy alias)
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "config.h"
#include "errors.h"

using namespace speakeasy;

TEST(ConfigTest, DefaultConfigValidates) {
    SpeakeasyConfig cfg;
    EXPECT_NO_THROW(cfg.validate_config());
}

TEST(ConfigTest, DefaultHasExpectedValues) {
    SpeakeasyConfig cfg;
    EXPECT_EQ(cfg.timeout, 60);
    EXPECT_EQ(cfg.max_api_count, 10000);
    EXPECT_EQ(cfg.os_ver.major, 6);
    EXPECT_EQ(cfg.analysis.strings, true);
}

TEST(ConfigTest, JsonRoundTrip) {
    SpeakeasyConfig cfg;
    cfg.timeout = 90;
    cfg.analysis.coverage = true;
    nlohmann::json j = cfg;
    SpeakeasyConfig cfg2 = j;
    EXPECT_EQ(cfg2.timeout, 90);
    EXPECT_EQ(cfg2.analysis.coverage, true);
    EXPECT_EQ(cfg2.analysis.strings, true);  // non-overridden preserved
}

TEST(ConfigTest, CustomOsVersion) {
    nlohmann::json j;
    j["os_ver"]["major"] = 10;
    j["os_ver"]["minor"] = 0;
    j["os_ver"]["build"] = 19041;
    SpeakeasyConfig cfg = j;
    EXPECT_EQ(cfg.os_ver.major, 10);
    EXPECT_EQ(cfg.os_ver.minor, 0);
}

TEST(ConfigTest, RejectsInvalidEngine) {
    nlohmann::json j;
    j["emu_engine"] = "alternate_engine";
    SpeakeasyConfig cfg = j;
    EXPECT_THROW(cfg.validate_config(), ConfigError);
}

// Legacy capture_memory_dumps alias (test_config_memory_dumps.py)
TEST(ConfigTest, LegacyCaptureMemoryDumpsAlias) {
    nlohmann::json j = R"({
        "config_version": 0.2,
        "emu_engine": "unicorn",
        "timeout": 60,
        "system": "windows",
        "capture_memory_dumps": true,
        "analysis": {"memory_tracing": false, "strings": true, "coverage": false},
        "exceptions": {"dispatch_handlers": true},
        "os_ver": {},
        "current_dir": "C:\\Windows",
        "hostname": "test",
        "user": {"name": "test"},
        "filesystem": {"files": []},
        "network": {"dns": {"names": {}}, "http": {"responses": []},
                     "winsock": {"responses": []}, "adapters": []},
        "modules": {"module_directory_x86": "", "module_directory_x64": ""}
    })"_json;
    SpeakeasyConfig cfg = j;
    SUCCEED();
}
