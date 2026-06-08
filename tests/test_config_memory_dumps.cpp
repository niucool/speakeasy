/**
 * test_config_memory_dumps.cpp — Port of test_config_memory_dumps.py
 * Tests that the legacy capture_memory_dumps config alias maps to snapshot_memory_regions.
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "config.h"

using json = nlohmann::json;
using namespace speakeasy;

TEST(ConfigMemoryDumpsTest, LegacyCaptureMemoryDumpsAliasStillWorks) {
    json data = {
        {"config_version", 0.2},
        {"emu_engine", "unicorn"},
        {"timeout", 60},
        {"system", "windows"},
        {"capture_memory_dumps", true},
        {"analysis", {
            {"memory_tracing", false},
            {"strings", true},
            {"coverage", false}
        }},
        {"exceptions", {
            {"dispatch_handlers", true}
        }},
        {"os_ver", {}},
        {"current_dir", "C:\\Windows"},
        {"hostname", "test"},
        {"user", {{"name", "test"}}},
        {"filesystem", {{"files", json::array()}}},
        {"network", {
            {"dns", {{"names", {}}}},
            {"http", {{"responses", json::array()}}},
            {"winsock", {{"responses", json::array()}}},
            {"adapters", json::array()}
        }},
        {"modules", {
            {"module_directory_x86", ""},
            {"module_directory_x64", ""}
        }}
    };

    SpeakeasyConfig cfg;
    from_json(data, cfg);
    // The legacy capture_memory_dumps should map to snapshot_memory_regions
    EXPECT_TRUE(cfg.snapshot_memory_regions);
}

TEST(ConfigMemoryDumpsTest, SnapshotMemoryRegionsDefaultsFalse) {
    SpeakeasyConfig cfg;
    EXPECT_FALSE(cfg.snapshot_memory_regions);
}

TEST(ConfigMemoryDumpsTest, ExplicitSnapshotMemoryRegionsTrue) {
    json data = {
        {"snapshot_memory_regions", true},
        {"analysis", {{"memory_tracing", true}}}
    };
    SpeakeasyConfig cfg;
    from_json(data, cfg);
    EXPECT_TRUE(cfg.snapshot_memory_regions);
    EXPECT_TRUE(cfg.analysis.memory_tracing);
}

TEST(ConfigMemoryDumpsTest, ValidDefaultConfig) {
    SpeakeasyConfig cfg;
    EXPECT_NO_THROW(cfg.validate_config());
}
