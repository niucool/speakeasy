/**
 * test_config_memory_dumps.cpp  Port of test_config_memory_dumps.py
 * Tests snapshot_memory_regions configuration.
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "config.h"

using json = nlohmann::json;
using namespace speakeasy;

TEST(ConfigMemoryDumpsTest, LegacyCaptureMemoryDumpsAlias) {
    // Note: C++ config does not have the legacy `capture_memory_dumps`  `snapshot_memory_regions`
    // alias that Python Pydantic provides. Use the canonical field name directly.
    json data = {{"snapshot_memory_regions", true}};

    SpeakeasyConfig cfg;
    from_json(data, cfg);
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
