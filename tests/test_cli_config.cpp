/**
 * test_cli_config.cpp — Port of test_cli_config.py
 * Tests CLI configuration precedence, merging, and validation.
 */

#include <gtest/gtest.h>
#include <string>
#include <map>
#include <nlohmann/json.hpp>

#include "cli_config.h"
#include "config.h"

using namespace speakeasy;

// Helper to convert nested string map back to flat assertions
// The C++ API uses std::map<string, map<string,string>> for config dicts

TEST(CliConfigTest, GetDefaultConfigDictIsValid) {
    auto defaults = get_default_config_dict();
    EXPECT_FALSE(defaults.empty());
    EXPECT_TRUE(defaults.count("timeout") > 0);
    EXPECT_TRUE(defaults.count("emu_engine") > 0);
    EXPECT_TRUE(defaults.count("system") > 0);
}

TEST(CliConfigTest, MergeConfigDictsMergesMappingsAndReplacesLists) {
    auto base = get_default_config_dict();

    // Build overlay with analysis.memory_tracing = true
    std::map<std::string, std::map<std::string, std::string>> overlay;
    overlay["analysis"]["memory_tracing"] = "true";

    auto merged = merge_config_dicts(base, overlay);

    // analysis.memory_tracing should be true from overlay
    EXPECT_EQ(merged["analysis"]["memory_tracing"], "true");
    // analysis.strings should still be from base (merged, not replaced)
    EXPECT_EQ(merged["analysis"]["strings"], "true");
}

TEST(CliConfigTest, PartialConfigOverlayInheritsModelDefaults) {
    // Test that partial config JSON inherits model defaults
    nlohmann::json partial = {{"analysis", {{"memory_tracing", true}}}};

    speakeasy::SpeakeasyConfig model;
    from_json(partial, model);

    EXPECT_TRUE(model.analysis.memory_tracing);
    // Should inherit defaults for unspecified fields
    EXPECT_TRUE(model.analysis.strings);
    EXPECT_EQ(model.os_ver.major, 6);
}

TEST(CliConfigTest, ConfigPrecedencePrefersCliOverConfigOverlay) {
    auto base = get_default_config_dict();

    std::map<std::string, std::map<std::string, std::string>> config_overlay;
    config_overlay["timeout"] = {{"", "15"}};
    config_overlay["analysis"]["coverage"] = "true";

    auto layered = merge_config_dicts(base, config_overlay);
    EXPECT_EQ(layered["timeout"][""], "15");
    EXPECT_EQ(layered["analysis"]["coverage"], "true");

    // After CLI override: timeout=90, coverage=false
    std::map<std::string, std::map<std::string, std::string>> cli_overrides;
    cli_overrides["timeout"] = {{"", "90"}};
    cli_overrides["analysis"]["coverage"] = "false";
    auto final = merge_config_dicts(layered, cli_overrides);

    EXPECT_EQ(final["timeout"][""], "90");
    EXPECT_EQ(final["analysis"]["coverage"], "false");
}

TEST(CliConfigTest, GetConfigCliFieldSpecsReturnsValidSpecs) {
    auto specs = get_config_cli_field_specs();
    EXPECT_FALSE(specs.empty());
    // Verify all specs have required fields
    for (auto& spec : specs) {
        EXPECT_FALSE(spec.path.empty());
        EXPECT_FALSE(spec.option.empty());
        EXPECT_FALSE(spec.kind.empty());
    }
}
