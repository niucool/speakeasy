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

TEST(CliConfigTest, GetDefaultConfigDictIsValid) {
    auto defaults = get_default_config_dict();
    EXPECT_FALSE(defaults.empty());
    // Top-level values are stored under the empty-string section key
    EXPECT_TRUE(defaults.count("") > 0);
    auto& top = defaults.at("");
    EXPECT_EQ(top.at("emu_engine"), "unicorn");
    EXPECT_EQ(top.at("timeout"), "60");
    EXPECT_EQ(top.at("system"), "windows");
    EXPECT_EQ(top.at("max_api_count"), "10000");
}

TEST(CliConfigTest, MergeConfigDictsMergesMappingsAndReplacesLists) {
    auto base = get_default_config_dict();

    std::map<std::string, std::map<std::string, std::string>> overlay;
    overlay["analysis"]["memory_tracing"] = "true";

    auto merged = merge_config_dicts(base, overlay);

    EXPECT_EQ(merged["analysis"]["memory_tracing"], "true");
    // Base values preserved
    EXPECT_EQ(merged["analysis"]["strings"], "true");
}

TEST(CliConfigTest, PartialConfigOverlayInheritsModelDefaults) {
    nlohmann::json partial = {{"analysis", {{"memory_tracing", true}}}};

    speakeasy::SpeakeasyConfig model;
    from_json(partial, model);

    EXPECT_TRUE(model.analysis.memory_tracing);
    EXPECT_TRUE(model.analysis.strings);
    EXPECT_EQ(model.os_ver.major, 6);
}

TEST(CliConfigTest, ConfigPrecedencePrefersCliOverConfigOverlay) {
    auto base = get_default_config_dict();

    std::map<std::string, std::map<std::string, std::string>> config_overlay;
    config_overlay[""]["timeout"] = "15";
    config_overlay["analysis"]["coverage"] = "true";

    auto layered = merge_config_dicts(base, config_overlay);
    EXPECT_EQ(layered[""]["timeout"], "15");
    EXPECT_EQ(layered["analysis"]["coverage"], "true");

    // After CLI override
    std::map<std::string, std::map<std::string, std::string>> cli_overrides;
    cli_overrides[""]["timeout"] = "90";
    cli_overrides["analysis"]["coverage"] = "false";
    auto final = merge_config_dicts(layered, cli_overrides);

    EXPECT_EQ(final[""]["timeout"], "90");
    EXPECT_EQ(final["analysis"]["coverage"], "false");
}

TEST(CliConfigTest, GetConfigCliFieldSpecsReturnsValidSpecs) {
    auto specs = get_config_cli_field_specs();
    EXPECT_FALSE(specs.empty());
    for (auto& spec : specs) {
        EXPECT_FALSE(spec.path.empty());
        EXPECT_FALSE(spec.option.empty());
        EXPECT_FALSE(spec.kind.empty());
    }
}
