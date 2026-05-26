// cli_config.h  CLI configuration field specs and overrides
//
// Maps to: speakeasy/cli_config.py

#ifndef SPEAKEASY_CLI_CONFIG_H
#define SPEAKEASY_CLI_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cxxopts.hpp>

namespace speakeasy {

/// Describes one config field exposed as a CLI option
struct CliFieldSpec {
    std::string path;        // dotted config path, e.g. "analysis.memory_tracing"
    std::string option;      // CLI flag, e.g. "--memory-tracing"
    std::string dest;        // parsed destination variable name
    std::string kind;        // "bool", "int", "float", "str", "list_str"
    std::string description;
    std::string default_val; // string representation of default
};

/// Build the list of CLI-exposable config fields
std::vector<CliFieldSpec> get_config_cli_field_specs();

/// Add config-related arguments to a cxxopts option group
void add_config_cli_arguments(cxxopts::Options& options);

/// Merge user config JSON over base defaults (deep merge)
std::map<std::string, std::map<std::string, std::string>>
merge_config_dicts(const std::map<std::string, std::map<std::string, std::string>>& base,
                   const std::map<std::string, std::map<std::string, std::string>>& overlay);

/// Apply CLI argument overrides to a config dictionary
void apply_config_cli_overrides(std::map<std::string, std::map<std::string, std::string>>& config,
                                const cxxopts::ParseResult& args);

/// Get default config as a string-keyed dictionary
std::map<std::string, std::map<std::string, std::string>> get_default_config_dict();

} // namespace speakeasy

#endif
