// cli_config.cpp — CLI configuration implementation

#include "cli_config.h"

namespace speakeasy {

std::vector<CliFieldSpec> get_config_cli_field_specs() {
    return {
        {"analysis.memory_tracing",  "--memory-tracing",  "memory_tracing",  "bool", "Enable memory tracing", "false"},
        {"analysis.strings",         "--extract-strings", "extract_strings", "bool", "Extract strings from memory", "true"},
        {"analysis.coverage",        "--coverage",        "coverage",        "bool", "Enable code coverage", "false"},
        {"timeout",                  "--timeout",          "timeout",          "int",  "Emulation timeout (seconds)", "60"},
        {"max_api_count",            "--max-api-count",   "max_api_count",   "int",  "Maximum API calls per run", "10000"},
        {"stack_size",               "--stack-size",      "stack_size",      "int",  "Stack commit size", "0"},
        {"current_dir",              "--current-dir",     "current_dir",     "str",  "Emulated current directory", "C:\\Windows\\system32"},
        {"command_line",             "--command-line",    "command_line",    "str",  "Emulated process command line", "svchost.exe"},
        {"domain",                   "--domain",          "domain",          "str",  "Domain name", "speakeasy_domain"},
        {"hostname",                 "--hostname",        "hostname",        "str",  "Hostname", "speakeasy_host"},
        {"keep_memory_on_free",      "--keep-memory",     "keep_memory",     "bool", "Keep memory pages on free", "false"},
        {"user.name",                "--user-name",       "user_name",       "str",  "Emulated user name", "speakeasy_user"},
        {"user.is_admin",            "--user-admin",      "user_admin",      "bool", "User is admin", "true"},
        {"os_ver.major",             "--os-major",        "os_major",        "int",  "OS major version", "6"},
        {"os_ver.minor",             "--os-minor",        "os_minor",        "int",  "OS minor version", "1"},
        {"os_ver.build",             "--os-build",        "os_build",        "int",  "OS build number", "7601"},
        {"exceptions.dispatch_handlers", "--dispatch-seh","dispatch_seh",    "bool", "Dispatch SEH exception handlers", "true"},
        {"api_hammering.enabled",    "--api-hammering",   "api_hammering",   "bool", "Enable API hammering detection", "false"},
        {"api_hammering.threshold",  "--hammer-threshold","hammer_threshold","int",  "API hammering threshold", "2000"},
    };
}

void add_config_cli_arguments(cxxopts::Options& options) {
    for (auto& spec : get_config_cli_field_specs()) {
        std::string desc = spec.description + " (default: " + spec.default_val + ")";
        cxxopts::OptionNames names = {spec.option};
        if (spec.kind == "bool") {
            options.add_option("Config", "", names, desc, cxxopts::value<bool>(), "");
        } else if (spec.kind == "int") {
            options.add_option("Config", "", names, desc, cxxopts::value<int>(), "N");
        } else if (spec.kind == "float") {
            options.add_option("Config", "", names, desc, cxxopts::value<double>(), "F");
        } else if (spec.kind == "str") {
            options.add_option("Config", "", names, desc, cxxopts::value<std::string>(), "S");
        }
    }
}

std::map<std::string, std::map<std::string, std::string>> get_default_config_dict() {
    std::map<std::string, std::map<std::string, std::string>> cfg;
    cfg["analysis"] = {{"memory_tracing", "false"}, {"strings", "true"}, {"coverage", "false"}};
    cfg["exceptions"] = {{"dispatch_handlers", "true"}};
    cfg["api_hammering"] = {{"enabled", "false"}, {"threshold", "2000"}};
    cfg["os_ver"] = {{"name", "windows"}, {"major", "6"}, {"minor", "1"}, {"build", "7601"}};
    cfg["user"] = {{"name", "speakeasy_user"}, {"is_admin", "true"}};
    // Top-level
    cfg[""] = {
        {"emu_engine", "unicorn"}, {"timeout", "60"}, {"max_api_count", "10000"},
        {"stack_size", "0"}, {"system", "windows"}, {"keep_memory_on_free", "false"},
        {"current_dir", "C:\\Windows\\system32"}, {"command_line", "svchost.exe"},
        {"domain", "speakeasy_domain"}, {"hostname", "speakeasy_host"}
    };
    return cfg;
}

std::map<std::string, std::map<std::string, std::string>>
merge_config_dicts(const std::map<std::string, std::map<std::string, std::string>>& base,
                   const std::map<std::string, std::map<std::string, std::string>>& overlay) {
    auto merged = base;
    for (auto& [section, kv] : overlay) {
        if (merged.count(section)) {
            for (auto& [k, v] : kv) {
                merged[section][k] = v;
            }
        } else {
            merged[section] = kv;
        }
    }
    return merged;
}

void apply_config_cli_overrides(std::map<std::string, std::map<std::string, std::string>>& config,
                                const cxxopts::ParseResult& args) {
    for (auto& spec : get_config_cli_field_specs()) {
        if (!args.count(spec.dest)) continue;

        // Parse path into section.key
        auto dot = spec.path.find('.');
        std::string section = (dot != std::string::npos) ? spec.path.substr(0, dot) : "";
        std::string key = (dot != std::string::npos) ? spec.path.substr(dot + 1) : spec.path;

        if (spec.kind == "bool") {
            config[section][key] = args[spec.dest].as<bool>() ? "true" : "false";
        } else if (spec.kind == "int") {
            config[section][key] = std::to_string(args[spec.dest].as<int>());
        } else if (spec.kind == "float") {
            config[section][key] = std::to_string(args[spec.dest].as<double>());
        } else if (spec.kind == "str") {
            config[section][key] = args[spec.dest].as<std::string>();
        }
    }
}

} // namespace speakeasy
