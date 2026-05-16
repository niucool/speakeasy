// config.cpp — Emulation configuration implementation
//
// Maps to: speakeasy/config.py

#include "config.h"
#include "errors.h"
#include <fstream>
#include <stdexcept>

namespace speakeasy {

// ── nlohmann_json serialization ──────────────────────────────

void to_json(nlohmann::json& j, const OsVersion& v) {
    j = nlohmann::json{
        {"name", v.name},
        {"major", v.major},
        {"minor", v.minor},
        {"build", v.build}
    };
}

void from_json(const nlohmann::json& j, OsVersion& v) {
    if (j.contains("name"))  j.at("name").get_to(v.name);
    if (j.contains("major")) j.at("major").get_to(v.major);
    if (j.contains("minor")) j.at("minor").get_to(v.minor);
    if (j.contains("build")) j.at("build").get_to(v.build);
}

// ── Macro helpers for struct serialization ───────────────────
#define JSON_GET_OPTIONAL_STRING(j, key, field) \
    if (j.contains(key)) j.at(key).get_to(field);

#define JSON_GET_OPTIONAL_INT(j, key, field) \
    if (j.contains(key)) field = j.at(key).get<int>();

#define JSON_GET_OPTIONAL_BOOL(j, key, field) \
    if (j.contains(key)) field = j.at(key).get<bool>();

// ── EmuConfig serialization ──────────────────────────────────

void to_json(nlohmann::json& j, const SpeakeasyConfig& cfg) {
    j = nlohmann::json{
        {"config_version", cfg.config_version},
        {"description", cfg.description},
        {"emu_engine", cfg.emu_engine},
        {"timeout", cfg.timeout},
        {"max_api_count", cfg.max_api_count},
        {"stack_size", cfg.stack_size},
        {"system", cfg.system},
        {"keep_memory_on_free", cfg.keep_memory_on_free},
        {"current_dir", cfg.current_dir},
        {"command_line", cfg.command_line},
        {"domain", cfg.domain},
        {"hostname", cfg.hostname},
        {"os_ver", cfg.os_ver},
        {"user", {
            {"name", cfg.user.name},
            {"is_admin", cfg.user.is_admin},
            {"sid", cfg.user.sid}
        }},
        {"env", cfg.env},
        {"analysis", {
            {"memory_tracing", cfg.analysis.memory_tracing},
            {"strings", cfg.analysis.strings},
            {"coverage", cfg.analysis.coverage}
        }},
        {"exceptions", {
            {"dispatch_handlers", cfg.exceptions.dispatch_handlers}
        }},
        {"api_hammering", {
            {"enabled", cfg.api_hammering.enabled},
            {"threshold", cfg.api_hammering.threshold}
        }}
    };
    // Extended fields (symlinks, drives, filesystem, etc.) are
    // serialized as-needed by the report generator.
}

void from_json(const nlohmann::json& j, SpeakeasyConfig& cfg) {
    JSON_GET_OPTIONAL_INT(j, "config_version", cfg.config_version);
    JSON_GET_OPTIONAL_STRING(j, "description", cfg.description);
    JSON_GET_OPTIONAL_STRING(j, "emu_engine", cfg.emu_engine);
    JSON_GET_OPTIONAL_INT(j, "timeout", cfg.timeout);
    JSON_GET_OPTIONAL_INT(j, "max_api_count", cfg.max_api_count);
    JSON_GET_OPTIONAL_INT(j, "stack_size", cfg.stack_size);
    JSON_GET_OPTIONAL_STRING(j, "system", cfg.system);
    JSON_GET_OPTIONAL_BOOL(j, "keep_memory_on_free", cfg.keep_memory_on_free);
    JSON_GET_OPTIONAL_STRING(j, "current_dir", cfg.current_dir);
    JSON_GET_OPTIONAL_STRING(j, "command_line", cfg.command_line);
    JSON_GET_OPTIONAL_STRING(j, "domain", cfg.domain);
    JSON_GET_OPTIONAL_STRING(j, "hostname", cfg.hostname);

    if (j.contains("os_ver")) {
        j.at("os_ver").get_to(cfg.os_ver);
    }
    if (j.contains("user")) {
        auto& u = j.at("user");
        JSON_GET_OPTIONAL_STRING(u, "name", cfg.user.name);
        JSON_GET_OPTIONAL_BOOL(u, "is_admin", cfg.user.is_admin);
        JSON_GET_OPTIONAL_STRING(u, "sid", cfg.user.sid);
    }
    if (j.contains("env") && j.at("env").is_object()) {
        for (auto& [k, v] : j.at("env").items()) {
            cfg.env[k] = v.get<std::string>();
        }
    }
    if (j.contains("analysis")) {
        auto& a = j.at("analysis");
        JSON_GET_OPTIONAL_BOOL(a, "memory_tracing", cfg.analysis.memory_tracing);
        JSON_GET_OPTIONAL_BOOL(a, "strings", cfg.analysis.strings);
        JSON_GET_OPTIONAL_BOOL(a, "coverage", cfg.analysis.coverage);
    }
    if (j.contains("exceptions")) {
        auto& e = j.at("exceptions");
        JSON_GET_OPTIONAL_BOOL(e, "dispatch_handlers", cfg.exceptions.dispatch_handlers);
    }
    if (j.contains("api_hammering")) {
        auto& ah = j.at("api_hammering");
        JSON_GET_OPTIONAL_BOOL(ah, "enabled", cfg.api_hammering.enabled);
        JSON_GET_OPTIONAL_INT(ah, "threshold", cfg.api_hammering.threshold);
    }
}

// ── Validation ───────────────────────────────────────────────

void validate_config(const SpeakeasyConfig& cfg) {
    if (cfg.emu_engine != "unicorn") {
        throw ConfigError("Unsupported emulation engine: " + cfg.emu_engine);
    }
    if (cfg.timeout < 0) {
        throw ConfigError("Timeout must be >= 0");
    }
    if (cfg.max_api_count < 0) {
        throw ConfigError("max_api_count must be >= 0");
    }
    if (cfg.stack_size < 0) {
        throw ConfigError("stack_size must be >= 0");
    }
    if (cfg.system != "windows") {
        throw ConfigError("Unsupported system: " + cfg.system);
    }
    if (cfg.os_ver.name != "windows") {
        throw ConfigError("Unsupported OS name: " + cfg.os_ver.name);
    }
    if (cfg.config_version < 0) {
        throw ConfigError("config_version must be >= 0");
    }
}

// ── Config loading ───────────────────────────────────────────

SpeakeasyConfig load_config(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        throw ConfigError("Cannot open config file: " + path);
    }
    nlohmann::json j;
    ifs >> j;
    SpeakeasyConfig cfg;
    from_json(j, cfg);
    validate_config(cfg);
    return cfg;
}

SpeakeasyConfig default_config() {
    SpeakeasyConfig cfg;
    // cfg is already populated with defaults matching the Python DEFAULT_CONFIG_DATA
    return cfg;
}

} // namespace speakeasy
