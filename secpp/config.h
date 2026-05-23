// config.h — Emulation configuration
//
// Maps to: speakeasy/config.py
//
// Reads and validates the JSON configuration file that drives all
// aspects of emulation: OS version, filesystem, registry, network,
// processes, modules, and API hammering.

#ifndef SPEAKEASY_CONFIG_H
#define SPEAKEASY_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace speakeasy {

// ── Config sub-structures ────────────────────────────────────

struct OsVersion {
    std::string name = "windows";
    int major = 6;
    int minor = 1;
    int build = 7601;
};

struct UserInfo {
    std::string name = "speakeasy_user";
    bool is_admin = true;
    std::string sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
};

struct AnalysisConfig {
    bool memory_tracing = false;
    bool strings = true;
    bool coverage = false;
};

struct ExceptionsConfig {
    bool dispatch_handlers = true;
};

struct ApiHammeringConfig {
    bool enabled = false;
    int threshold = 2000;
    std::vector<std::string> allow_list;
};

struct SymlinkEntry {
    std::string name;
    std::string target;
};

struct DriveEntry {
    std::string root_path;
    std::string drive_type;
    std::string volume_guid_path;
};

struct FileEntry {
    std::string mode;        // "full_path" or "by_ext"
    std::string emu_path;
    std::string path;        // host path or $ROOT$/... path
    std::string ext;         // used when mode == "by_ext"
    struct {
        std::string byte_val = "0x41";
        int size = 0;
    } byte_fill;
};

struct FilesystemConfig {
    std::vector<FileEntry> files;
};

struct RegistryValue {
    std::string name;
    std::string type;  // REG_SZ, REG_DWORD, etc.
    std::string data;
};

struct RegistryKey {
    std::string path;
    std::vector<RegistryValue> values;
};

struct RegistryConfig {
    std::vector<RegistryKey> keys;
};

struct DnsNameEntry {
    std::string name;
    std::string ip;
};

struct DnsTxtEntry {
    std::string name;
    std::string path;
};

struct DnsConfig {
    std::vector<DnsNameEntry> names;
    std::vector<DnsTxtEntry> txt;
};

struct HttpResponseFile {
    std::string mode;
    std::string path;
    std::string ext;
};

struct HttpResponse {
    std::string verb;
    std::vector<HttpResponseFile> files;
};

struct HttpConfig {
    std::vector<HttpResponse> responses;
};

struct WinsockConfig {
    std::vector<std::map<std::string, std::string>> responses;
};

struct AdapterEntry {
    std::string name;
    std::string description;
    std::string mac_address;
    std::string type;
    std::string ip_address;
    std::string subnet_mask;
    bool dhcp_enabled = false;
};

struct NetworkConfig {
    DnsConfig dns;
    HttpConfig http;
    WinsockConfig winsock;
    std::vector<AdapterEntry> adapters;
};

struct ProcessEntry {
    std::string name;
    std::string base;
    int pid = 0;
    std::string path;
    std::string command_line;
    bool is_main_exe = false;
    int session = 0;
};

struct DriverInfo {
    std::string name;
    std::vector<std::map<std::string, std::string>> devices;
};

struct Module {
    std::string name;
    uint64_t base;
    size_t image_size;
    std::string path;
    virtual ~Module() = default;
};

struct SystemModule : public Module {
    DriverInfo driver;  // optional
};

struct UserModule : public Module {
};

struct ModulesConfig {
    bool modules_always_exist = false;
    bool functions_always_exist = false;
    std::string module_directory_x86;
    std::string module_directory_x64;
    std::vector<std::shared_ptr<Module>> system_modules;
    std::vector<std::shared_ptr<Module>> user_modules;
};

// ── Top-level config ────────────────────────────────────────

struct SpeakeasyConfig {
    double config_version = 0.2;
    std::string description;
    std::string emu_engine = "unicorn";
    int timeout = 60;
    int max_api_count = 10000;
    int stack_size = 0;
    std::string system = "windows";

    AnalysisConfig analysis;
    bool keep_memory_on_free = false;
    bool snapshot_memory_regions = false;
    ExceptionsConfig exceptions;
    OsVersion os_ver;
    std::string current_dir = "C:\\Windows\\system32";
    std::string command_line = "svchost.exe myarg1 myarg2";
    std::map<std::string, std::string> env;
    std::string domain = "speakeasy_domain";
    std::string hostname = "speakeasy_host";
    UserInfo user;
    ApiHammeringConfig api_hammering;

    std::vector<SymlinkEntry> symlinks;
    std::vector<DriveEntry> drives;
    FilesystemConfig filesystem;
    RegistryConfig registry;
    NetworkConfig network;
    std::vector<ProcessEntry> processes;
    ModulesConfig modules;

    SpeakeasyConfig();

    // ── Validation ───────────────────────────────────────────────

    /**
     * Validate an emulation configuration and throw on invalid values.
     */
    void validate_config() const;

    /**
     * Load and validate configuration from a JSON file path.
     * Throws std::runtime_error on invalid or missing config.
     */
    bool load_config(const std::string& path);

private:
    bool load_config_from_json(const nlohmann::json& j);

    friend void from_json(const nlohmann::json& j, SpeakeasyConfig& cfg);
};

// ── Serialization (nlohmann_json) ───────────────────────────

void to_json(nlohmann::json& j, const OsVersion& v);
void from_json(const nlohmann::json& j, OsVersion& v);

void to_json(nlohmann::json& j, const SpeakeasyConfig& cfg);
void from_json(const nlohmann::json& j, SpeakeasyConfig& cfg);


} // namespace speakeasy

#endif // SPEAKEASY_CONFIG_H
