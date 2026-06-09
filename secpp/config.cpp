// config.cpp  Emulation configuration implementation
//
// Maps to: speakeasy/config.py

#include "config.h"
#include "errors.h"
#include "struct.h"
#include <fstream>
#include <stdexcept>
#include <iostream>

namespace speakeasy {

static constexpr const char DEFAULT_CONFIG_DATA[] = R"CFG({
  "config_version": 0.2,
  "description": "Default emulation profile to use when not overridden by user",
  "emu_engine": "unicorn",
  "timeout": 60,
  "max_api_count": 10000,
  "max_instructions": -1,
  "stack_size": 0,
  "system": "windows",
  "analysis": {"memory_tracing": false, "strings": true, "coverage": false},
  "keep_memory_on_free": false,
  "exceptions": {"dispatch_handlers": true},
  "os_ver": {"name": "windows", "major": 6, "minor": 1, "build": 7601},
  "current_dir": "C:\\Windows\\system32",
  "command_line": "svchost.exe myarg1 myarg2",
  "env": {
    "comspec": "C:\\Windows\\system32\\cmd.exe",
    "systemroot": "C:\\Windows",
    "windir": "C:\\Windows",
    "temp": "C:\\Windows\\temp\\",
    "userprofile": "C:\\Users\\speakeasy_user",
    "systemdrive": "C:",
    "allusersprofile": "C:\\ProgramData",
    "programfiles": "C:\\Program Files"
  },
  "domain": "speakeasy_domain",
  "hostname": "speakeasy_host",
  "user": {"name": "speakeasy_user", "is_admin": true, "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001"},
  "api_hammering": {"enabled": false, "threshold": 2000},
  "symlinks": [
    {"name": "\\??\\C:", "target": "\\Device\\HarddiskVolume1"},
    {"name": "\\??\\PhysicalDrive0", "target": "\\Device\\Harddisk0\\DR0"}
  ],
  "drives": [
    {"root_path": "C:\\", "drive_type": "DRIVE_FIXED", "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000001}\\"},
    {"root_path": "D:\\", "drive_type": "DRIVE_CDROM", "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000002}\\"},
    {"root_path": "E:\\", "drive_type": "DRIVE_REMOTE", "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000003}\\"},
    {"root_path": "F:\\", "drive_type": "DRIVE_REMOVABLE", "volume_guid_path": "\\\\?\\Volume{bb1d6623-5e53-11ea-a949-100000000004}\\"}
  ],
  "filesystem": {
    "files": [
      {"mode": "full_path", "emu_path": "c:\\programdata\\mydir\\myfile.bin", "byte_fill": {"byte": "0x41", "size": 512}},
      {"mode": "full_path", "emu_path": "c:\\Windows\\system32\\cmd.exe", "path": "$ROOT$/resources/files/default.bin"},
      {"mode": "full_path", "emu_path": "c:\\Windows\\system32\\svchost.exe", "path": "$ROOT$/resources/files/default.bin"},
      {"mode": "by_ext", "ext": "exe", "path": "$ROOT$/resources/files/default.bin"},
      {"mode": "by_ext", "ext": "txt", "path": "$ROOT$/resources/files/default.bin"},
      {"mode": "full_path", "emu_path": "\\\\.\\pipe*", "path": "$ROOT$/resources/web/stager.bin"}
    ]
  },
  "registry": {
    "keys": [
      {"path": "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\usbsamp", "values": [{"name": "DisplayName", "type": "REG_SZ", "data": "An example service"}, {"name": "Start", "type": "REG_DWORD", "data": "0x00000003"}]},
      {"path": "HKEY_CLASSES_ROOT\\Interface\\{b196b287-bab4-101a-b69c-00aa00341d07}", "values": [{"name": "default", "type": "REG_SZ", "data": "IEnumConnections"}]},
      {"path": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "values": [{"name": "default", "type": "REG_SZ", "data": "IEnumConnections"}]},
      {"path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "values": []}
    ]
  },
  "network": {
    "dns": {
      "names": {"speakeasy_host": "127.0.0.1", "default": "10.1.2.3", "google.com": "8.8.8.8", "localhost": "127.0.0.1"},
      "txt": [{"name": "default", "path": "$ROOT$/resources/web/default.bin"}]
    },
    "http": {"responses": [{"verb": "GET", "files": [{"mode": "default", "path": "$ROOT$/resources/web/default.bin"}, {"mode": "by_ext", "ext": "gif", "path": "$ROOT$/resources/web/decoy.gif"}, {"mode": "by_ext", "ext": "jpg", "path": "$ROOT$/resources/web/decoy.jpg"}]}]},
    "winsock": {"responses": [{"mode": "default", "path": "$ROOT$/resources/web/stager.bin"}]},
    "adapters": [{"name": "{00000000-0000-0000-0000-000000000000}", "description": "Intel(R) PRO/1000 MT Network Connection", "mac_address": "00-13-CE-12-34-56", "type": "ethernet", "ip_address": "127.0.0.1", "subnet_mask": "255.0.0.0", "dhcp_enabled": true}]
  },
  "processes": [
    {"name": "System", "base_addr": "0x80000000", "pid": 4, "path": "[System Process]"},
    {"name": "smss", "base_addr": "0x05000000", "path": "C:\\Windows\\system32\\smss.exe"},
    {"name": "csrss", "base_addr": "0x05510000", "path": "C:\\Windows\\system32\\csrss.exe"},
    {"name": "wininit", "base_addr": "0x05520000", "path": "C:\\Windows\\system32\\wininit.exe"},
    {"name": "services", "base_addr": "0x05530000", "path": "C:\\Windows\\system32\\services.exe"},
    {"name": "lsass", "base_addr": "0x05540000", "path": "C:\\Windows\\system32\\lsass.exe"},
    {"name": "winlogon", "base_addr": "0x05550000", "path": "C:\\Windows\\system32\\winlogon.exe"},
    {"name": "svchost", "base_addr": "0x05560000", "path": "C:\\Windows\\system32\\svchost.exe"},
    {"name": "outlook", "base_addr": "0x05590000", "path": "C:\\Windows\\system32\\outlook.exe"},
    {"name": "explorer", "base_addr": "0x05570000", "path": "C:\\Windows\\explorer.exe"},
    {"name": "main", "base_addr": "0x00400000", "path": "C:\\Windows\\system32\\svchost.exe", "command_line": "svchost.exe", "is_main_exe": true, "session": 1}
  ],
  "modules": {
    "modules_always_exist": false,
    "functions_always_exist": false,
    "module_directory_x86": "$ROOT$/winenv/decoys/x86",
    "module_directory_x64": "$ROOT$/winenv/decoys/amd64",
    "system_modules": [
      {"name": "ntoskrnl", "base_addr": "0x803d0000", "path": "C:\\Windows\\system32\\ntoskrnl.exe"},
      {"name": "hal", "base_addr": "0xC1000000", "path": "C:\\Windows\\system32\\hal.dll"},
      {"name": "ntfs", "base_addr": "0xC2000000", "path": "C:\\Windows\\system32\\drivers\\ntfs.sys"},
      {"name": "netio", "base_addr": "0xD4000000", "path": "C:\\Windows\\system32\\drivers\\netio.sys"},
      {"name": "volmgr", "base_addr": "0xC6000000", "path": "C:\\Windows\\system32\\drivers\\volmgr.sys", "driver": {"name": "\\Driver\\volmgr", "devices": [{"name": "\\Device\\HarddiskVolume1"}]}},
      {"name": "disk", "base_addr": "0xC3000000", "path": "C:\\Windows\\system32\\drivers\\disk.sys", "driver": {"name": "\\Driver\\Disk", "devices": [{"name": "\\Device\\Harddisk0\\DR0"}]}},
      {"name": "tcpip", "base_addr": "0xC4000000", "path": "C:\\Windows\\system32\\drivers\\tcpip.sys", "driver": {"name": "\\Driver\\Tcpip", "devices": [{"name": "\\Device\\Tcp"}]}},
      {"name": "ndis", "base_addr": "0xC7000000", "path": "C:\\Windows\\system32\\drivers\\ndis.sys", "driver": {"name": "\\Driver\\Ndis", "devices": [{"name": "\\Device\\Ndis"}]}}
    ],
    "user_modules": [
      {"name": "ntdll", "base_addr": "0x7C000000", "path": "C:\\Windows\\system32\\ntdll.dll"},
      {"name": "kernel32", "base_addr": "0x77000000", "path": "C:\\Windows\\system32\\kernel32.dll"},
      {"name": "ws2_32", "base_addr": "0x78C00000", "path": "C:\\Windows\\system32\\ws2_32.dll"},
      {"name": "wininet", "base_addr": "0x7BC00000", "path": "C:\\Windows\\system32\\wininet.dll"},
      {"name": "winhttp", "base_addr": "0x7BA00000", "path": "C:\\Windows\\system32\\winhttp.dll"},
      {"name": "advapi32", "base_addr": "0x78000000", "path": "C:\\Windows\\system32\\advapi32.dll"},
      {"name": "psapi", "base_addr": "0x71000000", "path": "C:\\Windows\\system32\\psapi.dll"},
      {"name": "user32", "base_addr": "0x77D10000", "path": "C:\\Windows\\system32\\user32.dll"},
      {"name": "gdi32", "base_addr": "0x77E10000", "path": "C:\\Windows\\system32\\gdi32.dll"},
      {"name": "msvcrt", "base_addr": "0x77F10000", "path": "C:\\Windows\\system32\\msvcrt.dll"},
      {"name": "dnsapi", "base_addr": "0x78F10000", "path": "C:\\Windows\\system32\\dnsapi.dll"},
      {"name": "shlwapi", "base_addr": "0x67000000", "path": "C:\\Windows\\system32\\shlwapi.dll"},
      {"name": "advpack", "base_addr": "0x68F00000", "path": "C:\\Windows\\system32\\advpack.dll"},
      {"name": "dbghelp", "base_addr": "0x62000000", "path": "C:\\Windows\\system32\\dbghelp.dll"},
      {"name": "shell32", "base_addr": "0x69000000", "path": "C:\\Windows\\system32\\shell32.dll"},
      {"name": "WTSAPI32", "base_addr": "0x63000000", "path": "C:\\Windows\\system32\\WTSAPI32.dll"},
      {"name": "CRYPT32", "base_addr": "0x58000000", "path": "C:\\Windows\\system32\\CRYPT32.dll"},
      {"name": "mscoree", "base_addr": "0x53000000", "path": "C:\\Windows\\system32\\mscoree.dll"},
      {"name": "urlmon", "base_addr": "0x54500000", "path": "C:\\Windows\\system32\\urlmon.dll"},
      {"name": "riched32", "base_addr": "0x56500000", "path": "C:\\Windows\\system32\\riched32.dll"},
      {"name": "userenv", "base_addr": "0x76500000", "path": "C:\\Windows\\system32\\userenv.dll"},
      {"name": "ole32", "base_addr": "0x65500000", "path": "C:\\Windows\\system32\\ole32.dll"},
      {"name": "gdiplus", "base_addr": "0x75500000", "path": "C:\\Windows\\system32\\gdiplus.dll"},
      {"name": "setupapi", "base_addr": "0x55500000", "path": "C:\\Windows\\system32\\setupapi.dll"},
      {"name": "NETAPI32", "base_addr": "0x54400000", "path": "C:\\Windows\\system32\\NETAPI32.dll"},
      {"name": "rpcrt4", "base_addr": "0x53300000", "path": "C:\\Windows\\system32\\Rpcrt4.dll"},
      {"name": "linkinfo", "base_addr": "0x63300000", "path": "C:\\Windows\\system32\\linkinfo.dll"},
      {"name": "EhStorShell", "base_addr": "0x73300000", "path": "C:\\Windows\\system32\\EhStorShell.dll"},
      {"name": "comctl32", "base_addr": "0x5f500000", "path": "C:\\Windows\\system32\\comctl32.dll"},
      {"name": "secur32", "base_addr": "0x5f600000", "path": "C:\\Windows\\system32\\secur32.dll"},
      {"name": "KtmW32", "base_addr": "0x5f700000", "path": "C:\\Windows\\system32\\KtmW32.dll"},
      {"name": "oleaut32", "base_addr": "0x5f800000", "path": "C:\\Windows\\system32\\oleaut32.dll"},
      {"name": "bcrypt", "base_addr": "0x5f900000", "path": "C:\\Windows\\system32\\bcrypt.dll"},
      {"name": "ncrypt", "base_addr": "0x5fa00000", "path": "C:\\Windows\\system32\\ncrypt.dll"},
      {"name": "netutils", "base_addr": "0x5fb00000", "path": "C:\\Windows\\system32\\netutils.dll"},
      {"name": "wkscli", "base_addr": "0x5fc00000", "path": "C:\\Windows\\system32\\wkscli.dll"},
      {"name": "iphlpapi", "base_addr": "0x5fd00000", "path": "C:\\Windows\\system32\\iphlpapi.dll"},
      {"name": "sfc_os", "base_addr": "0x5fe00000", "path": "C:\\Windows\\system32\\sfc_os.dll"},
      {"name": "winmm", "base_addr": "0x5ff00000", "path": "C:\\Windows\\system32\\winmm.dll"},
      {"name": "bcryptprimitives", "base_addr": "0x60000000", "path": "C:\\Windows\\system32\\bcryptprimitives.dll"}
    ]
  }
})CFG";

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

SpeakeasyConfig::SpeakeasyConfig() {
    nlohmann::json j = nlohmann::json::parse(DEFAULT_CONFIG_DATA);
    load_config_from_json(j);
}

//  Macro helpers for struct serialization 
#define JSON_GET_OPTIONAL_STRING(j, key, field) \
    if (j.contains(key)) j.at(key).get_to(field);

#define JSON_GET_OPTIONAL_INT(j, key, field) \
    if (j.contains(key)) field = j.at(key).get<int>();

#define JSON_GET_OPTIONAL_BOOL(j, key, field) \
    if (j.contains(key)) field = j.at(key).get<bool>();

//  Validation 

void SpeakeasyConfig::validate_config() const {
    if (emu_engine != "unicorn") {
        throw ConfigError("Unsupported emulation engine: " + emu_engine);
    }
    if (timeout < 0) {
        throw ConfigError("Timeout must be >= 0");
    }
    if (max_api_count < 0) {
        throw ConfigError("max_api_count must be >= 0");
    }
    if (stack_size < 0) {
        throw ConfigError("stack_size must be >= 0");
    }
    if (system != "windows") {
        throw ConfigError("Unsupported system: " + system);
    }
    if (os_ver.name != "windows") {
        throw ConfigError("Unsupported OS name: " + os_ver.name);
    }
    if (config_version < 0) {
        throw ConfigError("config_version must be >= 0");
    }
}

//  Config loading 

bool SpeakeasyConfig::load_config(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        throw ConfigError("Cannot open config file: " + path);
    }
    nlohmann::json j;
    ifs >> j;

    return load_config_from_json(j);
}

bool SpeakeasyConfig::load_config_from_json(const nlohmann::json& j) {
    if (j.contains("config_version")) config_version = j.at("config_version").get<double>();
    if (j.contains("description")) description = j.at("description").get<std::string>();
    if (j.contains("emu_engine")) emu_engine = j.at("emu_engine").get<std::string>();
    if (j.contains("timeout")) timeout = j.at("timeout").get<int>();
    if (j.contains("max_api_count")) max_api_count = j.at("max_api_count").get<int>();
    if (j.contains("max_instructions")) max_instructions = j.at("max_instructions").get<int>();
    if (j.contains("stack_size")) stack_size = j.at("stack_size").get<int>();
    if (j.contains("system")) system = j.at("system").get<std::string>();
    if (j.contains("keep_memory_on_free")) keep_memory_on_free = j.at("keep_memory_on_free").get<bool>();
    if (j.contains("snapshot_memory_regions")) snapshot_memory_regions = j.at("snapshot_memory_regions").get<bool>();
    if (j.contains("current_dir")) current_dir = j.at("current_dir").get<std::string>();
    if (j.contains("command_line")) command_line = j.at("command_line").get<std::string>();
    if (j.contains("domain")) domain = j.at("domain").get<std::string>();
    if (j.contains("hostname")) hostname = j.at("hostname").get<std::string>();

    if (j.contains("os_ver")) {
        j.at("os_ver").get_to(os_ver);
    }

    if (j.contains("user")) {
        auto& u = j.at("user");
        if (u.contains("name")) u.at("name").get_to(user.name);
        if (u.contains("is_admin")) u.at("is_admin").get_to(user.is_admin);
        if (u.contains("sid")) u.at("sid").get_to(user.sid);
    }

    if (j.contains("env") && j.at("env").is_object()) {
        for (auto& [k, v] : j.at("env").items()) {
            env[k] = v.get<std::string>();
        }
    }

    if (j.contains("analysis")) {
        auto& a = j.at("analysis");
        if (a.contains("memory_tracing")) a.at("memory_tracing").get_to(analysis.memory_tracing);
        if (a.contains("strings")) a.at("strings").get_to(analysis.strings);
        if (a.contains("coverage")) a.at("coverage").get_to(analysis.coverage);
    }

    if (j.contains("exceptions")) {
        auto& e = j.at("exceptions");
        if (e.contains("dispatch_handlers")) e.at("dispatch_handlers").get_to(exceptions.dispatch_handlers);
    }

    if (j.contains("api_hammering")) {
        auto& ah = j.at("api_hammering");
        if (ah.contains("enabled")) ah.at("enabled").get_to(api_hammering.enabled);
        if (ah.contains("threshold")) ah.at("threshold").get_to(api_hammering.threshold);
        if (ah.contains("allow_list")) {
            for (auto& item : ah.at("allow_list")) {
                api_hammering.allow_list.push_back(item.get<std::string>());
            }
        }
    }

    if (j.contains("symlinks") && j.at("symlinks").is_array()) {
        for (auto& item : j.at("symlinks")) {
            SymlinkEntry entry;
            if (item.contains("name")) item.at("name").get_to(entry.name);
            if (item.contains("target")) item.at("target").get_to(entry.target);
            symlinks.push_back(entry);
        }
    }

    if (j.contains("drives") && j.at("drives").is_array()) {
        for (auto& item : j.at("drives")) {
            DriveEntry entry;
            if (item.contains("root_path")) item.at("root_path").get_to(entry.root_path);
            if (item.contains("drive_type")) item.at("drive_type").get_to(entry.drive_type);
            if (item.contains("volume_guid_path")) item.at("volume_guid_path").get_to(entry.volume_guid_path);
            drives.push_back(entry);
        }
    }

    if (j.contains("filesystem")) {
        auto& fs = j.at("filesystem");
        if (fs.contains("files") && fs.at("files").is_array()) {
            for (auto& item : fs.at("files")) {
                FileEntry entry;
                if (item.contains("mode")) item.at("mode").get_to(entry.mode);
                if (item.contains("emu_path")) item.at("emu_path").get_to(entry.emu_path);
                if (item.contains("path")) item.at("path").get_to(entry.path);
                if (item.contains("ext")) item.at("ext").get_to(entry.ext);
                if (item.contains("byte_fill")) {
                    auto& bf = item.at("byte_fill");
                    if (bf.contains("byte")) bf.at("byte").get_to(entry.byte_fill.byte_val);
                    if (bf.contains("size")) bf.at("size").get_to(entry.byte_fill.size);
                }
                filesystem.files.push_back(entry);
            }
        }
    }

    if (j.contains("registry")) {
        auto& reg = j.at("registry");
        if (reg.contains("keys") && reg.at("keys").is_array()) {
            for (auto& key_item : reg.at("keys")) {
                RegistryKey reg_key;
                if (key_item.contains("path")) key_item.at("path").get_to(reg_key.path);
                if (key_item.contains("values") && key_item.at("values").is_array()) {
                    for (auto& val_item : key_item.at("values")) {
                        RegistryValue reg_val;
                        if (val_item.contains("name")) val_item.at("name").get_to(reg_val.name);
                        if (val_item.contains("type")) val_item.at("type").get_to(reg_val.type);
                        if (val_item.contains("data")) val_item.at("data").get_to(reg_val.data);
                        reg_key.values.push_back(reg_val);
                    }
                }
                registry.keys.push_back(reg_key);
            }
        }
    }

    if (j.contains("network")) {
        auto& net = j.at("network");
        if (net.contains("dns")) {
            auto& dns_cfg = net.at("dns");
            if (dns_cfg.contains("names") && dns_cfg.at("names").is_object()) {
                for (auto& [name_key, val] : dns_cfg.at("names").items()) {
                    DnsNameEntry dns_entry;
                    dns_entry.name = name_key;
                    dns_entry.ip = val.get<std::string>();
                    network.dns.names.push_back(dns_entry);
                }
            }
            if (dns_cfg.contains("txt") && dns_cfg.at("txt").is_array()) {
                for (auto& txt_item : dns_cfg.at("txt")) {
                    DnsTxtEntry txt_entry;
                    if (txt_item.contains("name")) txt_item.at("name").get_to(txt_entry.name);
                    if (txt_item.contains("path")) txt_item.at("path").get_to(txt_entry.path);
                    network.dns.txt.push_back(txt_entry);
                }
            }
        }
        if (net.contains("http")) {
            auto& http_cfg = net.at("http");
            if (http_cfg.contains("responses") && http_cfg.at("responses").is_array()) {
                for (auto& resp_item : http_cfg.at("responses")) {
                    HttpResponse resp;
                    if (resp_item.contains("verb")) resp_item.at("verb").get_to(resp.verb);
                    if (resp_item.contains("files") && resp_item.at("files").is_array()) {
                        for (auto& file_item : resp_item.at("files")) {
                            HttpResponseFile resp_file;
                            if (file_item.contains("mode")) file_item.at("mode").get_to(resp_file.mode);
                            if (file_item.contains("path")) file_item.at("path").get_to(resp_file.path);
                            if (file_item.contains("ext")) file_item.at("ext").get_to(resp_file.ext);
                            resp.files.push_back(resp_file);
                        }
                    }
                    network.http.responses.push_back(resp);
                }
            }
        }
        if (net.contains("winsock")) {
            auto& ws_cfg = net.at("winsock");
            if (ws_cfg.contains("responses") && ws_cfg.at("responses").is_array()) {
                for (auto& resp_item : ws_cfg.at("responses")) {
                    std::map<std::string, std::string> ws_resp;
                    for (auto& [k, v] : resp_item.items()) {
                        ws_resp[k] = v.get<std::string>();
                    }
                    network.winsock.responses.push_back(ws_resp);
                }
            }
        }
        if (net.contains("adapters") && net.at("adapters").is_array()) {
            for (auto& ad_item : net.at("adapters")) {
                AdapterEntry ad_entry;
                if (ad_item.contains("name")) ad_item.at("name").get_to(ad_entry.name);
                if (ad_item.contains("description")) ad_item.at("description").get_to(ad_entry.description);
                if (ad_item.contains("mac_address")) ad_item.at("mac_address").get_to(ad_entry.mac_address);
                if (ad_item.contains("type")) ad_item.at("type").get_to(ad_entry.type);
                if (ad_item.contains("ip_address")) ad_item.at("ip_address").get_to(ad_entry.ip_address);
                if (ad_item.contains("subnet_mask")) ad_item.at("subnet_mask").get_to(ad_entry.subnet_mask);
                if (ad_item.contains("dhcp_enabled")) ad_item.at("dhcp_enabled").get_to(ad_entry.dhcp_enabled);
                network.adapters.push_back(ad_entry);
            }
        }
    }

    if (j.contains("processes") && j.at("processes").is_array()) {
        for (auto& proc_item : j.at("processes")) {
            ProcessEntry entry;
            if (proc_item.contains("name")) proc_item.at("name").get_to(entry.name);
            if (proc_item.contains("base_addr")) proc_item.at("base_addr").get_to(entry.base);
            if (proc_item.contains("pid")) proc_item.at("pid").get_to(entry.pid);
            if (proc_item.contains("path")) proc_item.at("path").get_to(entry.path);
            if (proc_item.contains("command_line")) proc_item.at("command_line").get_to(entry.command_line);
            if (proc_item.contains("is_main_exe")) proc_item.at("is_main_exe").get_to(entry.is_main_exe);
            if (proc_item.contains("session")) proc_item.at("session").get_to(entry.session);
            processes.push_back(entry);
        }
    }

    if (j.contains("modules")) {
        auto& mods = j.at("modules");
        if (mods.contains("modules_always_exist")) mods.at("modules_always_exist").get_to(modules.modules_always_exist);
        if (mods.contains("functions_always_exist")) mods.at("functions_always_exist").get_to(modules.functions_always_exist);
        if (mods.contains("module_directory_x86")) mods.at("module_directory_x86").get_to(modules.module_directory_x86);
        if (mods.contains("module_directory_x64")) mods.at("module_directory_x64").get_to(modules.module_directory_x64);

        if (mods.contains("system_modules") && mods.at("system_modules").is_array()) {
            for (auto& sys_mod_item : mods.at("system_modules")) {
                auto sys_mod = std::make_shared<SystemModule>();
                if (sys_mod_item.contains("name")) sys_mod_item.at("name").get_to(sys_mod->name);
                if (sys_mod_item.contains("base_addr")) {
                    std::string base_str = sys_mod_item.at("base_addr").get<std::string>();
                    sys_mod->base = std::stoull(base_str, nullptr, 16);
                }
                sys_mod->image_size = 0;
                if (sys_mod_item.contains("path")) sys_mod_item.at("path").get_to(sys_mod->path);
                if (sys_mod_item.contains("driver")) {
                    auto& drv = sys_mod_item.at("driver");
                    if (drv.contains("name")) drv.at("name").get_to(sys_mod->driver.name);
                    if (drv.contains("devices") && drv.at("devices").is_array()) {
                        for (auto& dev_item : drv.at("devices")) {
                            std::map<std::string, std::string> dev;
                            for (auto& [k, v] : dev_item.items()) {
                                dev[k] = v.get<std::string>();
                            }
                            sys_mod->driver.devices.push_back(dev);
                        }
                    }
                }
                modules.system_modules.push_back(sys_mod);
            }
        }

        if (mods.contains("user_modules") && mods.at("user_modules").is_array()) {
            for (auto& usr_mod_item : mods.at("user_modules")) {
                auto usr_mod = std::make_shared<UserModule>();
                if (usr_mod_item.contains("name")) usr_mod_item.at("name").get_to(usr_mod->name);
                if (usr_mod_item.contains("base_addr")) {
                    std::string base_str = usr_mod_item.at("base_addr").get<std::string>();
                    usr_mod->base = std::stoull(base_str, nullptr, 16);
                }
                usr_mod->image_size = 0;
                if (usr_mod_item.contains("path")) usr_mod_item.at("path").get_to(usr_mod->path);
                modules.user_modules.push_back(usr_mod);
            }
        }
    }

    return true;
}

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
        {"snapshot_memory_regions", cfg.snapshot_memory_regions},
        {"current_dir", cfg.current_dir},
        {"command_line", cfg.command_line},
        {"domain", cfg.domain},
        {"hostname", cfg.hostname},
        {"env", cfg.env}
    };

    // os_ver
    nlohmann::json os_j;
    to_json(os_j, cfg.os_ver);
    j["os_ver"] = os_j;

    // user
    j["user"] = nlohmann::json{
        {"name", cfg.user.name},
        {"is_admin", cfg.user.is_admin},
        {"sid", cfg.user.sid}
    };

    // analysis
    j["analysis"] = nlohmann::json{
        {"memory_tracing", cfg.analysis.memory_tracing},
        {"strings", cfg.analysis.strings},
        {"coverage", cfg.analysis.coverage}
    };

    // exceptions
    j["exceptions"] = nlohmann::json{
        {"dispatch_handlers", cfg.exceptions.dispatch_handlers}
    };

    // api_hammering
    j["api_hammering"] = nlohmann::json{
        {"enabled", cfg.api_hammering.enabled},
        {"threshold", cfg.api_hammering.threshold},
        {"allow_list", cfg.api_hammering.allow_list}
    };

    // symlinks
    nlohmann::json syms = nlohmann::json::array();
    for (const auto& sym : cfg.symlinks) {
        syms.push_back(nlohmann::json{{"name", sym.name}, {"target", sym.target}});
    }
    j["symlinks"] = syms;

    // drives
    nlohmann::json drvs = nlohmann::json::array();
    for (const auto& drv : cfg.drives) {
        drvs.push_back(nlohmann::json{
            {"root_path", drv.root_path},
            {"drive_type", drv.drive_type},
            {"volume_guid_path", drv.volume_guid_path}
        });
    }
    j["drives"] = drvs;

    // filesystem
    nlohmann::json files = nlohmann::json::array();
    for (const auto& f : cfg.filesystem.files) {
        nlohmann::json f_j = nlohmann::json{
            {"mode", f.mode},
            {"emu_path", f.emu_path},
            {"path", f.path},
            {"ext", f.ext}
        };
        if (f.byte_fill.size > 0) {
            f_j["byte_fill"] = nlohmann::json{
                {"byte", f.byte_fill.byte_val},
                {"size", f.byte_fill.size}
            };
        }
        files.push_back(f_j);
    }
    j["filesystem"] = nlohmann::json{{"files", files}};

    // registry
    nlohmann::json keys = nlohmann::json::array();
    for (const auto& key : cfg.registry.keys) {
        nlohmann::json vals = nlohmann::json::array();
        for (const auto& val : key.values) {
            vals.push_back(nlohmann::json{
                {"name", val.name},
                {"type", val.type},
                {"data", val.data}
            });
        }
        keys.push_back(nlohmann::json{
            {"path", key.path},
            {"values", vals}
        });
    }
    j["registry"] = nlohmann::json{{"keys", keys}};

    // network
    nlohmann::json dns_names = nlohmann::json::object();
    for (const auto& entry : cfg.network.dns.names) {
        dns_names[entry.name] = entry.ip;
    }
    nlohmann::json dns_txt = nlohmann::json::array();
    for (const auto& entry : cfg.network.dns.txt) {
        dns_txt.push_back(nlohmann::json{{"name", entry.name}, {"path", entry.path}});
    }

    nlohmann::json http_resps = nlohmann::json::array();
    for (const auto& resp : cfg.network.http.responses) {
        nlohmann::json resp_files = nlohmann::json::array();
        for (const auto& f : resp.files) {
            resp_files.push_back(nlohmann::json{
                {"mode", f.mode},
                {"path", f.path},
                {"ext", f.ext}
            });
        }
        http_resps.push_back(nlohmann::json{
            {"verb", resp.verb},
            {"files", resp_files}
        });
    }

    nlohmann::json ws_resps = nlohmann::json::array();
    for (const auto& resp : cfg.network.winsock.responses) {
        nlohmann::json resp_j = nlohmann::json::object();
        for (const auto& [k, v] : resp) {
            resp_j[k] = v;
        }
        ws_resps.push_back(resp_j);
    }

    nlohmann::json adapters = nlohmann::json::array();
    for (const auto& ad : cfg.network.adapters) {
        adapters.push_back(nlohmann::json{
            {"name", ad.name},
            {"description", ad.description},
            {"mac_address", ad.mac_address},
            {"type", ad.type},
            {"ip_address", ad.ip_address},
            {"subnet_mask", ad.subnet_mask},
            {"dhcp_enabled", ad.dhcp_enabled}
        });
    }

    j["network"] = nlohmann::json{
        {"dns", nlohmann::json{{"names", dns_names}, {"txt", dns_txt}}},
        {"http", nlohmann::json{{"responses", http_resps}}},
        {"winsock", nlohmann::json{{"responses", ws_resps}}},
        {"adapters", adapters}
    };

    // processes
    nlohmann::json procs = nlohmann::json::array();
    for (const auto& proc : cfg.processes) {
        procs.push_back(nlohmann::json{
            {"name", proc.name},
            {"base_addr", proc.base},
            {"pid", proc.pid},
            {"path", proc.path},
            {"command_line", proc.command_line},
            {"is_main_exe", proc.is_main_exe},
            {"session", proc.session}
        });
    }
    j["processes"] = procs;

    // modules
    nlohmann::json sys_mods = nlohmann::json::array();
    for (const auto& mod : cfg.modules.system_modules) {
        nlohmann::json mod_j = nlohmann::json{
            {"name", mod->name},
            {"base_addr", hex_str(mod->base)},
            {"path", mod->path}
        };
        auto sys_mod = std::dynamic_pointer_cast<SystemModule>(mod);
        if (sys_mod && !sys_mod->driver.name.empty()) {
            nlohmann::json devs = nlohmann::json::array();
            for (const auto& dev : sys_mod->driver.devices) {
                nlohmann::json dev_j = nlohmann::json::object();
                for (const auto& [k, v] : dev) {
                    dev_j[k] = v;
                }
                devs.push_back(dev_j);
            }
            mod_j["driver"] = nlohmann::json{
                {"name", sys_mod->driver.name},
                {"devices", devs}
            };
        }
        sys_mods.push_back(mod_j);
    }

    nlohmann::json usr_mods = nlohmann::json::array();
    for (const auto& mod : cfg.modules.user_modules) {
        usr_mods.push_back(nlohmann::json{
            {"name", mod->name},
            {"base_addr", hex_str(mod->base)},
            {"path", mod->path}
        });
    }

    j["modules"] = nlohmann::json{
        {"modules_always_exist", cfg.modules.modules_always_exist},
        {"functions_always_exist", cfg.modules.functions_always_exist},
        {"module_directory_x86", cfg.modules.module_directory_x86},
        {"module_directory_x64", cfg.modules.module_directory_x64},
        {"system_modules", sys_mods},
        {"user_modules", usr_mods}
    };
}

void from_json(const nlohmann::json& j, SpeakeasyConfig& cfg) {
    cfg.load_config_from_json(j);
}


} // namespace speakeasy
