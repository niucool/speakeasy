// pma_profiles.h -- C++ port of tests/pma_profiles.py
// Profile functions that customize SpeakeasyConfig and CaseRuntime per PMA case.

#pragma once

#include <fstream>

#include "pma_harness.h"
#include "config.h"

// ---------------------------------------------------------------------------
// Registry key path used by pma-11-02
// ---------------------------------------------------------------------------
inline const char* REG_PATH_1102 =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

inline void ensure_user_module(speakeasy::SpeakeasyConfig& cfg, const std::string& name,
                                const std::string& base_addr, const std::string& path) {
    for (auto& m : cfg.modules.user_modules) {
        std::string mn = m->name;
        std::transform(mn.begin(), mn.end(), mn.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        std::string nn = name;
        std::transform(nn.begin(), nn.end(), nn.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (mn == nn) return;
    }
    auto mod = std::make_shared<speakeasy::Module>();
    mod->name = name;
    mod->base = std::stoull(base_addr, nullptr, 16);
    mod->path = path;
    mod->image_size = 0;
    cfg.modules.user_modules.push_back(mod);
}

inline void set_main_command_line(speakeasy::SpeakeasyConfig& cfg, const std::string& cmdline) {
    cfg.command_line = cmdline;
    for (auto& p : cfg.processes) {
        if (p.is_main_exe) {
            p.command_line = cmdline;
            break;
        }
    }
}

inline void ensure_pma_0304_registry(speakeasy::SpeakeasyConfig& cfg) {
    const std::string key_path = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft \\XPS";
    for (auto& k : cfg.registry.keys) {
        std::string kp = k.path;
        std::transform(kp.begin(), kp.end(), kp.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        std::string needle = key_path;
        std::transform(needle.begin(), needle.end(), needle.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (kp == needle) return;
    }
    speakeasy::RegistryKey key;
    key.path = key_path;
    speakeasy::RegistryValue val;
    val.name = "Configuration";
    val.type = "REG_SZ";
    val.data = "1";
    key.values.push_back(val);
    cfg.registry.keys.push_back(key);
}

inline void set_main_process(speakeasy::SpeakeasyConfig& cfg, const std::string& name,
                              const std::string& path, const std::string& cmdline) {
    for (auto& p : cfg.processes) {
        if (p.is_main_exe) {
            p.name = name;
            p.path = path;
            p.command_line = cmdline;
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Profiles  (pma_profiles.py:25-183)
// ---------------------------------------------------------------------------

// pma-01-02  (pma_profiles.py:25-28)
inline CaseRuntime profile_pma_0102(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 2;
    cfg.max_api_count = 250;
    return {};
}

// pma-01-04  (pma_profiles.py:31-35)
inline CaseRuntime profile_pma_0104(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 2;
    cfg.max_api_count = 250;
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll");
    return {};
}

// pma-01-01-staged  (pma_profiles.py:167-183)
inline CaseRuntime profile_pma_0101_staged(speakeasy::SpeakeasyConfig& cfg, const fs::path& tmp) {
    cfg.timeout = 20;
    cfg.max_api_count = 200;
    cfg.exceptions.dispatch_handlers = true;

    fs::path source = PMA_DIR;
    fs::path sample_path = tmp / "sample.exe";

    try {
        fs::copy_file(source / "Practical Malware Analysis Lab 01-01.exe_", sample_path,
                      fs::copy_options::overwrite_existing);
        fs::copy_file(source / "Practical Malware Analysis Lab 01-01.dll_",
                      tmp / "Lab01-01.dll", fs::copy_options::overwrite_existing);
        fs::copy_file(source / "kernel32.dll_", tmp / "Kernel32.dll",
                      fs::copy_options::overwrite_existing);
    } catch (...) {
        // If copy fails, the test will skip because sample_path won't exist
    }

    CaseRuntime rt;
    rt.sample_path = sample_path;
    rt.argv = {"WARNING_THIS_WILL_DESTROY_YOUR_MACHINE"};
    rt.volumes = {tmp.string() + ":C:\\Windows\\system32"};
    return rt;
}

// pma-03-04-probe  (pma_profiles.py:48-51)
inline CaseRuntime profile_pma_0304_probe(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    set_main_command_line(cfg, "svchost.exe");
    ensure_pma_0304_registry(cfg);
    return {};
}

// pma-03-04-in  (pma_profiles.py:54-57)
inline CaseRuntime profile_pma_0304_in(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    set_main_command_line(cfg, "svchost.exe -in abcd");
    ensure_pma_0304_registry(cfg);
    return {};
}

// pma-03-04-re  (pma_profiles.py:60-63)
inline CaseRuntime profile_pma_0304_re(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    set_main_command_line(cfg, "svchost.exe -re abcd");
    ensure_pma_0304_registry(cfg);
    return {};
}

// pma-03-04-cc  (pma_profiles.py:66-69)
inline CaseRuntime profile_pma_0304_cc(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    set_main_command_line(cfg, "svchost.exe -cc abcd");
    ensure_pma_0304_registry(cfg);
    return {};
}

// pma-11-02-deep  (pma_profiles.py:72-97)
inline CaseRuntime profile_pma_1102_deep(speakeasy::SpeakeasyConfig& cfg, const fs::path& tmp) {
    fs::path ini_path = tmp / "Lab11-02.ini";

    // Write xor-encoded ini file
    {
        std::string plain = "lab11-02@example.com\r\n";
        std::vector<uint8_t> encoded;
        for (char c : plain) encoded.push_back(static_cast<uint8_t>(c) ^ 0x21);
        std::ofstream ofs(ini_path, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(encoded.data()), encoded.size());
    }

    speakeasy::FileEntry fe;
    fe.mode = "full_path";
    fe.emu_path = "C:\\Windows\\system32\\Lab11-02.ini";
    fe.path = ini_path.string();
    cfg.filesystem.files.insert(cfg.filesystem.files.begin(), fe);

    // Add registry key if missing
    {
        std::string needle = REG_PATH_1102;
        std::transform(needle.begin(), needle.end(), needle.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        bool found = false;
        for (auto& k : cfg.registry.keys) {
            std::string kp = k.path;
            std::transform(kp.begin(), kp.end(), kp.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (kp == needle) { found = true; break; }
        }
        if (!found) {
            speakeasy::RegistryKey key;
            key.path = REG_PATH_1102;
            cfg.registry.keys.push_back(key);
        }
    }

    set_main_process(cfg, "outlook", "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
                     "OUTLOOK.EXE");

    return {};
}

// pma-11-03-dll  (pma_profiles.py:100-103)
inline CaseRuntime profile_pma_1103_dll(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 20;
    cfg.max_api_count = 500;
    return {};
}

// pma-11-03-exe-missing-source  (pma_profiles.py:106-116)
inline CaseRuntime profile_pma_1103_exe_missing_source(speakeasy::SpeakeasyConfig& cfg,
                                                         const fs::path& /*tmp*/) {
    // Remove the default main.exe entry
    auto& files = cfg.filesystem.files;
    files.erase(
        std::remove_if(files.begin(), files.end(), [](const speakeasy::FileEntry& fe) {
            std::string p = fe.emu_path;
            std::transform(p.begin(), p.end(), p.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            return fe.mode == "full_path" &&
                   p == "c:\\windows\\system32\\main.exe";
        }),
        files.end());
    return {};
}

// pma-12-01-deep  (pma_profiles.py:119-122)
inline CaseRuntime profile_pma_1201_deep(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    set_main_command_line(cfg, "svchost.exe");
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll");
    return {};
}

// pma-12-02-deep  (pma_profiles.py:125-128)
inline CaseRuntime profile_pma_1202_deep(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 2;
    set_main_command_line(cfg, "svchost.exe");
    return {};
}

// pma-12-03-deep  (pma_profiles.py:131-134)
inline CaseRuntime profile_pma_1203_deep(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 2;
    set_main_command_line(cfg, "svchost.exe");
    return {};
}

// pma-12-04-deep  (pma_profiles.py:137-140)
inline CaseRuntime profile_pma_1204_deep(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    ensure_user_module(cfg, "psapi", "0x71000000", "C:\\Windows\\system32\\psapi.dll");
    ensure_user_module(cfg, "sfc_os", "0x5fe00000", "C:\\Windows\\system32\\sfc_os.dll");
    return {};
}

// pma-14-02  (pma_profiles.py:143-149)
inline CaseRuntime profile_pma_1402(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 6;
    cfg.max_api_count = 800;
    cfg.api_hammering.enabled = true;
    cfg.api_hammering.threshold = 50;
    return {};
}

// pma-16-03  (pma_profiles.py:152-155)
inline CaseRuntime profile_pma_1603(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.exceptions.dispatch_handlers = true;
    return {};
}

// pma-17-02  (pma_profiles.py:158-164)
inline CaseRuntime profile_pma_1702(speakeasy::SpeakeasyConfig& cfg, const fs::path& /*tmp*/) {
    cfg.timeout = 4;
    cfg.max_api_count = 600;
    cfg.api_hammering.enabled = true;
    cfg.api_hammering.threshold = 100;
    return {};
}
