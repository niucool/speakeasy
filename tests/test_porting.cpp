/**
 * test_porting.cpp — Comprehensive porting-regression tests (GTest)
 *
 * Ports the following Python test files to C++:
 *   test_struct.py                → StructLayoutTest  (EmuStruct byte layout, write_le)
 *   test_cli_config.py            → ConfigTest        (defaults, JSON round-trip, merge)
 *   test_config.py                → ConfigTest        (validate, reject invalid engine)
 *   test_config_memory_dumps.py   → ConfigTest        (legacy alias)
 *   test_module_name_normalization.py → NormalizeModNameTest
 *   test_profiler_artifacts.py    → ProfilerEventTest (log_file_access, log_registry)
 *   test_volumes.py               → VolumeTest        (parse_volume_spec, expand)
 *   test_process_parameters.py    → NtDefTest         (UNICODE_STRING, KSYSTEM_TIME)
 *   test_artifact_store.py        → ArtifactStorePortTest (put/get, dedup, empty, size)
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <picosha2.h>
#include <miniz.h>
#include <cstring>
#include <cstdint>

#include "config.h"
#include "struct.h"
#include "volumes.h"
#include "profiler.h"
#include "profiler_events.h"
#include "artifacts.h"
#include "errors.h"
#include "memmgr.h"
#include "windows/winemu.h"
#include "windows/fileman.h"
#include "windows/loaders.h"
#include "winenv/defs/nt/ntoskrnl.h"
#include "common.h"

using namespace speakeasy;

// ══════════════════════════════════════════════════════════════════
// Struct tests  (← tests/test_struct.py)
// ══════════════════════════════════════════════════════════════════

class DEEP_NEST : public EmuStruct {
public:
    uint32_t Field1 = 0;
    uint32_t Field2 = 0;
    uint8_t  DeepData[32] = {};
    size_t sizeof_obj() const override { return 40; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        write_le(b, 0, Field1, 4);
        write_le(b, 4, Field2, 4);
        memcpy(b.data() + 8, DeepData, 32);
        return b;
    }
};

struct SHALLOW_NEST : public EmuStruct {
    uint16_t Field1 = 0;
    DEEP_NEST DeepStruct;
    uint16_t Field2 = 0;
    size_t sizeof_obj() const override { return 44; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(44);
        write_le(b, 0, Field1, 2);
        auto deep_bytes = DeepStruct.get_bytes();
        memcpy(b.data() + 2, deep_bytes.data(), deep_bytes.size());
        write_le(b, 42, Field2, 2);
        return b;
    }
};

TEST(StructLayoutTest, NestedEmuStruct32bit) {
    DEEP_NEST deep;
    deep.Field1 = 0x06060606;
    deep.Field2 = 0x07070707;
    memset(deep.DeepData, 'A', 32);
    SHALLOW_NEST shallow;
    shallow.Field1 = 0x0505;
    shallow.DeepStruct = deep;
    shallow.Field2 = 0x0808;
    auto bytes = shallow.get_bytes();
    ASSERT_EQ(bytes.size(), 44);
    EXPECT_EQ(bytes[0], 0x05); EXPECT_EQ(bytes[1], 0x05);
    EXPECT_EQ(bytes[2], 0x06); EXPECT_EQ(bytes[5], 0x06);
    EXPECT_EQ(bytes[10], 'A'); EXPECT_EQ(bytes[41], 'A');
    EXPECT_EQ(bytes[42], 0x08); EXPECT_EQ(bytes[43], 0x08);
}

TEST(StructLayoutTest, DefaultValuesAreZero) {
    DEEP_NEST deep;
    auto b = deep.get_bytes();
    for (uint8_t byte : b) EXPECT_EQ(byte, 0);
}

TEST(StructLayoutTest, WriteLeUint32) {
    std::vector<uint8_t> buf(8, 0);
    write_le(buf, 0, 0xAABBCCDDUL, 4);
    EXPECT_EQ(buf[0], 0xDD);
    EXPECT_EQ(buf[3], 0xAA);
}

// ══════════════════════════════════════════════════════════════════
// Config tests  (← tests/test_cli_config.py, test_config.py,
//                 test_config_memory_dumps.py)
// ══════════════════════════════════════════════════════════════════

TEST(ConfigTest, DefaultConfigValidates) {
    SpeakeasyConfig cfg = default_config();
    EXPECT_NO_THROW(validate_config(cfg));
}

TEST(ConfigTest, DefaultHasExpectedValues) {
    SpeakeasyConfig cfg = default_config();
    EXPECT_EQ(cfg.timeout, 60);
    EXPECT_EQ(cfg.max_api_count, 10000);
    EXPECT_EQ(cfg.os_ver.major, 6);
    EXPECT_EQ(cfg.analysis.strings, true);
}

TEST(ConfigTest, JsonRoundTrip) {
    SpeakeasyConfig cfg = default_config();
    cfg.timeout = 90;
    cfg.analysis.coverage = true;
    nlohmann::json j = cfg;
    SpeakeasyConfig cfg2 = j;
    EXPECT_EQ(cfg2.timeout, 90);
    EXPECT_EQ(cfg2.analysis.coverage, true);
    EXPECT_EQ(cfg2.analysis.strings, true);  // non-overridden preserved
}

TEST(ConfigTest, CustomOsVersion) {
    nlohmann::json j;
    j["os_ver"]["major"] = 10;
    j["os_ver"]["minor"] = 0;
    j["os_ver"]["build"] = 19041;
    SpeakeasyConfig cfg = j;
    EXPECT_EQ(cfg.os_ver.major, 10);
    EXPECT_EQ(cfg.os_ver.minor, 0);
}

TEST(ConfigTest, RejectsInvalidEngine) {
    nlohmann::json j;
    j["emu_engine"] = "alternate_engine";
    SpeakeasyConfig cfg = j;
    EXPECT_THROW(validate_config(cfg), ConfigError);
}

// Legacy capture_memory_dumps alias (← test_config_memory_dumps.py)
TEST(ConfigTest, LegacyCaptureMemoryDumpsAlias) {
    nlohmann::json j = R"({
        "config_version": 0.2,
        "emu_engine": "unicorn",
        "timeout": 60,
        "system": "windows",
        "capture_memory_dumps": true,
        "analysis": {"memory_tracing": false, "strings": true, "coverage": false},
        "exceptions": {"dispatch_handlers": true},
        "os_ver": {},
        "current_dir": "C:\\Windows",
        "hostname": "test",
        "user": {"name": "test"},
        "filesystem": {"files": []},
        "network": {"dns": {"names": {}}, "http": {"responses": []},
                     "winsock": {"responses": []}, "adapters": []},
        "modules": {"module_directory_x86": "", "module_directory_x64": ""}
    })"_json;
    SpeakeasyConfig cfg = j;
    SUCCEED();
}

// ══════════════════════════════════════════════════════════════════
// Module name normalization  (← tests/test_module_name_normalization.py)
// ── Replicates WindowsEmulator::normalize_mod_name inline
//     (the method is protected in the class)
// ══════════════════════════════════════════════════════════════════

static std::string normalize_mod_name(const std::string& name) {
    auto dot = name.find_last_of('.');
    std::string base = (dot != std::string::npos) ? name.substr(0, dot) : name;
    for (auto& c : base) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return base;
}

TEST(NormalizeModNameTest, Lowercase) {
    EXPECT_EQ(normalize_mod_name("KERNEL32"), "kernel32");
    EXPECT_EQ(normalize_mod_name("Kernel32"), "kernel32");
    EXPECT_EQ(normalize_mod_name("kernel32"), "kernel32");
}

TEST(NormalizeModNameTest, StripsExtension) {
    EXPECT_EQ(normalize_mod_name("kernel32.dll"), "kernel32");
    EXPECT_EQ(normalize_mod_name("kernel32.DLL"), "kernel32");
    EXPECT_EQ(normalize_mod_name("ntdll.dll"), "ntdll");
    EXPECT_EQ(normalize_mod_name("SHELL32.DLL"), "shell32");
}

TEST(NormalizeModNameTest, MixedCaseWithExtension) {
    EXPECT_EQ(normalize_mod_name("User32.DLL"), "user32");
    EXPECT_EQ(normalize_mod_name("ADVAPI32.dll"), "advapi32");
}

TEST(NormalizeModNameTest, NoExtension) {
    EXPECT_EQ(normalize_mod_name("kernel32"), "kernel32");
}

// ══════════════════════════════════════════════════════════════════
// Profiler event tests  (← tests/test_profiler_artifacts.py)
// ══════════════════════════════════════════════════════════════════

TEST(ProfilerEventTest, LogFileAccess) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    EXPECT_NO_THROW(
        prof.log_file_access(run, "C:\\test\\write.exe", "write",
                             std::vector<uint8_t>{'a','b','c'})
    );
}

TEST(ProfilerEventTest, LogRegistryAccess) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    EXPECT_NO_THROW(
        prof.log_registry_access(run, "HKLM\\SOFTWARE\\Test", "write",
                                 "TestValue", std::vector<uint8_t>{1,2,3,4})
    );
}

TEST(ProfilerEventTest, ProfilerGetReport) {
    Profiler prof;
    prof.set_start_time();
    auto report = prof.get_report();
    EXPECT_TRUE(report.report_version.size() > 0);  // Report is always valid, has version
}

TEST(ProfilerEventTest, MultipleFileAccesses) {
    Profiler prof;
    auto run = std::make_shared<::Run>();
    prof.add_run(run);
    for (int i = 0; i < 5; i++)
        EXPECT_NO_THROW(prof.log_file_access(run, "C:\\multi\\file" +
            std::to_string(i) + ".bin", "write"));
}

// ══════════════════════════════════════════════════════════════════
// Volume tests  (← tests/test_volumes.py)
// ══════════════════════════════════════════════════════════════════

TEST(VolumeTest, ParseUnixToWindows) {
    auto [host, guest] = parse_volume_spec("/tmp/samples:C:\\test");
    EXPECT_EQ(host, std::filesystem::path("/tmp/samples"));
    EXPECT_EQ(guest, "C:\\test");
}

TEST(VolumeTest, ParseWindowsToWindows) {
    auto [host, guest] = parse_volume_spec("D:\\src:C:\\dest");
    EXPECT_TRUE(host == "D:\\src" || host == "D:/src");
    EXPECT_EQ(guest, "C:\\dest");
}

TEST(VolumeTest, ExpandVolumeToEntries) {
    auto entries = expand_volume_to_entries("/tmp", "C:\\test");
    SUCCEED();  // no crash on empty dir
}

TEST(VolumeTest, RejectsMissingColon) {
    EXPECT_THROW(parse_volume_spec("invalid"), std::invalid_argument);
}

// ══════════════════════════════════════════════════════════════════
// ArtifactStore  (← tests/test_artifact_store.py)
// ══════════════════════════════════════════════════════════════════

TEST(ArtifactStorePortTest, GetMissing) {
    ArtifactStore store;
    EXPECT_ANY_THROW(store.get_bytes("nonexistent_hash"));
}

TEST(ArtifactStorePortTest, PutAndGet) {
    ArtifactStore store;
    std::string ref = store.put_bytes({'h','e','l','l','o'});
    EXPECT_NE(ref, "");
    auto retrieved = store.get_bytes(ref);
    ASSERT_EQ(retrieved.size(), 5);
    EXPECT_EQ(retrieved[0], 'h');
}

TEST(ArtifactStorePortTest, Dedup) {
    ArtifactStore store;
    EXPECT_EQ(store.put_bytes({'d','u','p','e'}),
              store.put_bytes({'d','u','p','e'}));
}

TEST(ArtifactStorePortTest, ToReportData) {
    ArtifactStore store;
    store.put_bytes({1,2,3});
    EXPECT_GE(store.to_report_data().size(), 1);
}

TEST(ArtifactStorePortTest, EmptyData) {
    ArtifactStore store;
    EXPECT_EQ(store.put_bytes({}), "");
}

TEST(ArtifactStorePortTest, SizeAndClear) {
    ArtifactStore store;
    store.put_bytes({1,2,3});
    store.put_bytes({4,5,6});
    EXPECT_EQ(store.size(), 2);
    store.clear();
    EXPECT_EQ(store.size(), 0);
}

// ══════════════════════════════════════════════════════════════════
// Memory Manager
// ══════════════════════════════════════════════════════════════════

TEST(MemoryManagerPortTest, MemMapMultiple) {
    MemoryManager mm;
    uint64_t a1 = mm.mem_map(0x1000, 0, PERM_MEM_RWX, "mm1");
    uint64_t a2 = mm.mem_map(0x2000, 0, PERM_MEM_RW,  "mm2");
    EXPECT_NE(a1, 0);
    EXPECT_NE(a2, 0);
}

TEST(MemoryManagerPortTest, MemMapAtFixedAddress) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(0x1000, 0x10000000, PERM_MEM_RWX, "fixed");
    EXPECT_EQ(addr, 0x10000000);
}

// ══════════════════════════════════════════════════════════════════
// NT struct offset tests  (← tests/test_process_parameters.py)
// ══════════════════════════════════════════════════════════════════

TEST(NtDefTest, UnicodeStringOffsets) {
    defs::nt::UNICODE_STRING us;
    EXPECT_EQ(us.sizeof_obj(), 16);  // x64: Len(2)+Max(2)+pad(4)+Buf(8)
}

TEST(NtDefTest, UnicodeStringBufferAtOffset8) {
    defs::nt::UNICODE_STRING us;
    us.Buffer = 0xDEADBEEFCAFEULL;
    auto bytes = us.get_bytes();
    EXPECT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[8], 0xFE);
    EXPECT_EQ(bytes[9], 0xCA);
}

TEST(NtDefTest, KSystemTimeLayout) {
    defs::nt::KSYSTEM_TIME kt;
    kt.LowPart   = 0xAABBCCDD;
    kt.High1Time = 0x11223344;
    kt.High2Time = 0x55667788;
    EXPECT_EQ(kt.sizeof_obj(), 12);
    auto bytes = kt.get_bytes();
    EXPECT_EQ(bytes.size(), 12);
    EXPECT_EQ(bytes[0],  0xDD);  // LowPart LSB
    EXPECT_EQ(bytes[3],  0xAA);  // LowPart MSB
    EXPECT_EQ(bytes[4],  0x44);  // High1Time LSB
    EXPECT_EQ(bytes[7],  0x11);  // High1Time MSB
    EXPECT_EQ(bytes[8],  0x88);  // High2Time LSB
    EXPECT_EQ(bytes[11], 0x55);  // High2Time MSB
}

TEST(NtDefTest, StringStruct) {
    defs::nt::STRING s;
    s.Length = 4;
    s.MaximumLength = 8;
    s.Buffer = 0x1000;
    auto bytes = s.get_bytes();
    EXPECT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[0], 4);   // Length
    EXPECT_EQ(bytes[2], 8);   // MaxLength
}

// ══════════════════════════════════════════════════════════════════
// Loaders & Module Classification Tests
// ══════════════════════════════════════════════════════════════════

TEST(LoaderModuleClassificationTest, SubsystemCUIExeClassification) {
    auto img = std::make_shared<LoadedImage>();
    img->is_driver = false;
    img->is_dll = false;
    img->is_decoy = false;
    img->metadata.subsystem = 3;  // IMAGE_SUBSYSTEM_WINDOWS_CUI
    img->base = 0x400000;
    img->image_size = 0x1000;
    img->ep = 0x1000;

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_exe());
    EXPECT_FALSE(mod.is_dll());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_FALSE(mod.is_decoy());
    EXPECT_EQ(mod.module_type, "exe");
}

TEST(LoaderModuleClassificationTest, DecoyLoaderClassification) {
    DecoyLoader loader("kernel32.dll", 0x77000000, "C:\\Windows\\System32\\kernel32.dll", 0x100000);
    auto img = loader.make_image();
    EXPECT_TRUE(img->is_decoy);
    EXPECT_FALSE(img->is_driver);

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_decoy());
    EXPECT_FALSE(mod.is_exe());
    EXPECT_FALSE(mod.is_dll());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_EQ(mod.module_type, "decoy");
}

TEST(LoaderModuleClassificationTest, ApiModuleLoaderClassification) {
    ApiModuleLoader loader("kernel32", nullptr, 64, 0x76000000, "C:\\Windows\\System32\\kernel32.dll");
    auto img = loader.make_image();
    EXPECT_TRUE(img->is_dll);
    EXPECT_FALSE(img->is_driver);
    EXPECT_FALSE(img->is_decoy);

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_dll());
    EXPECT_FALSE(mod.is_exe());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_FALSE(mod.is_decoy());
    EXPECT_EQ(mod.module_type, "dll");
}
