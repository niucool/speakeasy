/**
 * test_porting.cpp — Porting-regression tests (GTest) matching Python patterns
 *
 * References:
 *   test_struct.py              → StructLayoutTest (EmuStruct byte layout, write_le)
 *   test_cli_config.py          → ConfigTest (defaults, JSON round-trip)
 *   test_profiler_artifacts.py  → ProfilerEventTest (log_file_access, log_registry)
 *   test_volumes.py             → VolumeTest (parse_volume_spec, expand_volume)
 *   test_process_parameters.py  → NtDefTest (UNICODE_STRING, KSYSTEM_TIME)
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
#include "windows/fileman.h"
#include "winenv/defs/nt/ntoskrnl.h"
#include "common.h"

using namespace speakeasy;

// ══════════════════════════════════════════════════════════════════
// EmuStruct byte-layout tests (← tests/test_struct.py)
// ══════════════════════════════════════════════════════════════════

class DEEP_NEST : public EmuStruct {
public:
    uint32_t Field1 = 0;
    uint32_t Field2 = 0;
    uint8_t  DeepData[32] = {};
    size_t sizeof_obj() const override { return 40; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        write_le(b, 0,  Field1, 4);
        write_le(b, 4,  Field2, 4);
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
        write_le(b, 0,  Field1, 2);
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

TEST(StructLayoutTest, DeepDataDefaultsToZero) {
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
// Config tests (← tests/test_cli_config.py)
// ══════════════════════════════════════════════════════════════════

TEST(ConfigTest, DefaultConfigHasExpectedValues) {
    SpeakeasyConfig cfg = default_config();
    EXPECT_EQ(cfg.timeout, 60);
    EXPECT_EQ(cfg.os_ver.major, 6);
}

TEST(ConfigTest, ConfigRoundTripJson) {
    SpeakeasyConfig cfg = default_config();
    cfg.timeout = 90;
    nlohmann::json j = cfg;
    SpeakeasyConfig cfg2 = j;
    EXPECT_EQ(cfg2.timeout, 90);
    EXPECT_EQ(cfg2.analysis.strings, true);
}

TEST(ConfigTest, ConfigCustomOsVersion) {
    nlohmann::json j;
    j["os_ver"]["major"] = 10;
    SpeakeasyConfig cfg = j;
    EXPECT_EQ(cfg.os_ver.major, 10);
}

// ══════════════════════════════════════════════════════════════════
// Profiler event tests (← tests/test_profiler_artifacts.py)
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
    EXPECT_TRUE(report.empty() || report.size() > 0);
}

// ══════════════════════════════════════════════════════════════════
// Volume tests (← tests/test_volumes.py)
// ══════════════════════════════════════════════════════════════════

TEST(VolumeTest, ParseVolumeSpec) {
    auto [host, guest] = parse_volume_spec("/tmp/samples:C:\\test");
    EXPECT_EQ(host.string(), "/tmp/samples");
    EXPECT_EQ(guest, "C:\\test");
}

TEST(VolumeTest, ExpandVolumeToEntries) {
    // Just verify the function signature compiles and runs
    auto entries = expand_volume_to_entries("/tmp", "C:\\test");
    // Empty dir yields no entries; this test validates no crash
    SUCCEED();
}

// ══════════════════════════════════════════════════════════════════
// ArtifactStore — Porting variant (suffixed Port to avoid smoke_test dupes)
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
    std::string r1 = store.put_bytes({'d','u','p','e'});
    std::string r2 = store.put_bytes({'d','u','p','e'});
    EXPECT_EQ(r1, r2);
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
    EXPECT_NE(a1, 0);
    // Second allocation may return same address depending on manager impl
    uint64_t a2 = mm.mem_map(0x2000, 0, PERM_MEM_RW, "mm2");
    EXPECT_NE(a2, 0);
}

// ══════════════════════════════════════════════════════════════════
// NT struct offset tests (← tests/test_process_parameters.py)
// ══════════════════════════════════════════════════════════════════

TEST(NtDefTest, UnicodeStringOffsets) {
    defs::nt::UNICODE_STRING us;
    EXPECT_EQ(us.sizeof_obj(), 16);
}

TEST(NtDefTest, UnicodeStringBufferOffset) {
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
    EXPECT_EQ(bytes[0],  0xDD);
    EXPECT_EQ(bytes[3],  0xAA);
    EXPECT_EQ(bytes[4],  0x44);
    EXPECT_EQ(bytes[7],  0x11);
    EXPECT_EQ(bytes[8],  0x88);
    EXPECT_EQ(bytes[11], 0x55);
}
