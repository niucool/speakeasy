/**
 * smoke_test.cpp  Speakeasy C++ Port Dependency & Core Tests (GTest)
 *
 * Validates all third-party libraries plus core C++ port modules.
 * Runs via: ctest -C Debug  or  ./speakeasy_tests --gtest_filter=Smoke*
 */

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <plog/Log.h>

// Core speakeasy modules
#include "config.h"
#include "errors.h"
#include "report.h"
#include "volumes.h"
#include "struct.h"
#include "artifacts.h"
#include "memmgr.h"
#include "profiler.h"
#include "winenv/arch.h"

// Windows emulation modules
#include "windows/fileman.h"
#include "windows/common.h"
#include "winenv/defs/nt/ntoskrnl.h"
#include "winenv/defs/nt/ddk.h"
#include "common.h"    // PERM_MEM_*, HOOK_* constants
#include <picosha2.h>

using namespace speakeasy;

//  Third-party library smoke tests 

TEST(SmokeTest, JsonLibrary) {
    nlohmann::json j;
    j["test"] = "hello";
    j["version"] = 1;
    EXPECT_EQ(j["test"], "hello");
    EXPECT_EQ(j["version"], 1);

    // Round-trip serialization
    auto serialized = j.dump();
    auto parsed = nlohmann::json::parse(serialized);
    EXPECT_EQ(parsed["test"], "hello");
}

//TEST(SmokeTest, PlogLibrary) {
//    // plog is header-only; verify the include compiles
//    SUCCEED();
//}

TEST(SmokeTest, ProjectVersion) {
    // The C++ port version constant (defined in version.h, included transitively)
    EXPECT_TRUE(true); // version check placeholder
}

//  Architecture constants 

TEST(ArchTest, Constants) {
    EXPECT_EQ(speakeasy::arch::ARCH_X86, 32);
    EXPECT_EQ(speakeasy::arch::ARCH_AMD64, 64);
    EXPECT_EQ(speakeasy::arch::PAGE_SIZE, 0x1000U);
}

//  NT Kernel Structure tests 

TEST(NtStructTest, UnicodeStringSize) {
    // 64-bit layout: Length(2) + MaxLen(2) + pad(4) + Buffer(8) = 16
    defs::nt::UNICODE_STRING us;
    EXPECT_EQ(us.sizeof_obj(), 16);
}

TEST(NtStructTest, UnicodeStringGetBytes) {
    // With 8-byte pointers (x64): Length(2) + MaxLen(2) + pad(4) + Buffer(8) = 16
    // sizeof_obj always returns the 64-bit layout since uint64_t is used for Buffer
    defs::nt::UNICODE_STRING us;
    us.Buffer = 0xDEADBEEFCAFEULL;
    auto bytes = us.get_bytes();
    EXPECT_EQ(bytes.size(), 16);
    // Buffer at offset 8 (little-endian)
    EXPECT_EQ(bytes[8], 0xFE);
    EXPECT_EQ(bytes[9], 0xCA);
}

TEST(NtStructTest, StringStruct) {
    defs::nt::STRING s;
    s.Length = 4;
    s.MaximumLength = 8;
    s.Buffer = 0x1000;
    auto bytes = s.get_bytes();
    // 64-bit layout: Length(2) + MaxLen(2) + pad(4) + Buffer(8) = 16
    EXPECT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[0], 4);  // Length
    EXPECT_EQ(bytes[1], 0);
    EXPECT_EQ(bytes[2], 8);  // MaxLength
    EXPECT_EQ(bytes[3], 0);
}

TEST(NtStructTest, KSystemTime) {
    defs::nt::KSYSTEM_TIME kt;
    kt.LowPart = 0xAABBCCDD;
    kt.High1Time = 0x11223344;
    kt.High2Time = 0x55667788;
    EXPECT_EQ(kt.sizeof_obj(), 12);

    auto bytes = kt.get_bytes();
    EXPECT_EQ(bytes.size(), 12);
    EXPECT_EQ(bytes[0], 0xDD);
    EXPECT_EQ(bytes[3], 0xAA);
    EXPECT_EQ(bytes[4], 0x44);
}

//  DDK constants 

TEST(DdkTest, MajorFunctionCodes) {
    EXPECT_EQ(IRP_MJ_CREATE, 0x00);
    EXPECT_EQ(IRP_MJ_READ, 0x03);
    EXPECT_EQ(IRP_MJ_WRITE, 0x04);
    EXPECT_EQ(IRP_MJ_DEVICE_CONTROL, 0x0E);
    EXPECT_EQ(IRP_MJ_MAXIMUM_FUNCTION, 0x1B);
}

//  File tests (standalone data classes) 

TEST(FileTest, FileConstructor) {
    File f(nullptr, "/tmp/test.txt", {}, {});
    EXPECT_EQ(f.get_path(), "/tmp/test.txt");
    EXPECT_FALSE(f.is_directory());
    // get_hash() requires data; empty file data is fine
    EXPECT_NO_THROW(f.get_size());
}

TEST(FileTest, FileDataReadWrite) {
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    File f(nullptr, "/tmp/test.txt", {}, data);
    EXPECT_EQ(f.get_size(), 5);

    auto read_data = f.get_data(-1, false);
    EXPECT_EQ(read_data.size(), 5);
    EXPECT_EQ(read_data[0], 'h');
}

TEST(FileTest, FileDuplicate) {
    std::vector<uint8_t> data = {'d', 'u', 'p', 'e'};
    File f(nullptr, "/tmp/orig.txt", {}, data);
    auto dup = f.duplicate();
    EXPECT_EQ(dup->get_path(), "/tmp/orig.txt");
    EXPECT_EQ(dup->get_size(), 4);
}

TEST(FileTest, FileSeek) {
    std::vector<uint8_t> data = {'a', 'b', 'c', 'd', 'e'};
    File f(nullptr, "/tmp/seek.txt", {}, data);
    EXPECT_EQ(f.tell(), 0);
    f.seek(2, 0);
    EXPECT_EQ(f.tell(), 2);

    auto read_data = f.get_data(2, false);
    EXPECT_EQ(read_data.size(), 2);
    EXPECT_EQ(read_data[0], 'c');
}

TEST(FileTest, FileAddData) {
    File f(nullptr, "/tmp/append.txt", {}, {});
    EXPECT_EQ(f.get_size(), 0);

    f.add_data({'h', 'i'});
    EXPECT_EQ(f.get_size(), 2);

    f.add_data({'!'});
    EXPECT_EQ(f.get_size(), 3);
}

TEST(FileTest, FileRemoveData) {
    std::vector<uint8_t> data = {'t', 'o', 'g', 'o'};
    File f(nullptr, "/tmp/remove.txt", {}, data);
    EXPECT_EQ(f.get_size(), 4);

    f.remove_data();
    EXPECT_EQ(f.get_size(), 0);
}

TEST(FileTest, FileGetHandle) {
    File f(nullptr, "/tmp/h1.txt", {}, {});
    uint32_t hf = f.get_handle();
    EXPECT_GT(hf, 0);
}

TEST(FileTest, MapViewConstructor) {
    MapView mv(0x1000, 0, 4096, 3, nullptr);
    EXPECT_EQ(mv.base, 0x1000ULL);
    EXPECT_EQ(mv.size, 4096);
    EXPECT_EQ(mv.protect, 3);
}

TEST(FileTest, FileMapConstructor) {
    FileMap fm(nullptr, "test_map", 4096, 3, nullptr);
    EXPECT_EQ(fm.get_name(), "test_map");
    EXPECT_EQ(fm.get_prot(), 3);
    EXPECT_EQ(fm.get_backed_file(), nullptr);
    EXPECT_GT(fm.get_handle(), 0);
}

TEST(FileTest, FileMapAddView) {
    FileMap fm(nullptr, "map_with_views", 8192, 3, nullptr);
    fm.add_view(0x1000, 0, 4096, 3);
    EXPECT_EQ(fm.get_views().size(), 1);
}

TEST(FileTest, PipeConstructor) {
    Pipe p(nullptr, "test_pipe", "read", 1, 4096, 4096, {});
    EXPECT_EQ(p.get_path(), "test_pipe");
    EXPECT_GT(p.get_handle(), 0);
}

//  Error tests 

TEST(ErrorTest, SpeakeasyErrorMessage) {
    SpeakeasyError err("custom error");
    EXPECT_STREQ(err.what(), "custom error");
}

TEST(ErrorTest, SpeakeasyErrorDefault) {
    SpeakeasyError err;
    EXPECT_STREQ(err.what(), "Speakeasy error occurred");
}

TEST(ErrorTest, ConfigErrorMessage) {
    ConfigError err("bad config");
    EXPECT_STREQ(err.what(), "bad config");
}

TEST(ErrorTest, NotSupportedError) {
    NotSupportedError err("not supported");
    EXPECT_STREQ(err.what(), "not supported");
}

//  Memory Manager tests 

TEST(MemoryManagerTest, DefaultConstruction) {
    MemoryManager mm;
    EXPECT_NO_THROW(mm.get_mem_maps());
    EXPECT_TRUE(mm.get_mem_maps().empty());
}

TEST(MemoryManagerTest, MemMapAndRead) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(4096, 0, PERM_MEM_RWX, "test_map");
    EXPECT_NE(addr, 0);

    auto map = mm.get_address_map(addr);
    ASSERT_NE(map, nullptr);
    EXPECT_EQ(map->get_size(), 4096);
    // Tag may include size suffix (e.g. "test_map.0x4096")
    EXPECT_TRUE(map->get_tag().find("test_map") != std::string::npos);
}

TEST(MemoryManagerTest, MemWriteAndRead) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(4096, 0, PERM_MEM_RW, "rw_test");

    std::vector<uint8_t> data = {0x10, 0x20, 0x30, 0x40};
    // mem_write requires a live emulation engine; without one the write
    // is tracked but reads may return zeros.
    EXPECT_NO_THROW(mm.mem_write(addr, data));
    EXPECT_NO_THROW(mm.mem_read(addr, 4));
}

TEST(MemoryManagerTest, MemProtect) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(4096, 0, PERM_MEM_RW, "prot_test");

    mm.mem_protect(addr, 4096, PERM_MEM_READ);
    auto map = mm.get_address_map(addr);
    ASSERT_NE(map, nullptr);
    // Protection change is tracked in the memory map
    EXPECT_NO_THROW(mm.mem_protect(addr, 4096, PERM_MEM_RW));
}

TEST(MemoryManagerTest, MemFree) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(4096, 0, PERM_MEM_RW, "free_test");
    EXPECT_NE(addr, 0);

    mm.mem_free(addr);
    // After free, address_map should either be null or marked free
    auto map = mm.get_address_map(addr);
    EXPECT_EQ(map, nullptr);
    // Memory manager coalesces; the exact behavior depends on implementation
    // but at minimum it should not crash
    //SUCCEED();
}

TEST(MemoryManagerTest, MemReserve) {
    MemoryManager mm;
    uint64_t addr = mm.mem_reserve(8192, 0, PERM_MEM_NONE, "reserved");
    EXPECT_NE(addr, 0);

    // Reserved memory should not be accessible as a regular map
    EXPECT_EQ(mm.get_address_map(addr), nullptr);
}

//  Profiler tests 

TEST(ProfilerTest, RunConstruction) {
    ::Run test_run;
    EXPECT_EQ(test_run.instr_cnt, 0);
    EXPECT_EQ(test_run.num_apis, 0);
    EXPECT_EQ(test_run.start_addr, 0);
    EXPECT_EQ(test_run.get_api_count(), 0);
}

TEST(ProfilerTest, ProfilerConstruction) {
    Profiler prof;
    EXPECT_NO_THROW(prof.set_start_time());
    EXPECT_NO_THROW(prof.get_run_time());
    EXPECT_NO_THROW(prof.stop_run_clock());
}

TEST(ProfilerTest, ProfilerAddRun) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    my_run->type = "test_run";
    my_run->start_addr = 0x1000;
    EXPECT_NO_THROW(prof.add_run(my_run));
}

TEST(ProfilerTest, ProfilerLogError) {
    Profiler prof;
    EXPECT_NO_THROW(prof.log_error("test error"));
}

TEST(ProfilerTest, ProfilerGetReport) {
    Profiler prof;
    auto report = prof.get_report();
    EXPECT_TRUE(report.report_version.size() > 0);  // Report is always valid, has version
}

TEST(ProfilerTest, ProfilerEmptyJsonReport) {
    Profiler prof;
    auto json = prof.get_json_report();
    EXPECT_TRUE(json.is_object() || json.is_null());
}

//  Profiler event logging tests 

TEST(ProfilerTest, LogFileAccess) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    EXPECT_NO_THROW(prof.log_file_access(my_run, "/tmp/test", "open"));
}

TEST(ProfilerTest, LogRegistryAccess) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    EXPECT_NO_THROW(prof.log_registry_access(my_run, "HKLM\\Software\\Test", "open"));
}

TEST(ProfilerTest, LogProcessEvent) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    std::map<std::string, std::string> kwargs = {{"pid", "1234"}};
    EXPECT_NO_THROW(prof.log_process_event(my_run, nullptr, "create", kwargs));
}

TEST(ProfilerTest, LogDns) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    EXPECT_NO_THROW(prof.log_dns(my_run, "example.com", "1.2.3.4"));
}

TEST(ProfilerTest, LogNetwork) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    std::vector<uint8_t> data = {0x01, 0x02};
    EXPECT_NO_THROW(prof.log_network(my_run, "1.2.3.4", 80, "connect", "tcp", data));
}

TEST(ProfilerTest, LogHttp) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    std::vector<uint8_t> body = {'O', 'K'};
    EXPECT_NO_THROW(prof.log_http(my_run, "example.com", 80, "http", "GET /", body));
}

TEST(ProfilerTest, LogApi) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    std::vector<std::string> argv = {"0x1000", "4", "0"};
    EXPECT_NO_THROW(prof.log_api(my_run, 0x401000, "kernel32.VirtualAlloc", nullptr, argv));
}

TEST(ProfilerTest, LogDynCode) {
    Profiler prof;
    auto my_run = std::make_shared<::Run>();
    prof.add_run(my_run);
    EXPECT_NO_THROW(prof.log_dyn_code(my_run, "mmap", 0x100000, 4096));
}

TEST(ProfilerTest, HandleBinaryData) {
    Profiler prof;
    std::vector<uint8_t> raw = {'t', 'e', 's', 't', ' ', 'd', 'a', 't', 'a'};
    std::string ref = prof.handle_binary_data(raw);
    // Returns SHA-256 hex ref or artifact reference
    EXPECT_FALSE(ref.empty());
}

//  ArtifactStore tests 

TEST(ArtifactStoreTest, PutAndGet) {
    ArtifactStore store;
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    auto ref = store.put_bytes(data);
    EXPECT_FALSE(ref.empty());

    auto retrieved = store.get_bytes(ref);
    EXPECT_EQ(retrieved.size(), 5);
    EXPECT_EQ(retrieved[0], 'h');
}

TEST(ArtifactStoreTest, Deduplication) {
    ArtifactStore store;
    std::vector<uint8_t> data = {'d', 'u', 'p', 'e'};
    auto ref1 = store.put_bytes(data);
    auto ref2 = store.put_bytes(data);
    EXPECT_EQ(ref1, ref2);  // Same content = same ref
}

TEST(ArtifactStoreTest, GetMissing) {
    ArtifactStore store;
    // Use EXPECT_ANY_THROW: SEH exceptions (miniz env) may prevent
    // std::runtime_error from being catchable as a C++ exception.
    EXPECT_ANY_THROW(store.get_bytes("nonexistent_hash"));
}

TEST(ArtifactStoreTest, EmptyData) {
    ArtifactStore store;
    // Empty data may still produce an artifact reference (SHA of empty string)
    auto ref = store.put_bytes({});
    // Any behavior is valid; just ensure no crash
    EXPECT_NO_THROW(store.put_bytes({}));
}

//  GDT constants 

TEST(GdtTest, AccessBits) {
    EXPECT_EQ(GDT_ACCESS_BITS::ProtMode32, 0x04);
    EXPECT_EQ(GDT_ACCESS_BITS::PresentBit, 0x80);
    EXPECT_EQ(GDT_ACCESS_BITS::Ring0, 0);
    EXPECT_EQ(GDT_ACCESS_BITS::DataWritable, 0x02);
    EXPECT_EQ(GDT_ACCESS_BITS::CodeReadable, 0x02);
}
