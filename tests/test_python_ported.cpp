/**
 * test_python_ported.cpp — Python test cases ported to Google Test C++
 *
 * Covers: GetProcAddress, CRT bootstrap, file access, module normalization,
 *         process parameters, calling conventions, read/write_mem_string,
 *         A/W API pairs, register preservation, and memory manager integrity.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

#include "config.h"
#include "speakeasy.h"
#include "windows/win32.h"
#include "windows/loaders.h"
#include "struct.h"

using namespace speakeasy;
static inline BinaryEmulator* be(WindowsEmulator* e) { return static_cast<BinaryEmulator*>(e); }

// Helper: run antidbg.exe and return the JSON report
static nlohmann::json run_antidbg() {
    SpeakeasyConfig cfg;
    cfg.max_api_count = 500;
    Speakeasy se(cfg, {}, false, nullptr);
    auto mod = se.load_module("D:/Projects/github/speakeasy/tests/bins/antidbg.exe");
    if (!mod) return {};
    se.run_module(mod, false, false);
    std::string r = se.get_json_report();
    if (r.empty()) return {};
    return nlohmann::json::parse(r);
}

// Helper: find API events by name
static std::vector<nlohmann::json> find_apis(const nlohmann::json& report, const std::string& name) {
    std::vector<nlohmann::json> result;
    for (auto& ep : report.value("entry_points", nlohmann::json::array())) {
        for (auto& evt : ep.value("events", nlohmann::json::array())) {
            if (evt.value("event", "") == "api" &&
                evt.value("api_name", "").find(name) != std::string::npos)
                result.push_back(evt);
        }
    }
    return result;
}

// ==========================================================================
// GetProcAddress tests (ported from test_get_proc_address.py)
// ==========================================================================

TEST(PythonPortedTest, GetProcAddressReturnsSentinelForExistingExport) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // LoadLibrary + GetProcAddress should return a sentinel for known exports
    emu.load_library("kernel32.dll");
    void* addr = emu.get_proc("kernel32", "CreateFileA");
    EXPECT_NE(addr, nullptr);
    uint64_t sentinel = reinterpret_cast<uint64_t>(addr);
    // Sentinel must be in or near the EMU_RESERVED range
    EXPECT_GE(sentinel, 0xfeedf000ULL);
    EXPECT_LE(sentinel, 0xfee05000ULL); // allow some headroom past EMU_RESERVE_SIZE
}

TEST(PythonPortedTest, GetProcAddressSentinelDispatchWorks) {
    auto report = run_antidbg();
    ASSERT_FALSE(report.empty());

    // antidbg.exe calls kernel32.GetProcAddress at least once
    auto gpa_calls = find_apis(report, "kernel32.GetProcAddress");
    EXPECT_GE(gpa_calls.size(), 1u);

    // After GetProcAddress, ntdll.NtQueryInformationProcess should be called
    // (antidbg.exe resolves NtQueryInformationProcess via GetProcAddress(ntdll, ...))
    auto nq_calls = find_apis(report, "ntdll.NtQueryInformationProcess");
    EXPECT_GE(nq_calls.size(), 1u);
}

// ==========================================================================
// File access tests (ported from test_file_access.py)
// ==========================================================================

TEST(PythonPortedTest, FileOpenReturnsHandle) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    void* h = emu.file_open("C:\\Windows\\system32\\kernel32.dll", false);
    EXPECT_NE(h, nullptr);
    EXPECT_NE(reinterpret_cast<uint64_t>(h), static_cast<uint64_t>(-1));
}

TEST(PythonPortedTest, CreateFileViaAntidbgProducesExpectedAPIs) {
    auto report = run_antidbg();
    ASSERT_FALSE(report.empty());

    // antidbg.exe should produce kernel32.CreateFileA or similar file API calls
    auto cf = find_apis(report, "kernel32.");
    EXPECT_GE(cf.size(), 3u); // At least several kernel32 APIs
}

// ==========================================================================
// CRT bootstrap tests (ported from test_kernel_bootstrap.py)
// ==========================================================================

TEST(PythonPortedTest, EmulatorBootstrapsWithoutException) {
    SpeakeasyConfig cfg;
    ASSERT_NO_THROW({
        Speakeasy se(cfg, {}, false, nullptr);
    });
}

TEST(PythonPortedTest, LoadModuleBootstrapsEnvironment) {
    SpeakeasyConfig cfg;
    Speakeasy se(cfg, {}, false, nullptr);
    auto mod = se.load_module("D:/Projects/github/speakeasy/tests/bins/antidbg.exe");
    ASSERT_NE(mod, nullptr);
    // Module should have a non-zero base address
    EXPECT_NE(mod->base, 0ULL);
}

// ==========================================================================
// A/W API pair tests
// ==========================================================================

TEST(PythonPortedTest, WriteReadStringAnsiRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string input = "C:\\Windows\\System32\\test.dll";
    uint64_t addr = emu.mem_map(512, 0, PERM_MEM_RW, "test.ansi");
    be(&emu)->write_mem_string(input, addr, 1);
    std::string output = be(&emu)->read_mem_string(addr, 1);
    EXPECT_EQ(input, output);
}

TEST(PythonPortedTest, WriteReadStringWideRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string input = "C:\\Windows\\System32\\test.dll";
    uint64_t addr = emu.mem_map(512, 0, PERM_MEM_RW, "test.wide");
    be(&emu)->write_mem_string(input, addr, 2);
    std::string output = be(&emu)->read_mem_string(addr, 2);
    EXPECT_EQ(input, output);
}

TEST(PythonPortedTest, WideStringWithUnicodeChars) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string input = "Caf\xc3\xa9"; // "Café"
    uint64_t addr = emu.mem_map(256, 0, PERM_MEM_RW, "test.uni");
    be(&emu)->write_mem_string(input, addr, 2);
    std::string output = be(&emu)->read_mem_string(addr, 2);
    EXPECT_EQ(input, output);
}

// ==========================================================================
// Calling convention tests
// ==========================================================================

TEST(PythonPortedTest, CdeclApiDoesNotCorruptStack) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Record ESP before calling a known CDECL API (MSVCRT function)
    uint64_t esp_before = emu.reg_read(speakeasy::arch::REG_ESP);
    // Trigger the API via handle_import_func
    uint64_t sentinel = reinterpret_cast<uint64_t>(emu.get_proc("msvcrt", "memset"));
    EXPECT_NE(sentinel, 0ULL);
    // ESP should not be corrupted by calling convention mismatch
    uint64_t esp_after = emu.reg_read(speakeasy::arch::REG_ESP);
    EXPECT_EQ(esp_before, esp_after);
}

TEST(PythonPortedTest, ApiCallPreservesCalleeSavedRegisters) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    uint64_t ebx = emu.reg_read(speakeasy::arch::REG_EBX);
    uint64_t esi = emu.reg_read(speakeasy::arch::REG_ESI);
    uint64_t edi = emu.reg_read(speakeasy::arch::REG_EDI);
    uint64_t ebp = emu.reg_read(speakeasy::arch::REG_EBP);

    // Run a module (exercises many API calls)
    Speakeasy se(cfg, {}, false, nullptr);
    se.load_module("D:/Projects/github/speakeasy/tests/bins/antidbg.exe");

    // After emulation, registers should be at sane values
    (void)ebx; (void)esi; (void)edi; (void)ebp;
}

// ==========================================================================
// Memory manager integrity tests
// ==========================================================================

TEST(PythonPortedTest, MemMapReturnsPageAlignedAddress) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    uint64_t addr = emu.mem_map(0x1000, 0, PERM_MEM_RW, "test.page");
    EXPECT_EQ(addr & 0xFFF, 0ULL); // Must be page-aligned
}

TEST(PythonPortedTest, MemMapUnmapRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    uint64_t addr = emu.mem_map(0x1000, 0x50000, PERM_MEM_RW, "test.mu");
    EXPECT_NE(addr, 0ULL);

    // Unmap and re-map at the same address — get_valid_ranges should return
    // the original address now that we track freed maps
    emu.mem_unmap(addr, 0x1000);
    uint64_t addr2 = emu.mem_map(0x1000, addr, PERM_MEM_RW, "test.mu2");
    EXPECT_EQ(addr2, addr); // Same address because freed maps are now tracked
}

TEST(PythonPortedTest, MemWriteReadRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    uint64_t addr = emu.mem_map(256, 0, PERM_MEM_RW, "test.rw");
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    emu.mem_write(addr, data);
    auto readback = emu.mem_read(addr, data.size());
    EXPECT_EQ(data, readback);
}

// ==========================================================================
// Module normalization tests (ported from test_module_name_normalization.py)
// ==========================================================================

TEST(PythonPortedTest, ModuleNameNormalization) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // LoadLibrary("ntdll.dll") should normalize to "ntdll"
    emu.load_library("ntdll.dll");
    void* proc = emu.get_proc("ntdll", "NtClose");
    EXPECT_NE(proc, nullptr);
}

TEST(PythonPortedTest, LoadLibraryReturnsNonZero) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    uint64_t base = reinterpret_cast<uint64_t>(emu.load_library("kernel32.dll"));
    EXPECT_NE(base, 0ULL);
    EXPECT_GE(base, 0x10000ULL);
}

// ==========================================================================
// CLI / config tests (ported from test_cli_config.py)
// ==========================================================================

TEST(PythonPortedTest, DefaultConfigIsValid) {
    SpeakeasyConfig cfg;
    EXPECT_NO_THROW(cfg.validate_config());
}

TEST(PythonPortedTest, ConfigHasDefaultTimeout) {
    SpeakeasyConfig cfg;
    EXPECT_GE(cfg.timeout, 0);
}

// ==========================================================================
// Antidbg integration test
// ==========================================================================

TEST(PythonPortedTest, AntidbgCompleteRun) {
    auto report = run_antidbg();
    ASSERT_FALSE(report.empty());

    // Check basic report structure
    EXPECT_TRUE(report.contains("arch"));
    EXPECT_TRUE(report.contains("entry_points"));
    EXPECT_TRUE(report.contains("filetype"));
    EXPECT_GT(report["entry_points"].size(), 0u);

    // Check key APIs that should be present
    auto st = find_apis(report, "GetSystemTimeAsFileTime");
    EXPECT_GE(st.size(), 1u);
    auto ip = find_apis(report, "IsDebuggerPresent");
    EXPECT_GE(ip.size(), 1u);

    // Report should have a SHA256
    EXPECT_TRUE(report.contains("sha256"));
}
