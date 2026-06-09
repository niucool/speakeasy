// test_pma_samples.cpp -- C++ port of tests/test_pma_samples.py
// Runs declarative PMA (Practical Malware Analysis) test cases against the
// Speakeasy emulator, verifying that expected APIs and indicators appear.
//
// Requires the capa-testfiles Git submodule for sample binaries.
// Run: git submodule update --init --recursive
// Set SPEAKEASY_PMA_FULL=1 to run all 38 cases instead of the curated 12.

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <set>
#include <vector>

#include "pma_harness.h"
#include "pma_profiles.h"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Curated subset of PMA cases run in CI / default mode (Python:29-37)
// ---------------------------------------------------------------------------
static const std::set<std::string> CURATED_CASE_NAMES = {
    "pma-01-02-exe",
    "pma-03-02-dll",
    "pma-03-04-in",
    "pma-05-01-dll",
    "pma-06-03-exe",
    "pma-10-03-sys",
    "pma-11-02-dll",
    "pma-12-02-exe",
    "pma-12-04-exe",
    "pma-14-01-exe",
    "pma-16-03-exe",
    "pma-21-01-exe",
};

// ---------------------------------------------------------------------------
// All PMA cases (Python: pma_cases.py:22-280)
// ---------------------------------------------------------------------------
static const std::vector<PmaCase> PMA_CASES = {
    // --- pma-01 ---
    PmaCase{"pma-01-01-dll", "Practical Malware Analysis Lab 01-01.dll_",
            {"KERNEL32.OpenMutexA", "WS2_32.WSAStartup"}, {}, {}, {"max_api_count"}},
    PmaCase{"pma-01-01-exe", "Practical Malware Analysis Lab 01-01.exe_",
            {"MSVCRT.__getmainargs", "MSVCRT.exit"}},
    PmaCase{"pma-01-01-exe-staged", "Practical Malware Analysis Lab 01-01.exe_",
            {"KERNEL32.CreateFileMappingA", "KERNEL32.MapViewOfFile"}, {},
            {}, {"max_api_count", "invalid_read"}, {}, profile_pma_0101_staged},
    PmaCase{"pma-01-02-exe", "Practical Malware Analysis Lab 01-02.exe_",
            {"KERNEL32.GetProcAddress", "WININET.InternetOpenUrlA"},
            {{}, {}, {"www.malwareanalysisbook.com"}, {"http://www.malwareanalysisbook.com"}},
            {}, {"max_api_count"}, {}, profile_pma_0102},
    PmaCase{"pma-01-04-exe", "Practical Malware Analysis Lab 01-04.exe_",
            {"KERNEL32.LoadLibraryA", "KERNEL32.GetProcAddress"}, {}, {}, {}, {}, profile_pma_0104},

    // --- pma-03 ---
    PmaCase{"pma-03-02-dll", "Practical Malware Analysis Lab 03-02.dll_",
            {"ADVAPI32.OpenSCManagerA", "KERNEL32.GetModuleFileNameA"},
            {{}, {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost"},
             {"practicalmalwareanalysis.com"}},
            {}, {"max_api_count"}},
    PmaCase{"pma-03-03-exe", "Practical Malware Analysis Lab 03-03.exe_",
            {"KERNEL32.HeapCreate", "KERNEL32.Sleep"}},
    PmaCase{"pma-03-04-exe", "Practical Malware Analysis Lab 03-04.exe_",
            {"KERNEL32.GetVersionExA", "KERNEL32.SetHandleCount"}},
    PmaCase{"pma-03-04-probe", "Practical Malware Analysis Lab 03-04.exe_",
            {"ADVAPI32.RegQueryValueExA", "KERNEL32.GetTimeZoneInformation"}, {}, {}, {},
            {}, profile_pma_0304_probe},
    PmaCase{"pma-03-04-in", "Practical Malware Analysis Lab 03-04.exe_",
            {"ADVAPI32.ChangeServiceConfigA", "KERNEL32.CopyFileA", "ADVAPI32.RegSetValueExA"},
            {}, {}, {}, {}, profile_pma_0304_in},
    PmaCase{"pma-03-04-re", "Practical Malware Analysis Lab 03-04.exe_",
            {"ADVAPI32.DeleteService", "KERNEL32.DeleteFileA", "ADVAPI32.RegDeleteValueA"},
            {}, {}, {}, {}, profile_pma_0304_re},
    PmaCase{"pma-03-04-cc", "Practical Malware Analysis Lab 03-04.exe_",
            {"ADVAPI32.RegOpenKeyExA", "ADVAPI32.RegQueryValueExA", "KERNEL32.WriteFile"},
            {}, {}, {}, {}, profile_pma_0304_cc},

    // --- pma-05 ---
    PmaCase{"pma-05-01-dll", "Practical Malware Analysis Lab 05-01.dll_",
            {"KERNEL32.CreateThread", "ADVAPI32.RegSetValueExA"},
            {{"C:\\Windows\\system32\\Practical Malware Analysis Lab 05-01.dll_"},
             {"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Irmon"}},
            {}, {"max_api_count", "invalid_read"}},

    // --- pma-06 ---
    PmaCase{"pma-06-03-exe", "Practical Malware Analysis Lab 06-03.exe_",
            {"WININET.InternetGetConnectedState", "WININET.InternetOpenUrlA",
             "KERNEL32.WriteFile", "KERNEL32.ExitProcess"},
            {{}, {}, {"www.practicalmalwareanalysis.com"},
             {"http://www.practicalmalwareanalysis.com/cc.htm"}}},

    // --- pma-10 ---
    PmaCase{"pma-10-03-exe", "Practical Malware Analysis Lab 10-03.exe_",
            {"ADVAPI32.CreateServiceA", "KERNEL32.DeviceIoControl", "ole32.CoCreateInstance"}},
    PmaCase{"pma-10-03-sys", "Practical Malware Analysis Lab 10-03.sys_",
            {"ntoskrnl.IoCreateDevice", "ntoskrnl.IoDeleteDevice"}},

    // --- pma-11 ---
    PmaCase{"pma-11-01-exe", "Practical Malware Analysis Lab 11-01.exe_",
            {"KERNEL32.FindResourceA", "ADVAPI32.RegSetValueExA"},
            {{"msgina32.dll"},
             {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}}},
    PmaCase{"pma-11-02-dll", "Practical Malware Analysis Lab 11-02.dll_",
            {"KERNEL32.CreateToolhelp32Snapshot", "KERNEL32.VirtualProtect",
             "ADVAPI32.RegSetValueExA"},
            {{"C:\\Windows\\system32\\Lab11-02.ini"},
             {"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"}},
            {}, {}, {}, profile_pma_1102_deep},
    PmaCase{"pma-11-03-dll", "Practical Malware Analysis Lab 11-03.dll_",
            {"KERNEL32.CreateThread", "USER32.GetAsyncKeyState", "KERNEL32.Sleep"},
            {{"C:\\WINDOWS\\System32\\kernel64x.dll"}},
            {}, {"max_api_count"}, {}, profile_pma_1103_dll},
    PmaCase{"pma-11-03-exe", "Practical Malware Analysis Lab 11-03.exe_",
            {"KERNEL32.CopyFileA", "KERNEL32.ExitProcess"}, {}, {}, {}, {},
            profile_pma_1103_exe_missing_source},

    // --- pma-12 ---
    PmaCase{"pma-12-01-dll", "Practical Malware Analysis Lab 12-01.dll_",
            {"KERNEL32.TlsAlloc", "KERNEL32.InitializeCriticalSection"}, {},
            {}, {"max_api_count"}},
    PmaCase{"pma-12-01-exe", "Practical Malware Analysis Lab 12-01.exe_",
            {"psapi.EnumProcesses", "KERNEL32.CreateRemoteThread", "kernel32.LoadLibraryA"},
            {}, {}, {}, {}, profile_pma_1201_deep},
    PmaCase{"pma-12-02-exe", "Practical Malware Analysis Lab 12-02.exe_",
            {"KERNEL32.CreateProcessA", "KERNEL32.ResumeThread",
             "ntdll.NtUnmapViewOfSection"},
            {}, {}, {"invalid_fetch"}, {}, profile_pma_1202_deep},
    PmaCase{"pma-12-03-exe", "Practical Malware Analysis Lab 12-03.exe_",
            {"USER32.SetWindowsHookExA", "USER32.CallNextHookEx",
             "USER32.UnhookWindowsHookEx"},
            {{"practicalmalwareanalysis.log"}}, {}, {}, {},
            profile_pma_1203_deep},
    PmaCase{"pma-12-04-exe", "Practical Malware Analysis Lab 12-04.exe_",
            {"KERNEL32.CreateRemoteThread", "KERNEL32.WinExec",
             "sfc_os.SfcTerminateWatcherThread"}, {}, {}, {}, {},
            profile_pma_1204_deep},

    // --- pma-14 ---
    PmaCase{"pma-14-01-exe", "Practical Malware Analysis Lab 14-01.exe_",
            {"ADVAPI32.GetCurrentHwProfileA", "urlmon.URLDownloadToCacheFileA"},
            {{"C:\\Windows\\Temp\\a.png"}, {}, {"www.practicalmalwareanalysis.com"}}},
    PmaCase{"pma-14-02-exe", "Practical Malware Analysis Lab 14-02.exe_",
            {"KERNEL32.CreatePipe", "SHELL32.ShellExecuteExA", "SHELL32.SHChangeNotify"},
            {}, {}, {"max_api_count"}, {}, profile_pma_1402},

    // --- pma-16 ---
    PmaCase{"pma-16-01-exe", "Practical Malware Analysis Lab 16-01.exe_",
            {"KERNEL32.GetVersionExA", "KERNEL32.GetCommandLineA"}},
    PmaCase{"pma-16-02-exe", "Practical Malware Analysis Lab 16-02.exe_",
            {"USER32.FindWindowA", "KERNEL32.CreateThread"}},
    PmaCase{"pma-16-03-exe", "Practical Malware Analysis Lab 16-03.exe_",
            {"KERNEL32.GetVersionExA", "KERNEL32.ExitProcess"}, {}, {}, {}, {},
            profile_pma_1603},

    // --- pma-17 ---
    PmaCase{"pma-17-02-dll", "Practical Malware Analysis Lab 17-02.dll_",
            {"KERNEL32.CreateThread", "MSVCRT._strtime"},
            {{"C:\\Windows\\system32\\Practical Malware Analysis Lab 17-02.dll_"},
             {"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\Irmon"}},
            {}, {"max_api_count", "invalid_read"}, {}, profile_pma_1702},
    PmaCase{"pma-17-03-exe", "Practical Malware Analysis Lab 17-03.exe_",
            {"MSVCRT.__getmainargs", "KERNEL32.LoadLibraryA"},
            {{}, {"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses"}}},

    // --- pma-18 ---
    PmaCase{"pma-18-01-exe", "Practical Malware Analysis Lab 18-01.exe_",
            {"KERNEL32.LoadLibraryA", "KERNEL32.GetProcAddress"}},
    PmaCase{"pma-18-03-exe", "Practical Malware Analysis Lab 18-03.exe_",
            {"KERNEL32.VirtualAlloc", "KERNEL32.GetProcAddress"}},

    // --- pma-19 ---
    PmaCase{"pma-19-02-exe", "Practical Malware Analysis Lab 19-02.exe_",
            {"KERNEL32.GetVersionExA", "KERNEL32.GetStartupInfoA"},
            {{}, {"HKEY_CLASSES_ROOT\\http\\shell\\open\\command"}}},

    // --- pma-20 ---
    PmaCase{"pma-20-02-exe", "Practical Malware Analysis Lab 20-02.exe_",
            {"KERNEL32.VirtualAlloc", "KERNEL32.GetStartupInfoA"}},

    // --- pma-21 ---
    PmaCase{"pma-21-01-exe", "Practical Malware Analysis Lab 21-01.exe_",
            {"KERNEL32.GetTickCount", "KERNEL32.EncodePointer"}},
};

// ---------------------------------------------------------------------------
// Build the set of cases to actually run
// ---------------------------------------------------------------------------
static std::vector<PmaCase> get_cases_to_run() {
    const char* full_env = std::getenv("SPEAKEASY_PMA_FULL");
    bool run_full = (full_env && std::string(full_env) == "1");

    if (run_full) return PMA_CASES;

    std::vector<PmaCase> selected;
    for (auto& c : PMA_CASES) {
        if (CURATED_CASE_NAMES.count(c.name))
            selected.push_back(c);
    }
    return selected;
}

// ---------------------------------------------------------------------------
// Sanitize test name for GoogleTest (replace '-' and '.' with '_')
// ---------------------------------------------------------------------------
static std::string sanitize_name(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '-' || c == '.') out += '_';
        else out += c;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Parameterized test
// ---------------------------------------------------------------------------
class PmaSampleTest : public ::testing::TestWithParam<PmaCase> {};

TEST_P(PmaSampleTest, DeclarativeCase) {
    auto& case_ = GetParam();

    // Resolve sample path
    fs::path sample_path = get_sample_path(case_);
    if (!fs::exists(sample_path)) {
        GTEST_SKIP() << "missing sample: " << sample_path.string()
                      << " -- run: git submodule update --init --recursive";
    }

    // Set up a temporary directory for profiles that need one
    fs::path tmp_path = fs::temp_directory_path() / ("speakeasy_pma_" + sanitize_name(case_.name));
    std::error_code ec;
    fs::create_directories(tmp_path, ec);

    speakeasy::SpeakeasyConfig cfg;
    speakeasy::Report report;
    try {
        report = run_case(case_, tmp_path, cfg);
    } catch (const std::exception& e) {
        fs::remove_all(tmp_path, ec);
        FAIL() << "case " << case_.name << " threw exception: " << e.what();
    }

    fs::remove_all(tmp_path, ec);
    ObservedBehavior observed = collect_behavior(report);
    assert_case(case_, report, observed);
}

// ---------------------------------------------------------------------------
// Instantiate
// ---------------------------------------------------------------------------
static auto g_pma_cases = get_cases_to_run();

INSTANTIATE_TEST_SUITE_P(
    PmaSamples,
    PmaSampleTest,
    ::testing::ValuesIn(g_pma_cases),
    [](const ::testing::TestParamInfo<PmaCase>& info) { return sanitize_name(info.param.name); });
