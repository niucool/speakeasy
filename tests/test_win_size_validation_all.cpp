// test_win_size_validation_all.cpp — validates ALL our EmuStruct sizes match Windows SDK
//
// Comprehensive: compares sizeof_obj() for EVERY struct in speakeasy::defs
// against the real Windows SDK sizeof() for the corresponding native type.
//
// NOTE: Skips structs without direct Windows SDK equivalents:
//   - Undocumented NT kernel structs (EPROCESS, ETHREAD, TEB, PEB, IRP, FILE_OBJECT, etc.)
//   - WDF/WSK structs (framework internal)
//   - COM interface vtables
//   - USB descriptor structs (USB standard, not Windows structs)
//   - CONTEXT/CONTEXT64 (our x86 layout differs from native x64 CONTEXT)
//   - NDIS structs beyond NDIS_OBJECT_HEADER (require WDK)
//   - FWPM structs (require fwpmk.h from WDK)
//   - KEVENT, KIDTENTRY, KIDTENTRY64 (kernel structs, not in SDK headers)
//   - FILE_STANDARD_INFORMATION, KEY_VALUE_PARTIAL_INFORMATION (ntddk.h, WDK)
//   - FLOATING_SAVE_AREA (x86 only, not defined on x64 builds)
//   - EXCEPTION_REGISTRATION (SEH internal, not in SDK headers)
//
// INCLUDE ORDER: our defs FIRST, then Windows SDK headers.

#include <gtest/gtest.h>

#ifdef _WIN32

// ── Our struct defs (must be FIRST) ───────────────────────────
#pragma push_macro("DELETE")
#pragma push_macro("READ_CONTROL")
#pragma push_macro("WRITE_DAC")
#pragma push_macro("WRITE_OWNER")
#pragma push_macro("SYNCHRONIZE")
#pragma push_macro("GENERIC_READ")
#pragma push_macro("GENERIC_WRITE")
#pragma push_macro("GENERIC_EXECUTE")
#pragma push_macro("GENERIC_ALL")
#pragma push_macro("STATUS_SUCCESS")
#pragma push_macro("STATUS_BREAKPOINT")
#pragma push_macro("STATUS_SINGLE_STEP")
#pragma push_macro("STATUS_ACCESS_VIOLATION")
#pragma push_macro("STATUS_INVALID_HANDLE")
#pragma push_macro("STATUS_INVALID_PARAMETER")
#pragma push_macro("STATUS_UNSUCCESSFUL")
#pragma push_macro("STATUS_INFO_LENGTH_MISMATCH")
#pragma push_macro("STATUS_BUFFER_TOO_SMALL")
#pragma push_macro("STATUS_NOT_SUPPORTED")
#pragma push_macro("STATUS_OBJECT_NAME_NOT_FOUND")
#pragma push_macro("STATUS_PROCEDURE_NOT_FOUND")
#pragma push_macro("STATUS_OBJECT_TYPE_MISMATCH")
#pragma push_macro("NonPagedPool")
#pragma push_macro("PagedPool")
#pragma push_macro("FILE_ATTRIBUTE_READONLY")
#pragma push_macro("FILE_ATTRIBUTE_HIDDEN")
#pragma push_macro("FILE_ATTRIBUTE_DIRECTORY")
#pragma push_macro("FILE_ATTRIBUTE_NORMAL")

#include "winenv/deffs/nt/ntoskrnl.h"
#include "winenv/deffs/nt/ddk.h"
#include "winenv/deffs/registry/reg.h"
#include "winenv/deffs/usb.h"
#include "winenv/deffs/wdf.h"
#include "winenv/deffs/wsk.h"
#include "winenv/deffs/wininet.h"
#include "winenv/deffs/ndis/ndis.h"
#include "winenv/deffs/wfp/fwpmtypes.h"
#include "winenv/deffs/winsock/ws2_32.h"
#include "winenv/deffs/winsock/winsock.h"
#include "winenv/deffs/windows/windef.h"
#include "winenv/deffs/windows/kernel32.h"
#include "winenv/deffs/windows/user32.h"
#include "winenv/deffs/windows/shell32.h"
#include "winenv/deffs/windows/advapi32.h"
#include "winenv/deffs/windows/iphlpapi.h"
#include "winenv/deffs/windows/netapi32.h"
#include "winenv/deffs/windows/windows.h"
#include "winenv/deffs/windows/com.h"

#pragma pop_macro("DELETE")
#pragma pop_macro("READ_CONTROL")
#pragma pop_macro("WRITE_DAC")
#pragma pop_macro("WRITE_OWNER")
#pragma pop_macro("SYNCHRONIZE")
#pragma pop_macro("GENERIC_READ")
#pragma pop_macro("GENERIC_WRITE")
#pragma pop_macro("GENERIC_EXECUTE")
#pragma pop_macro("GENERIC_ALL")
#pragma pop_macro("STATUS_SUCCESS")
#pragma pop_macro("STATUS_BREAKPOINT")
#pragma pop_macro("STATUS_SINGLE_STEP")
#pragma pop_macro("STATUS_ACCESS_VIOLATION")
#pragma pop_macro("STATUS_INVALID_HANDLE")
#pragma pop_macro("STATUS_INVALID_PARAMETER")
#pragma pop_macro("STATUS_UNSUCCESSFUL")
#pragma pop_macro("STATUS_INFO_LENGTH_MISMATCH")
#pragma pop_macro("STATUS_BUFFER_TOO_SMALL")
#pragma pop_macro("STATUS_NOT_SUPPORTED")
#pragma pop_macro("STATUS_OBJECT_NAME_NOT_FOUND")
#pragma pop_macro("STATUS_PROCEDURE_NOT_FOUND")
#pragma pop_macro("STATUS_OBJECT_TYPE_MISMATCH")
#pragma pop_macro("NonPagedPool")
#pragma pop_macro("PagedPool")
#pragma pop_macro("FILE_ATTRIBUTE_READONLY")
#pragma pop_macro("FILE_ATTRIBUTE_HIDDEN")
#pragma pop_macro("FILE_ATTRIBUTE_DIRECTORY")
#pragma pop_macro("FILE_ATTRIBUTE_NORMAL")

// ── Windows SDK headers ───────────────────────────────────────
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <winuser.h>
#include <winbase.h>
#include <winnt.h>
#include <ws2def.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <winreg.h>
#include <wininet.h>
#include <lmwksta.h>
#include <ntddndis.h>

namespace ns = speakeasy::defs::new_structs;

#define CHECK_SIZE(suite, our_obj, win_type) \
    do { \
        auto ___our = (our_obj).sizeof_obj(); \
        auto ___win = sizeof(win_type); \
        EXPECT_EQ(___our, ___win) \
            << "  " << suite << ": our=" << ___our << " win=" << ___win; \
    } while(0)

// ═══════════════════════════════════════════════════════════════
// STRUCT SIZE VALIDATION
// ═══════════════════════════════════════════════════════════════

// ── nt/ntoskrnl.h / nt: core NT documented structs ───────────

TEST(WinSizeAll, UNICODE_STRING)     { CHECK_SIZE("UNICODE_STRING", ns::UNICODE_STRING<sizeof(void*)>(), ::UNICODE_STRING); }
TEST(WinSizeAll, LIST_ENTRY)         { CHECK_SIZE("LIST_ENTRY", ns::LIST_ENTRY<sizeof(void*)>(), ::LIST_ENTRY); }
TEST(WinSizeAll, OBJECT_ATTRIBUTES)  { CHECK_SIZE("OBJECT_ATTRIBUTES", ns::OBJECT_ATTRIBUTES<sizeof(void*)>(), ::OBJECT_ATTRIBUTES); }
TEST(WinSizeAll, IO_STATUS_BLOCK)    { CHECK_SIZE("IO_STATUS_BLOCK", ns::IO_STATUS_BLOCK<sizeof(void*)>(), ::IO_STATUS_BLOCK); }
TEST(WinSizeAll, LARGE_INTEGER)      { CHECK_SIZE("LARGE_INTEGER", ns::LARGE_INTEGER(), ::LARGE_INTEGER); }
TEST(WinSizeAll, STRING)             { CHECK_SIZE("STRING", ns::STRING<sizeof(void*)>(), ::STRING); }
TEST(WinSizeAll, CLIENT_ID)          { CHECK_SIZE("CLIENT_ID", ns::CLIENT_ID(), ::CLIENT_ID); }
TEST(WinSizeAll, NT_TIB)             { CHECK_SIZE("NT_TIB", ns::NT_TIB<sizeof(void*)>(), ::NT_TIB); }
TEST(WinSizeAll, SYSTEM_TIMEOFDAY_INFORMATION) { CHECK_SIZE("SYSTEM_TIMEOFDAY_INFORMATION", ns::SYSTEM_TIMEOFDAY_INFORMATION(), ::SYSTEM_TIMEOFDAY_INFORMATION); }
TEST(WinSizeAll, RTL_OSVERSIONINFOW) { CHECK_SIZE("RTL_OSVERSIONINFOW", ns::RTL_OSVERSIONINFOW(), ::RTL_OSVERSIONINFOW); }
TEST(WinSizeAll, RTL_OSVERSIONINFOEXW) { CHECK_SIZE("RTL_OSVERSIONINFOEXW", ns::RTL_OSVERSIONINFOEXW(), ::RTL_OSVERSIONINFOEXW); }

// ── windef.h ──────────────────────────────────────────────────

TEST(WinSizeAll, POINT)      { CHECK_SIZE("POINT", ns::POINT(), ::POINT); }
TEST(WinSizeAll, RECT)       { CHECK_SIZE("RECT", ns::RECT(), ::RECT); }
TEST(WinSizeAll, MONITORINFO){ CHECK_SIZE("MONITORINFO", ns::MONITORINFO(), ::MONITORINFO); }

// ── kernel32.h ────────────────────────────────────────────────

TEST(WinSizeAll, FILETIME)                      { CHECK_SIZE("FILETIME", ns::FILETIME(), ::FILETIME); }
TEST(WinSizeAll, SYSTEMTIME)                    { CHECK_SIZE("SYSTEMTIME", ns::SYSTEMTIME(), ::SYSTEMTIME); }
TEST(WinSizeAll, SYSTEM_INFO)                   { CHECK_SIZE("SYSTEM_INFO", ns::SYSTEM_INFO<sizeof(void*)>(), ::SYSTEM_INFO); }
TEST(WinSizeAll, MEMORY_BASIC_INFORMATION)      { CHECK_SIZE("MEMORY_BASIC_INFORMATION", ns::MEMORY_BASIC_INFORMATION<sizeof(void*)>(), ::MEMORY_BASIC_INFORMATION); }
TEST(WinSizeAll, PROCESSENTRY32)                { CHECK_SIZE("PROCESSENTRY32", ns::PROCESSENTRY32<sizeof(void*)>(), ::PROCESSENTRY32); }
TEST(WinSizeAll, THREADENTRY32)                 { CHECK_SIZE("THREADENTRY32", ns::THREADENTRY32(), ::THREADENTRY32); }
TEST(WinSizeAll, MODULEENTRY32)                 { CHECK_SIZE("MODULEENTRY32", ns::MODULEENTRY32<sizeof(void*)>(), ::MODULEENTRY32); }
TEST(WinSizeAll, PROCESS_INFORMATION)           { CHECK_SIZE("PROCESS_INFORMATION", ns::PROCESS_INFORMATION<sizeof(void*)>(), ::PROCESS_INFORMATION); }
TEST(WinSizeAll, WIN32_FIND_DATA)               { CHECK_SIZE("WIN32_FIND_DATA", ns::WIN32_FIND_DATA(), ::WIN32_FIND_DATA); }
TEST(WinSizeAll, WIN32_FILE_ATTRIBUTE_DATA)     { CHECK_SIZE("WIN32_FILE_ATTRIBUTE_DATA", ns::WIN32_FILE_ATTRIBUTE_DATA(), ::WIN32_FILE_ATTRIBUTE_DATA); }
TEST(WinSizeAll, STARTUPINFO)                   { CHECK_SIZE("STARTUPINFO", ns::STARTUPINFO<sizeof(void*)>(), ::STARTUPINFO); }
TEST(WinSizeAll, OSVERSIONINFO)                 { CHECK_SIZE("OSVERSIONINFO", ns::OSVERSIONINFO(), ::OSVERSIONINFO); }
TEST(WinSizeAll, OSVERSIONINFOEX)               { CHECK_SIZE("OSVERSIONINFOEX", ns::OSVERSIONINFOEX(), ::OSVERSIONINFOEX); }

// ── user32.h ──────────────────────────────────────────────────

TEST(WinSizeAll, MSG)               { CHECK_SIZE("MSG", ns::MSG<sizeof(void*)>(), ::MSG); }
TEST(WinSizeAll, WNDCLASSEX)        { CHECK_SIZE("WNDCLASSEX", ns::WNDCLASSEX<sizeof(void*)>(), ::WNDCLASSEX); }
TEST(WinSizeAll, KBDLLHOOKSTRUCT)   { CHECK_SIZE("KBDLLHOOKSTRUCT", ns::KBDLLHOOKSTRUCT<sizeof(void*)>(), ::KBDLLHOOKSTRUCT); }
TEST(WinSizeAll, USEROBJECTFLAGS)   { CHECK_SIZE("USEROBJECTFLAGS", ns::USEROBJECTFLAGS(), ::USEROBJECTFLAGS); }

// ── shell32.h ─────────────────────────────────────────────────

TEST(WinSizeAll, SHELLEXECUTEINFOA) { CHECK_SIZE("SHELLEXECUTEINFOA", ns::SHELLEXECUTEINFOA<sizeof(void*)>(), ::SHELLEXECUTEINFOA); }

// ── advapi32.h ────────────────────────────────────────────────

TEST(WinSizeAll, SERVICE_TABLE_ENTRY) { CHECK_SIZE("SERVICE_TABLE_ENTRY", ns::SERVICE_TABLE_ENTRY<sizeof(void*)>(), ::SERVICE_TABLE_ENTRYA); }

// ── iphlpapi.h ────────────────────────────────────────────────

TEST(WinSizeAll, IP_ADDR_STRING)  { CHECK_SIZE("IP_ADDR_STRING", ns::IP_ADDR_STRING<sizeof(void*)>(), ::IP_ADDR_STRING); }
TEST(WinSizeAll, IP_ADAPTER_INFO) { CHECK_SIZE("IP_ADAPTER_INFO", ns::IP_ADAPTER_INFO<sizeof(void*)>(), ::IP_ADAPTER_INFO); }

// ── netapi32.h ────────────────────────────────────────────────

TEST(WinSizeAll, WKSTA_INFO_100)  { CHECK_SIZE("WKSTA_INFO_100", ns::WKSTA_INFO_100<sizeof(void*)>(), ::WKSTA_INFO_100); }
TEST(WinSizeAll, WKSTA_INFO_101)  { CHECK_SIZE("WKSTA_INFO_101", ns::WKSTA_INFO_101<sizeof(void*)>(), ::WKSTA_INFO_101); }
TEST(WinSizeAll, WKSTA_INFO_102)  { CHECK_SIZE("WKSTA_INFO_102", ns::WKSTA_INFO_102<sizeof(void*)>(), ::WKSTA_INFO_102); }

// ── winsock/ws2_32.h ──────────────────────────────────────────

TEST(WinSizeAll, WSAData)         { CHECK_SIZE("WSAData", ns::WSAData<sizeof(void*)>(), ::WSADATA); }
TEST(WinSizeAll, sockaddr_in)     { CHECK_SIZE("sockaddr_in", ns::sockaddr_in(), ::sockaddr_in); }
TEST(WinSizeAll, hostent)         { CHECK_SIZE("hostent", ns::hostent<sizeof(void*)>(), ::hostent); }
TEST(WinSizeAll, addrinfo)        { CHECK_SIZE("addrinfo", ns::addrinfo<sizeof(void*)>(), ::addrinfo); }

// ── wininet.h ─────────────────────────────────────────────────

TEST(WinSizeAll, URL_COMPONENTS)  { CHECK_SIZE("URL_COMPONENTS", ns::URL_COMPONENTS<sizeof(void*)>(), ::URL_COMPONENTS); }

// ── windows/windows.h: winnt.h structs ────────────────────────

TEST(WinSizeAll, GUID)              { CHECK_SIZE("GUID", ns::GUID(), ::GUID); }
TEST(WinSizeAll, M128A)             { CHECK_SIZE("M128A", ns::M128A(), ::M128A); }
TEST(WinSizeAll, EXCEPTION_RECORD)  { CHECK_SIZE("EXCEPTION_RECORD", ns::EXCEPTION_RECORD<sizeof(void*)>(), ::EXCEPTION_RECORD); }
TEST(WinSizeAll, EXCEPTION_POINTERS){ CHECK_SIZE("EXCEPTION_POINTERS", ns::EXCEPTION_POINTERS<sizeof(void*)>(), ::EXCEPTION_POINTERS); }
TEST(WinSizeAll, SID) {
    // SID has variable SubAuthority — check at least the fixed header portion matches
    auto our = ns::SID().sizeof_obj();
    size_t win_min = sizeof(::SID);
    EXPECT_GE(our, win_min) << "  SID: our=" << our << " win_min=" << win_min;
}

// ── ndis/ndis.h (NDIS_OBJECT_HEADER only — rest needs WDK) ───

TEST(WinSizeAll, NDIS_OBJECT_HEADER) { CHECK_SIZE("NDIS_OBJECT_HEADER", ns::NDIS_OBJECT_HEADER(), ::NDIS_OBJECT_HEADER); }

// ── CONTEXT: special case (our layout is x86, test on x64) ────

TEST(WinSizeAll, CONTEXT) {
    EXPECT_EQ(ns::CONTEXT().sizeof_obj(), 204UL);    // x86 CONTEXT
}
TEST(WinSizeAll, CONTEXT64) {
    EXPECT_EQ(ns::CONTEXT64().sizeof_obj(), 1144UL); // x64 minimal CONTEXT
}

#else  // !_WIN32
TEST(WinSizeAll, SkipOnNonWindows) {
    GTEST_SKIP() << "WinSizeAll requires Windows SDK (windows.h)";
}
#endif  // _WIN32
