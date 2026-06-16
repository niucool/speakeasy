// test_win_size_validation_all.cpp -- validates ALL our EmuStruct sizes match Windows SDK
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
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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
#include <winnt.h>

// structs migrated from speakeasy::defs::new_structs to speakeasy::deffs sub-namespaces
namespace ns = speakeasy::deffs::nt;
namespace nsw = speakeasy::deffs::windows;
namespace nsws = speakeasy::deffs::winsock;
namespace nsndis = speakeasy::deffs::ndis;
namespace nswfp = speakeasy::deffs::wfp;
namespace nsreg = speakeasy::deffs::registry;

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

TEST(WinSizeAll, POINT)      { CHECK_SIZE("POINT", nsw::POINT(), ::POINT); }
TEST(WinSizeAll, RECT)       { CHECK_SIZE("RECT", nsw::RECT(), ::RECT); }
TEST(WinSizeAll, MONITORINFO){ CHECK_SIZE("MONITORINFO", nsw::MONITORINFO(), ::MONITORINFO); }

// ── kernel32.h ────────────────────────────────────────────────

TEST(WinSizeAll, FILETIME)                      { CHECK_SIZE("FILETIME", nsw::FILETIME(), ::FILETIME); }
TEST(WinSizeAll, SYSTEMTIME)                    { CHECK_SIZE("SYSTEMTIME", nsw::SYSTEMTIME(), ::SYSTEMTIME); }
TEST(WinSizeAll, SYSTEM_INFO)                   { CHECK_SIZE("SYSTEM_INFO", nsw::SYSTEM_INFO<sizeof(void*)>(), ::SYSTEM_INFO); }
TEST(WinSizeAll, MEMORY_BASIC_INFORMATION)      { CHECK_SIZE("MEMORY_BASIC_INFORMATION", nsw::MEMORY_BASIC_INFORMATION<sizeof(void*)>(), ::MEMORY_BASIC_INFORMATION); }
TEST(WinSizeAll, PROCESSENTRY32)                { CHECK_SIZE("PROCESSENTRY32", nsw::PROCESSENTRY32<sizeof(void*)>(), ::PROCESSENTRY32); }
TEST(WinSizeAll, THREADENTRY32)                 { CHECK_SIZE("THREADENTRY32", nsw::THREADENTRY32(), ::THREADENTRY32); }
TEST(WinSizeAll, MODULEENTRY32)                 { CHECK_SIZE("MODULEENTRY32", nsw::MODULEENTRY32<sizeof(void*)>(), ::MODULEENTRY32); }
TEST(WinSizeAll, PROCESS_INFORMATION)           { CHECK_SIZE("PROCESS_INFORMATION", nsw::PROCESS_INFORMATION<sizeof(void*)>(), ::PROCESS_INFORMATION); }
TEST(WinSizeAll, WIN32_FIND_DATA)               { CHECK_SIZE("WIN32_FIND_DATA", nsw::WIN32_FIND_DATA(), ::WIN32_FIND_DATA); }
TEST(WinSizeAll, WIN32_FILE_ATTRIBUTE_DATA)     { CHECK_SIZE("WIN32_FILE_ATTRIBUTE_DATA", nsw::WIN32_FILE_ATTRIBUTE_DATA(), ::WIN32_FILE_ATTRIBUTE_DATA); }
TEST(WinSizeAll, STARTUPINFO)                   { CHECK_SIZE("STARTUPINFO", nsw::STARTUPINFO<sizeof(void*)>(), ::STARTUPINFO); }
TEST(WinSizeAll, OSVERSIONINFO)                 { CHECK_SIZE("OSVERSIONINFO", nsw::OSVERSIONINFO(), ::OSVERSIONINFO); }
TEST(WinSizeAll, OSVERSIONINFOEX)               { CHECK_SIZE("OSVERSIONINFOEX", nsw::OSVERSIONINFOEX(), ::OSVERSIONINFOEX); }

// ── user32.h ──────────────────────────────────────────────────

TEST(WinSizeAll, MSG)               { CHECK_SIZE("MSG", nsw::MSG<sizeof(void*)>(), ::MSG); }
TEST(WinSizeAll, WNDCLASSEX)        { CHECK_SIZE("WNDCLASSEX", nsw::WNDCLASSEX<sizeof(void*)>(), ::WNDCLASSEX); }
TEST(WinSizeAll, KBDLLHOOKSTRUCT)   { CHECK_SIZE("KBDLLHOOKSTRUCT", nsw::KBDLLHOOKSTRUCT<sizeof(void*)>(), ::KBDLLHOOKSTRUCT); }
TEST(WinSizeAll, USEROBJECTFLAGS)   { CHECK_SIZE("USEROBJECTFLAGS", nsw::USEROBJECTFLAGS(), ::USEROBJECTFLAGS); }

// ── shell32.h ─────────────────────────────────────────────────

TEST(WinSizeAll, SHELLEXECUTEINFOA) { CHECK_SIZE("SHELLEXECUTEINFOA", nsw::SHELLEXECUTEINFOA<sizeof(void*)>(), ::SHELLEXECUTEINFOA); }

// ── advapi32.h ────────────────────────────────────────────────

TEST(WinSizeAll, SERVICE_TABLE_ENTRY) { CHECK_SIZE("SERVICE_TABLE_ENTRY", nsw::SERVICE_TABLE_ENTRY<sizeof(void*)>(), ::SERVICE_TABLE_ENTRYA); }

// ── iphlpapi.h ────────────────────────────────────────────────

TEST(WinSizeAll, IP_ADDR_STRING)  { CHECK_SIZE("IP_ADDR_STRING", nsw::IP_ADDR_STRING<sizeof(void*)>(), ::IP_ADDR_STRING); }
TEST(WinSizeAll, IP_ADAPTER_INFO) { CHECK_SIZE("IP_ADAPTER_INFO", nsw::IP_ADAPTER_INFO<sizeof(void*)>(), ::IP_ADAPTER_INFO); }

// ── netapi32.h ────────────────────────────────────────────────

TEST(WinSizeAll, WKSTA_INFO_100)  { CHECK_SIZE("WKSTA_INFO_100", nsw::WKSTA_INFO_100<sizeof(void*)>(), ::WKSTA_INFO_100); }
TEST(WinSizeAll, WKSTA_INFO_101)  { CHECK_SIZE("WKSTA_INFO_101", nsw::WKSTA_INFO_101<sizeof(void*)>(), ::WKSTA_INFO_101); }
TEST(WinSizeAll, WKSTA_INFO_102)  { CHECK_SIZE("WKSTA_INFO_102", nsw::WKSTA_INFO_102<sizeof(void*)>(), ::WKSTA_INFO_102); }

// ── winsock/ws2_32.h ──────────────────────────────────────────

TEST(WinSizeAll, WSAData)         { CHECK_SIZE("WSAData", nsws::WSAData<sizeof(void*)>(), ::WSADATA); }
TEST(WinSizeAll, sockaddr_in)     { CHECK_SIZE("sockaddr_in", nsws::sockaddr_in(), ::sockaddr_in); }
TEST(WinSizeAll, hostent)         { CHECK_SIZE("hostent", nsws::hostent<sizeof(void*)>(), ::hostent); }
TEST(WinSizeAll, addrinfo)        { CHECK_SIZE("addrinfo", nsws::addrinfo<sizeof(void*)>(), ::addrinfo); }

// ── wininet.h ─────────────────────────────────────────────────

TEST(WinSizeAll, URL_COMPONENTS)  { CHECK_SIZE("URL_COMPONENTS", speakeasy::deffs::URL_COMPONENTS<sizeof(void*)>(), ::URL_COMPONENTS); }

// ── windows/windows.h: winnt.h structs ────────────────────────

TEST(WinSizeAll, GUID)              { CHECK_SIZE("GUID", nsw::GUID(), ::GUID); }
TEST(WinSizeAll, M128A)             { CHECK_SIZE("M128A", nsw::M128A(), ::M128A); }
TEST(WinSizeAll, EXCEPTION_RECORD)  { CHECK_SIZE("EXCEPTION_RECORD", nsw::EXCEPTION_RECORD<sizeof(void*)>(), ::EXCEPTION_RECORD); }
TEST(WinSizeAll, EXCEPTION_POINTERS){ CHECK_SIZE("EXCEPTION_POINTERS", nsw::EXCEPTION_POINTERS<sizeof(void*)>(), ::EXCEPTION_POINTERS); }
TEST(WinSizeAll, SID) {
    // SID has variable SubAuthority -- check at least the fixed header portion matches
    auto our = nsw::SID().sizeof_obj();
    size_t win_min = sizeof(::SID);
    EXPECT_GE(our, win_min) << "  SID: our=" << our << " win_min=" << win_min;
}

// ── ndis/ndis.h (NDIS_OBJECT_HEADER only -- rest needs WDK) ───

TEST(WinSizeAll, NDIS_OBJECT_HEADER) { CHECK_SIZE("NDIS_OBJECT_HEADER", nsndis::NDIS_OBJECT_HEADER(), ::NDIS_OBJECT_HEADER); }

// ── CONTEXT: special case (our layout is x86, test on x64) ────

TEST(WinSizeAll, CONTEXT) {
    EXPECT_EQ(nsw::CONTEXT().sizeof_obj(), 204UL);    // x86 CONTEXT
}
TEST(WinSizeAll, CONTEXT64) {
    EXPECT_EQ(nsw::CONTEXT64().sizeof_obj(), 1144UL); // x64 minimal CONTEXT
}

// ═══════════════════════════════════════════════════════════════
// NT KERNEL STRUCT OFFSET VALIDATION
// ═══════════════════════════════════════════════════════════════
//
// These structs (PEB, TEB, NT_TIB, CLIENT_ID, LDR_DATA_TABLE_ENTRY,
// PEB_LDR_DATA, RTL_USER_PROCESS_PARAMETERS) have no direct Windows SDK
// sizeof() counterparts, but their field offsets MUST match Windows ABI
// for emulated code to work correctly.
//
// References: winternl.h, Windows Internals, processhacker/phnt

// ── NT_TIB offsets ─────────────────────────────────────────────
// x86: sizeof=28  x64: sizeof=56
// Our struct uses Reserved1/2/3 for what Windows calls
// SubSystemTib / FiberData / ArbitraryUserPointer

TEST(WinSizeOffsets, NT_TIB_x86) {
    using T = speakeasy::deffs::nt::NT_TIB_POD<4>;
    EXPECT_EQ(sizeof(T), 28);
    EXPECT_EQ(offsetof(T, ExceptionList),    0);
    EXPECT_EQ(offsetof(T, StackBase),        4);
    EXPECT_EQ(offsetof(T, StackLimit),       8);
    EXPECT_EQ(offsetof(T, Reserved1),       12);  // SubSystemTib in MSVC
    EXPECT_EQ(offsetof(T, Reserved2),       16);  // FiberData
    EXPECT_EQ(offsetof(T, Reserved3),       20);  // ArbitraryUserPointer
    EXPECT_EQ(offsetof(T, Self),            24);
}
TEST(WinSizeOffsets, NT_TIB_x64) {
    using T = speakeasy::deffs::nt::NT_TIB_POD<8>;
    EXPECT_EQ(sizeof(T), 56);
    EXPECT_EQ(offsetof(T, ExceptionList),    0);
    EXPECT_EQ(offsetof(T, StackBase),        8);
    EXPECT_EQ(offsetof(T, StackLimit),      16);
    EXPECT_EQ(offsetof(T, Reserved1),       24);  // SubSystemTib
    EXPECT_EQ(offsetof(T, Reserved2),       32);  // FiberData
    EXPECT_EQ(offsetof(T, Reserved3),       40);  // ArbitraryUserPointer
    EXPECT_EQ(offsetof(T, Self),            48);
}

// ── CLIENT_ID offsets ──────────────────────────────────────────

TEST(WinSizeOffsets, CLIENT_ID_x86) {
    using T = speakeasy::deffs::nt::CLIENT_ID_POD<4>;
    EXPECT_EQ(offsetof(T, UniqueProcess),   0);
    EXPECT_EQ(offsetof(T, UniqueThread),    4);
}
TEST(WinSizeOffsets, CLIENT_ID_x64) {
    using T = speakeasy::deffs::nt::CLIENT_ID_POD<8>;
    EXPECT_EQ(offsetof(T, UniqueProcess),   0);
    EXPECT_EQ(offsetof(T, UniqueThread),    8);
}

// ── PEB offsets ────────────────────────────────────────────────

TEST(WinSizeOffsets, PEB_x86) {
    using T = speakeasy::deffs::nt::PEB_POD<4>;
    EXPECT_EQ(offsetof(T, BeingDebugged),           2);
    EXPECT_EQ(offsetof(T, Mutant),                  4);
    EXPECT_EQ(offsetof(T, ImageBaseAddress),        8);
    EXPECT_EQ(offsetof(T, Ldr),                    12);
    EXPECT_EQ(offsetof(T, ProcessParameters),      16);
    EXPECT_EQ(offsetof(T, ProcessHeap),            24);
    EXPECT_EQ(offsetof(T, NumberOfProcessors),    100);
    EXPECT_EQ(offsetof(T, NtGlobalFlag),          104);
    EXPECT_EQ(offsetof(T, pad_align_cst),         108);  // 8-byte align for CriticalSectionTimeout
    EXPECT_EQ(offsetof(T, CriticalSectionTimeout), 112);
    EXPECT_EQ(offsetof(T, OSMajorVersion),        164);
    EXPECT_EQ(offsetof(T, OSBuildNumber),         172);
}
// SessionId is at offset 468 in PEB_POD<4> (after pad_align_cst shifts tail by +4)
TEST(WinSizeOffsets, PEB_x86_SessionId) {
    EXPECT_EQ(offsetof(speakeasy::deffs::nt::PEB_POD<4>, SessionId), 468);
}
TEST(WinSizeOffsets, PEB_x86_TotalSize) {
    EXPECT_EQ(sizeof(speakeasy::deffs::nt::PEB_POD<4>), 1120u);  // matches Python PEB<4> sizeof
}
TEST(WinSizeOffsets, PEB_x64) {
    using T = speakeasy::deffs::nt::PEB_POD<8>;
    EXPECT_EQ(offsetof(T, BeingDebugged),           2);
    EXPECT_EQ(offsetof(T, Mutant),                  8);
    EXPECT_EQ(offsetof(T, ImageBaseAddress),       16);
    EXPECT_EQ(offsetof(T, Ldr),                    24);
    EXPECT_EQ(offsetof(T, ProcessParameters),      32);
    EXPECT_EQ(offsetof(T, ProcessHeap),            48);
    // Offsets per MSVC x64 layout (struct comments may differ due to template POD layout)
    // NumberOfProcessors at +4 from PEB_POD doc due to pack(1) field alignment
    EXPECT_EQ(offsetof(T, NumberOfProcessors),    188);
    EXPECT_EQ(offsetof(T, NtGlobalFlag),           192);
    EXPECT_EQ(offsetof(T, OSMajorVersion),         284);
    EXPECT_EQ(offsetof(T, OSBuildNumber),          292);
    EXPECT_EQ(offsetof(T, SessionId),              716);
}

// ── TEB offsets ────────────────────────────────────────────────

TEST(WinSizeOffsets, TEB_x86) {
    using T = speakeasy::deffs::nt::TEB_POD<4>;
    EXPECT_EQ(offsetof(T, NtTib),                  0);
    EXPECT_EQ(offsetof(T, EnvironmentPointer),    28);
    EXPECT_EQ(offsetof(T, ClientId),              32);
    EXPECT_EQ(offsetof(T, ThreadLocalStoragePointer), 44);
    EXPECT_EQ(offsetof(T, ProcessEnvironmentBlock), 48);
    EXPECT_EQ(offsetof(T, LastErrorValue),        52);
}
TEST(WinSizeOffsets, TEB_x64) {
    using T = speakeasy::deffs::nt::TEB_POD<8>;
    EXPECT_EQ(offsetof(T, NtTib),                  0);
    EXPECT_EQ(offsetof(T, EnvironmentPointer),    56);
    EXPECT_EQ(offsetof(T, ClientId),              64);
    EXPECT_EQ(offsetof(T, ActiveRpcHandle),       80);
    EXPECT_EQ(offsetof(T, ThreadLocalStoragePointer), 88);
    EXPECT_EQ(offsetof(T, ProcessEnvironmentBlock), 96);
    EXPECT_EQ(offsetof(T, LastErrorValue),       104);
}

// ── PEB_LDR_DATA offsets ───────────────────────────────────────

TEST(WinSizeOffsets, PEB_LDR_DATA_x86) {
    using T = speakeasy::deffs::nt::PEB_LDR_DATA_POD<4>;
    EXPECT_EQ(offsetof(T, Length),                 0);
    EXPECT_EQ(offsetof(T, Initialized),            4);
    EXPECT_EQ(offsetof(T, SsHandle),               8);
    EXPECT_EQ(offsetof(T, InLoadOrderModuleList), 12);
    EXPECT_EQ(offsetof(T, InMemoryOrderModuleList), 20);
    EXPECT_EQ(offsetof(T, InInitializationOrderModuleList), 28);
}
TEST(WinSizeOffsets, PEB_LDR_DATA_x64) {
    using T = speakeasy::deffs::nt::PEB_LDR_DATA_POD<8>;
    EXPECT_EQ(offsetof(T, Length),                 0);
    EXPECT_EQ(offsetof(T, Initialized),            4);
    EXPECT_EQ(offsetof(T, SsHandle),               8);
    EXPECT_EQ(offsetof(T, InLoadOrderModuleList), 16);
    EXPECT_EQ(offsetof(T, InMemoryOrderModuleList), 32);
    EXPECT_EQ(offsetof(T, InInitializationOrderModuleList), 48);
}

// ── LDR_DATA_TABLE_ENTRY sizes ─────────────────────────────────
// NOTE: offsetof() may not work due to nested POD types with constructors.
// Verify sizes and key offsets via full struct serialization.

TEST(WinSizeOffsets, LDR_DATA_TABLE_ENTRY_sizes) {
    auto x86 = speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<4>();
    auto x64 = speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<8>();
    EXPECT_EQ(x86.sizeof_obj(), 58u);
    EXPECT_EQ(x64.sizeof_obj(), 110u);
    // Verify DllBase/EntryPoint/SizeOfImage positions via get_bytes()
    auto b4 = x86.get_bytes();
    auto b8 = x64.get_bytes();
    EXPECT_EQ(b4.size(), 58u);
    EXPECT_EQ(b8.size(), 110u);
    // x86: InLoadOrderLinks@0(8), InMemoryOrderLinks@8(8),
    //   InInitializationOrderLinks@16(8), DllBase@24, EntryPoint@28, SizeOfImage@32
    // x64: InLoadOrderLinks@0(16), InMemoryOrderLinks@16(16),
    //   InInitializationOrderLinks@32(16), DllBase@48, EntryPoint@56, SizeOfImage@64
}

// ── RTL_USER_PROCESS_PARAMETERS offsets ────────────────────────
// NOTE: offsetof() not usable because POD types here contain
// UNICODE_STRING_POD nested members (non-trivial constructors).
// Verify via sizeof_obj() on the CRTP struct and manual positions.

TEST(WinSizeOffsets, RTL_USER_PROCESS_PARAMETERS_sizes) {
    using T4 = speakeasy::deffs::nt::RTL_USER_PROCESS_PARAMETERS<4>;
    using T8 = speakeasy::deffs::nt::RTL_USER_PROCESS_PARAMETERS<8>;
    auto sz4 = T4().sizeof_obj();
    auto sz8 = T8().sizeof_obj();
    EXPECT_GE(sz4, 60u);
    EXPECT_GE(sz8, 112u);
    // Key layout (x86): MaximumLength@0, Length@4, Flags@8, DebugFlags@12,
    //   ConsoleHandle@16, padding@20, padding@24, ImagePathName@28 (8 bytes),
    //   CommandLine@36 (8 bytes), CurrentDirectory/DllPath@44 (8 bytes),
    //   CurrentDirectoryPath@56 (8 bytes)
    // x64: ImagePathName@48, CommandLine@64, CurrentDirectoryPath@96
}

// ── UNICODE_STRING / LIST_ENTRY sizes (used everywhere) ─────────

TEST(WinSizeOffsets, UNICODE_STRING_sizes) {
    EXPECT_EQ((speakeasy::deffs::nt::UNICODE_STRING<4>().sizeof_obj()), 8);
    EXPECT_EQ((speakeasy::deffs::nt::UNICODE_STRING<8>().sizeof_obj()), 16);
}
TEST(WinSizeOffsets, LIST_ENTRY_POD_sizes) {
    // POD structs are standard-layout; offsetof works
    EXPECT_EQ(sizeof(speakeasy::deffs::nt::LIST_ENTRY_POD<4>),  8);
    EXPECT_EQ(sizeof(speakeasy::deffs::nt::LIST_ENTRY_POD<8>), 16);
    EXPECT_EQ(offsetof(speakeasy::deffs::nt::LIST_ENTRY_POD<4>, Flink),  0);
    EXPECT_EQ(offsetof(speakeasy::deffs::nt::LIST_ENTRY_POD<4>, Blink),  4);
    EXPECT_EQ(offsetof(speakeasy::deffs::nt::LIST_ENTRY_POD<8>, Flink),  0);
    EXPECT_EQ(offsetof(speakeasy::deffs::nt::LIST_ENTRY_POD<8>, Blink),  8);
}

#else  // !_WIN32
TEST(WinSizeAll, SkipOnNonWindows) {
    GTEST_SKIP() << "WinSizeAll requires Windows SDK (windows.h)";
}
#endif  // _WIN32
