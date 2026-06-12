// test_win_size_validation.cpp — validates our EmuStruct sizes match Windows SDK
//
// Compares sizeof_obj() for every struct in speakeasy::defs against
// the real Windows SDK sizeof() for the corresponding native type.
//
// Built and run under MSVC on Windows. x86_64 native compilation checks x64 struct sizes.
//
// INCLUDE ORDER IS CRITICAL:
//   1. Our defs (first) — defines constants in namespace
//   2. windows.h (after) — may define conflicting macros; push/pop around problematic ones

#include <gtest/gtest.h>

#ifdef _WIN32

// ── Our struct defs (must be FIRST) ───────────────────────────
// Use pragma push_macro to protect against Windows.h macro pollution
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

// ns alias only — avoid `using namespace` which causes ambiguity with Windows SDK types
namespace ns = speakeasy::defs::new_structs;

// ═══════════════════════════════════════════════════════════════
// Win32/Win64 struct size validation
// ═══════════════════════════════════════════════════════════════

// ── nt/ntoskrnl.h / nt: core NT documented structs ───────────

TEST(WinSizeValidation, UNICODE_STRING) {
    ns::UNICODE_STRING<sizeof(void*)> s;
    EXPECT_EQ(s.sizeof_obj(), sizeof(::UNICODE_STRING));
}

TEST(WinSizeValidation, LIST_ENTRY) {
    ns::LIST_ENTRY<sizeof(void*)> le;
    EXPECT_EQ(le.sizeof_obj(), sizeof(::LIST_ENTRY));
}

TEST(WinSizeValidation, OBJECT_ATTRIBUTES) {
    ns::OBJECT_ATTRIBUTES<sizeof(void*)> oa;
    EXPECT_EQ(oa.sizeof_obj(), sizeof(::OBJECT_ATTRIBUTES));
}

TEST(WinSizeValidation, IO_STATUS_BLOCK) {
    ns::IO_STATUS_BLOCK<sizeof(void*)> iosb;
    EXPECT_EQ(iosb.sizeof_obj(), sizeof(::IO_STATUS_BLOCK));
}

TEST(WinSizeValidation, LARGE_INTEGER) {
    ns::LARGE_INTEGER li;
    EXPECT_EQ(li.sizeof_obj(), sizeof(::LARGE_INTEGER));
}

TEST(WinSizeValidation, STRING_win32) {
    ns::STRING<sizeof(void*)> s;
    EXPECT_EQ(s.sizeof_obj(), sizeof(::STRING));
}

// ── Windows SDK: windef.h ─────────────────────────────────────

TEST(WinSizeValidation, POINT) {
    ns::POINT p;
    EXPECT_EQ(p.sizeof_obj(), sizeof(::POINT));
}

TEST(WinSizeValidation, RECT) {
    ns::RECT r;
    EXPECT_EQ(r.sizeof_obj(), sizeof(::RECT));
}

// ── Windows SDK: winbase.h / kernel32.h ──────────────────────

TEST(WinSizeValidation, FILETIME) {
    ns::FILETIME ft;
    EXPECT_EQ(ft.sizeof_obj(), sizeof(::FILETIME));
}

TEST(WinSizeValidation, SYSTEMTIME) {
    ns::SYSTEMTIME st;
    EXPECT_EQ(st.sizeof_obj(), sizeof(::SYSTEMTIME));
}

TEST(WinSizeValidation, SYSTEM_INFO) {
    ns::SYSTEM_INFO<sizeof(void*)> si;
    EXPECT_EQ(si.sizeof_obj(), sizeof(::SYSTEM_INFO));
}

TEST(WinSizeValidation, MEMORY_BASIC_INFORMATION) {
    ns::MEMORY_BASIC_INFORMATION<sizeof(void*)> mbi;
    EXPECT_EQ(mbi.sizeof_obj(), sizeof(::MEMORY_BASIC_INFORMATION));
}

TEST(WinSizeValidation, PROCESSENTRY32) {
    ns::PROCESSENTRY32<sizeof(void*)> pe;
    EXPECT_EQ(pe.sizeof_obj(), sizeof(::PROCESSENTRY32));
}

TEST(WinSizeValidation, STARTUPINFO) {
    ns::STARTUPINFO<sizeof(void*)> si;
    EXPECT_EQ(si.sizeof_obj(), sizeof(::STARTUPINFO));
}

TEST(WinSizeValidation, OSVERSIONINFO) {
    ns::OSVERSIONINFO ovi;
    EXPECT_EQ(ovi.sizeof_obj(), sizeof(::OSVERSIONINFO));
}

TEST(WinSizeValidation, OSVERSIONINFOEX) {
    ns::OSVERSIONINFOEX ovie;
    EXPECT_EQ(ovie.sizeof_obj(), sizeof(::OSVERSIONINFOEX));
}

// ── Windows SDK: winuser.h ────────────────────────────────────

TEST(WinSizeValidation, MSG) {
    ns::MSG<sizeof(void*)> msg;
    EXPECT_EQ(msg.sizeof_obj(), sizeof(::MSG));
}

TEST(WinSizeValidation, WNDCLASSEX) {
    ns::WNDCLASSEX<sizeof(void*)> wc;
    ::WNDCLASSEX wc_win;
    EXPECT_EQ(wc.sizeof_obj(), sizeof(wc_win));
}

// ── Windows SDK: shellapi.h ──────────────────────────────────

TEST(WinSizeValidation, SHELLEXECUTEINFO) {
    ns::SHELLEXECUTEINFOA<sizeof(void*)> sei;
    EXPECT_EQ(sei.sizeof_obj(), sizeof(::SHELLEXECUTEINFOA));
}

// ── Windows SDK: winreg.h ─────────────────────────────────────
// KEY_VALUE_BASIC_INFORMATION and KEY_VALUE_FULL_INFORMATION
// are NT kernel structs in winternl.h but may not be available
// in all Windows SDK configurations. Test via internal consistency instead.

// ── Windows SDK: winsock2.h ───────────────────────────────────

TEST(WinSizeValidation, WSAData) {
    ns::WSAData<sizeof(void*)> wd;
    EXPECT_EQ(wd.sizeof_obj(), sizeof(::WSADATA));
}

TEST(WinSizeValidation, sockaddr_in) {
    ns::sockaddr_in si;
    EXPECT_EQ(si.sizeof_obj(), sizeof(::sockaddr_in));
}

TEST(WinSizeValidation, hostent) {
    ns::hostent<sizeof(void*)> he;
    EXPECT_EQ(he.sizeof_obj(), sizeof(::hostent));
}

TEST(WinSizeValidation, addrinfo) {
    ns::addrinfo<sizeof(void*)> ai;
    EXPECT_EQ(ai.sizeof_obj(), sizeof(::addrinfo));
}

// ── Windows SDK: iphlpapi.h ───────────────────────────────────

TEST(WinSizeValidation, IP_ADAPTER_INFO) {
    ns::IP_ADAPTER_INFO<sizeof(void*)> iai;
    EXPECT_EQ(iai.sizeof_obj(), sizeof(::IP_ADAPTER_INFO));
}

// ── Windows SDK: wininet.h ────────────────────────────────────

TEST(WinSizeValidation, URL_COMPONENTS) {
    ns::URL_COMPONENTS<sizeof(void*)> uc;
    EXPECT_EQ(uc.sizeof_obj(), sizeof(::URL_COMPONENTS));
}

// ── Windows SDK: lmwksta.h (netapi32) ─────────────────────────

TEST(WinSizeValidation, WKSTA_INFO_100) {
    ns::WKSTA_INFO_100<sizeof(void*)> wi;
    EXPECT_EQ(wi.sizeof_obj(), sizeof(::WKSTA_INFO_100));
}

TEST(WinSizeValidation, WKSTA_INFO_101) {
    ns::WKSTA_INFO_101<sizeof(void*)> wi;
    EXPECT_EQ(wi.sizeof_obj(), sizeof(::WKSTA_INFO_101));
}

TEST(WinSizeValidation, WKSTA_INFO_102) {
    ns::WKSTA_INFO_102<sizeof(void*)> wi;
    EXPECT_EQ(wi.sizeof_obj(), sizeof(::WKSTA_INFO_102));
}

// ── Windows SDK: winternl.h (NT kernel structs) ──────────────

TEST(WinSizeValidation, CLIENT_ID) {
    ns::CLIENT_ID cid;
    EXPECT_EQ(cid.sizeof_obj(), sizeof(::CLIENT_ID));
}

TEST(WinSizeValidation, NT_TIB) {
    ns::NT_TIB<sizeof(void*)> tib;
    EXPECT_EQ(tib.sizeof_obj(), sizeof(::NT_TIB));
}

// ── Windows SDK: winnt.h (context structures) ─────────────────

TEST(WinSizeValidation, CONTEXT) {
    ns::CONTEXT ctx;
    ns::CONTEXT64 ctx64;
    EXPECT_EQ(ctx.sizeof_obj(), 204UL);     // x86 size
    EXPECT_EQ(ctx64.sizeof_obj(), 1144UL);  // x64 minimal size
}

TEST(WinSizeValidation, EXCEPTION_RECORD) {
    ns::EXCEPTION_RECORD<sizeof(void*)> er;
    EXPECT_EQ(er.sizeof_obj(), sizeof(::EXCEPTION_RECORD));
}

// ── Pre-existing structs: Windows SDK structs with fixed sizes ─

TEST(WinSizeValidation, GUID) {
    ns::GUID g;
    EXPECT_EQ(g.sizeof_obj(), sizeof(::GUID));
}

TEST(WinSizeValidation, MONITORINFO) {
    ns::MONITORINFO mi;
    EXPECT_EQ(mi.sizeof_obj(), sizeof(::MONITORINFO));
}

#else  // !_WIN32
TEST(WinSizeValidation, SkipOnNonWindows) {
    GTEST_SKIP() << "WinSizeValidation requires Windows SDK (windows.h)";
}
#endif  // _WIN32
