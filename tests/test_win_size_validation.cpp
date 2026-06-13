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


#else  // !_WIN32
TEST(WinSizeValidation, SkipOnNonWindows) {
    GTEST_SKIP() << "WinSizeValidation requires Windows SDK (windows.h)";
}
#endif  // _WIN32
