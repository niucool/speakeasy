// kernel32.cpp  kernel32.dll handler (v2  ~110 APIs, macro-driven)
//
// Maps to: speakeasy/winenv/api/usermode/kernel32.py
//
// Implements core Windows kernel32 APIs with real emulated behavior:
// File I/O, Memory, DLL/Module, Process/Thread, Sync, System,
// Error, String, Environment, Toolhelp, and Console APIs.
//
// Windows error convention: success APIs return 0 (ERROR_SUCCESS),
// or 1 for BOOL success. GetLastError/SetLastError track error codes.

#include "kernel32.h"
#include "../../../helper.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <chrono>
#include <thread>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <unordered_map>

#include "memmgr.h"           // MemoryManager
#include "struct.h"           // speakeasy::write_le, read_le
#include "winenv/arch.h"      // ARCH_X86, ARCH_AMD64
#include "windows/winemu.h"   // WindowsEmulator
#include "windows/win32.h"    // Win32Emulator (set_last_error)
#include "windows/fileman.h"  // File, FileManager
#include "windows/objman.h"   // Process, Thread
#include "winenv/deffs/windows/kernel32.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

//  Typed cast helpers 
static inline int ptr_sz(void* e) {
    return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
}

// Undo Windows macro pollution for our function names
#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif
#ifdef GetStartupInfo
#undef GetStartupInfo
#endif
#ifdef GetSystemDirectory
#undef GetSystemDirectory
#endif
#ifdef GetTempFileName
#undef GetTempFileName
#endif
#ifdef GetTempPath
#undef GetTempPath
#endif
#ifdef GetTimeFormat
#undef GetTimeFormat
#endif
#ifdef GetVolumeInformation
#undef GetVolumeInformation
#endif
#ifdef GetVolumePathNamesForVolumeName
#undef GetVolumePathNamesForVolumeName
#endif
#ifdef GetWindowsDirectory
#undef GetWindowsDirectory
#endif
#ifdef IsBadStringPtr
#undef IsBadStringPtr
#endif
#ifdef IsBadStringPtrA
#undef IsBadStringPtrA
#endif
#ifdef IsBadStringPtrW
#undef IsBadStringPtrW
#endif
#ifdef LCMapString
#undef LCMapString
#endif
#ifdef MoveFile
#undef MoveFile
#endif
#ifdef OpenEvent
#undef OpenEvent
#endif
#ifdef OpenWaitableTimer
#undef OpenWaitableTimer
#endif
#ifdef SetConsoleTitle
#undef SetConsoleTitle
#endif
#ifdef SetDllDirectory
#undef SetDllDirectory
#endif
#ifdef VerifyVersionInfo
#undef VerifyVersionInfo
#endif
#ifdef InterlockedIncrement
#undef InterlockedIncrement
#endif
#ifdef InterlockedDecrement
#undef InterlockedDecrement
#endif
#ifdef LoadLibrary
#undef LoadLibrary
#endif
#ifdef LoadLibraryEx
#undef LoadLibraryEx
#endif
#ifdef CreateFile
#undef CreateFile
#endif
#ifdef CreateProcess
#undef CreateProcess
#endif
#ifdef CopyFile
#undef CopyFile
#endif
#ifdef InterlockedExchange
#undef InterlockedExchange
#endif
#ifdef InterlockedExchangeAdd
#undef InterlockedExchangeAdd
#endif
#ifdef InterlockedCompareExchange
#undef InterlockedCompareExchange
#endif
#ifdef lstrcmpi
#undef lstrcmpi
#endif
#ifdef lstrcpyn
#undef lstrcpyn
#endif
#ifdef AddAtom
#undef AddAtom
#endif
#ifdef CreateMutexEx
#undef CreateMutexEx
#endif
#ifdef CreateNamedPipe
#undef CreateNamedPipe
#endif
#ifdef CreateWaitableTimerEx
#undef CreateWaitableTimerEx
#endif
#ifdef FindAtom
#undef FindAtom
#endif
#ifdef FindFirstFileEx
#undef FindFirstFileEx
#endif
#ifdef FindFirstVolume
#undef FindFirstVolume
#endif
#ifdef FindNextVolume
#undef FindNextVolume
#endif
#ifdef FindResource
#undef FindResource
#endif
#ifdef FindResourceEx
#undef FindResourceEx
#endif
#ifdef FreeEnvironmentStrings
#undef FreeEnvironmentStrings
#endif
#ifdef FreeEnvironmentStringsA
#undef FreeEnvironmentStringsA
#endif
#ifdef FreeEnvironmentStringsW
#undef FreeEnvironmentStringsW
#endif
#ifdef GetEnvironmentStrings
#undef GetEnvironmentStrings
#endif
#ifdef GetEnvironmentStringsA
#undef GetEnvironmentStringsA
#endif
#ifdef GetEnvironmentStringsW
#undef GetEnvironmentStringsW
#endif
#ifdef GetAtomName
#undef GetAtomName
#endif
#ifdef GetBinaryType
#undef GetBinaryType
#endif
#ifdef GetComputerNameEx
#undef GetComputerNameEx
#endif
#ifdef GetConsoleTitle
#undef GetConsoleTitle
#endif
#ifdef GetDateFormat
#undef GetDateFormat
#endif
#ifdef GetFileAttributesEx
#undef GetFileAttributesEx
#endif
#ifdef GetFullPathName
#undef GetFullPathName
#endif
#ifdef GetLocaleInfo
#undef GetLocaleInfo
#endif
#ifdef GetLongPathName
#undef GetLongPathName
#endif
#ifdef GetModuleHandleEx
#undef GetModuleHandleEx
#endif
#ifdef GetProfileInt
#undef GetProfileInt
#endif
#ifdef GetShortPathName
#undef GetShortPathName
#endif
#ifdef GlobalAddAtom
#undef GlobalAddAtom
#endif

//  Windows constants (use K32_ prefix to avoid SDK macro conflicts) 
static constexpr uint32_t K32_ERR_SUCCESS           = 0;
static constexpr uint32_t K32_ERR_FILE_NOT_FOUND    = 2;
static constexpr uint32_t K32_ERR_PATH_NOT_FOUND    = 3;
static constexpr uint32_t K32_ERR_ACCESS_DENIED     = 5;
static constexpr uint32_t K32_ERR_INVALID_HANDLE    = 6;
static constexpr uint32_t K32_ERR_NO_MORE_FILES     = 18;
static constexpr uint32_t K32_ERR_FILE_EXISTS       = 80;
static constexpr uint32_t K32_ERR_INVALID_PARAM     = 87;
static constexpr uint32_t K32_ERR_INSUFFICIENT_BUF  = 122;
static constexpr uint32_t K32_ERR_MOD_NOT_FOUND     = 126;
static constexpr uint32_t K32_ERR_ALREADY_EXISTS    = 183;
static constexpr uint32_t K32_ERR_NO_MORE_ITEMS     = 259;
static constexpr uint32_t K32_ERR_NOT_ENOUGH_MEM    = 8;
static constexpr uint32_t K32_ERR_OUTOFMEMORY       = 14;
static constexpr uint32_t K32_ERR_BAD_ENVIRONMENT   = 10;

static constexpr uint32_t K32_INVALID_HANDLE        = 0xFFFFFFFF;
static constexpr uint32_t K32_INVALID_FILE_ATTR     = 0xFFFFFFFF;
static constexpr uint32_t K32_FILE_ATTR_NORMAL      = 0x80;

static constexpr uint32_t K32_PAGE_NO               = 0x01;
static constexpr uint32_t K32_PAGE_RO               = 0x02;
static constexpr uint32_t K32_PAGE_RW               = 0x04;
static constexpr uint32_t K32_PAGE_EX               = 0x10;
static constexpr uint32_t K32_PAGE_EX_RO            = 0x20;
static constexpr uint32_t K32_PAGE_EX_RW            = 0x40;

static constexpr uint32_t K32_MEM_COMMIT            = 0x1000;
static constexpr uint32_t K32_MEM_RESERVE           = 0x2000;
static constexpr uint32_t K32_MEM_RELEASE           = 0x8000;
static constexpr uint32_t K32_MEM_FREE              = 0x10000;

static constexpr uint32_t K32_CREATE_ALWAYS         = 2;
static constexpr uint32_t K32_CREATE_NEW            = 1;
static constexpr uint32_t K32_OPEN_ALWAYS           = 4;
static constexpr uint32_t K32_OPEN_EXISTING         = 3;
static constexpr uint32_t K32_TRUNCATE_EXISTING     = 5;

static constexpr uint32_t K32_WAIT_OBJECT_0         = 0;
static constexpr uint32_t K32_WAIT_TIMEOUT          = 0x102;
static constexpr uint32_t K32_WAIT_FAILED           = 0xFFFFFFFF;

static constexpr uint32_t K32_TH32CS_SNAPPROCESS    = 0x00000002;
static constexpr uint32_t K32_TH32CS_SNAPTHREAD     = 0x00000004;
static constexpr uint32_t K32_TH32CS_SNAPMODULE     = 0x00000008;
static constexpr uint32_t K32_TH32CS_SNAPALL        = 0x0000000F;

//  Permission conversion helpers 
static inline int win_to_emu_perms(uint32_t win_perms) {
    if (win_perms & K32_PAGE_EX_RW) return PERM_MEM_RWX;
    if (win_perms & K32_PAGE_NO) return PERM_MEM_NONE;
    int p = 0;
    if (win_perms & (K32_PAGE_EX | K32_PAGE_EX_RO))  p |= PERM_MEM_EXEC;
    if (win_perms & (K32_PAGE_EX_RO | K32_PAGE_RO | K32_PAGE_RW)) p |= PERM_MEM_READ;
    if (win_perms & K32_PAGE_RW) p |= PERM_MEM_WRITE;
    return p;
}

//  Snapshot state for Toolhelp 
struct SnapEntry {
    int index;
    std::vector<void*> items;
    int pid;
};
static std::unordered_map<uint64_t, std::unordered_map<uint32_t, SnapEntry>> g_snapshots;
// TODO: g_next_handle not yet used  handle counter tracking incomplete
// static uint64_t g_next_handle = 0x1800; // unused
static uint64_t g_next_snap_handle = 0x2000;

// Win32 macros expand many API names -> undefine before REG table
#ifdef DeleteFile
#undef DeleteFile
#endif
#ifdef CopyFile
#undef CopyFile
#endif
#ifdef CreateDirectory
#undef CreateDirectory
#endif
#ifdef RemoveDirectory
#undef RemoveDirectory
#endif
#ifdef GetFileAttributes
#undef GetFileAttributes
#endif
#ifdef FindFirstFile
#undef FindFirstFile
#endif
#ifdef FindNextFile
#undef FindNextFile
#endif
#ifdef CreateFileMapping
#undef CreateFileMapping
#endif
#ifdef GetDriveType
#undef GetDriveType
#endif
#ifdef GetDiskFreeSpaceEx
#undef GetDiskFreeSpaceEx
#endif
#ifdef GetModuleHandle
#undef GetModuleHandle
#endif
#ifdef GetModuleFileName
#undef GetModuleFileName
#endif
#ifdef CreateEvent
#undef CreateEvent
#endif
#ifdef CreateMutex
#undef CreateMutex
#endif
#ifdef OpenMutex
#undef OpenMutex
#endif
#ifdef CreateWaitableTimer
#undef CreateWaitableTimer
#endif
#ifdef GetVersionEx
#undef GetVersionEx
#endif
#ifdef GetComputerName
#undef GetComputerName
#endif
#ifdef GetUserName
#undef GetUserName
#endif
#ifdef lstrlen
#undef lstrlen
#endif
#ifdef lstrcpy
#undef lstrcpy
#endif
#ifdef lstrcat
#undef lstrcat
#endif
#ifdef lstrcmp
#undef lstrcmp
#endif
#ifdef GetCommandLine
#undef GetCommandLine
#endif
#ifdef GetEnvironmentVariable
#undef GetEnvironmentVariable
#endif
#ifdef SetEnvironmentVariable
#undef SetEnvironmentVariable
#endif
#ifdef GetCurrentDirectory
#undef GetCurrentDirectory
#endif
#ifdef SetCurrentDirectory
#undef SetCurrentDirectory
#endif
#ifdef ExpandEnvironmentStrings
#undef ExpandEnvironmentStrings
#endif
#ifdef OutputDebugString
#undef OutputDebugString
#endif

//  Constructor
Kernel32::Kernel32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Kernel32)
    REG(Kernel32, CreateFile, 7)
    REG(Kernel32, ReadFile, 5)       REG(Kernel32, WriteFile, 5)
    REG(Kernel32, CloseHandle, 1)    REG(Kernel32, DeleteFile, 1)
    REG(Kernel32, CopyFile, 3)
    REG(Kernel32, CreateDirectory, 2) REG(Kernel32, RemoveDirectory, 1)
    REG(Kernel32, GetFileAttributes, 1) REG(Kernel32, SetFilePointer, 4)
    REG(Kernel32, GetFileSize, 2)    REG(Kernel32, FindFirstFile, 2)
    REG(Kernel32, FindNextFile, 2) REG(Kernel32, FindClose, 1)
    REG(Kernel32, CreateFileMapping, 6) REG(Kernel32, MapViewOfFile, 5)
    REG(Kernel32, UnmapViewOfFile, 1) REG(Kernel32, FlushFileBuffers, 1)
    REG(Kernel32, SetEndOfFile, 1)   REG(Kernel32, GetFileTime, 4)
    REG(Kernel32, SetFileTime, 4)    REG(Kernel32, GetFileInformationByHandle, 2)
    REG(Kernel32, DeviceIoControl, 8) REG(Kernel32, GetDriveType, 1)
    REG(Kernel32, GetDiskFreeSpaceEx, 4)
    REG(Kernel32, VirtualAlloc, 4)   REG(Kernel32, VirtualAllocEx, 5)
    REG(Kernel32, VirtualFree, 3)    REG(Kernel32, VirtualProtect, 4)
    REG(Kernel32, VirtualProtectEx, 5) REG(Kernel32, VirtualQuery, 3)
    REG(Kernel32, WriteProcessMemory, 5) REG(Kernel32, ReadProcessMemory, 5)
    REG(Kernel32, HeapAlloc, 3)       REG(Kernel32, HeapFree, 3)
    REG(Kernel32, HeapCreate, 3)     REG(Kernel32, HeapDestroy, 1)
    REG(Kernel32, GetProcessHeap, 0) REG(Kernel32, GlobalAlloc, 2)
    REG(Kernel32, GlobalFree, 1)     REG(Kernel32, LocalAlloc, 2)
    REG(Kernel32, LocalFree, 1)      REG(Kernel32, RtlMoveMemory, 3)
    REG(Kernel32, RtlZeroMemory, 2)
    REG(Kernel32, LoadLibrary, 1)    REG(Kernel32, LoadLibraryEx, 3)
    REG(Kernel32, FreeLibrary, 1)
    REG(Kernel32, GetProcAddress, 2) REG(Kernel32, GetModuleHandle, 1)
    REG(Kernel32, GetModuleFileName, 3)
    REG(Kernel32, DisableThreadLibraryCalls, 1)
    REG(Kernel32, CreateProcess, 10)  REG(Kernel32, OpenProcess, 3)
    REG(Kernel32, TerminateProcess, 2) REG(Kernel32, GetCurrentProcess, 0)
    REG(Kernel32, GetCurrentProcessId, 0) REG(Kernel32, ExitProcess, 1)
    REG(Kernel32, CreateThread, 6)   REG(Kernel32, CreateRemoteThread, 7)
    REG(Kernel32, OpenThread, 3)     REG(Kernel32, TerminateThread, 2)
    REG(Kernel32, GetCurrentThread, 0) REG(Kernel32, GetCurrentThreadId, 0)
    REG(Kernel32, ResumeThread, 1)   REG(Kernel32, SuspendThread, 1)
    REG(Kernel32, ExitThread, 1)     REG(Kernel32, Sleep, 1)
    REG(Kernel32, SleepEx, 2)        REG(Kernel32, SwitchToThread, 0)
    REG(Kernel32, GetExitCodeProcess, 2) REG(Kernel32, GetExitCodeThread, 2)
    REG(Kernel32, QueueUserAPC, 3)   REG(Kernel32, WinExec, 2)
    REG(Kernel32, SetThreadPriority, 2) REG(Kernel32, GetThreadPriority, 1)
    REG(Kernel32, CreateEvent, 4)    REG(Kernel32, CreateMutex, 3)
    REG(Kernel32, OpenMutex, 3) REG(Kernel32, ReleaseMutex, 1)
    REG(Kernel32, SetEvent, 1)       REG(Kernel32, ResetEvent, 1)
    REG(Kernel32, WaitForSingleObject, 2) REG(Kernel32, WaitForMultipleObjects, 4)
    REG(Kernel32, InitializeCriticalSection, 1) REG(Kernel32, DeleteCriticalSection, 1)
    REG(Kernel32, EnterCriticalSection, 1) REG(Kernel32, LeaveCriticalSection, 1)
    REG(Kernel32, CreateWaitableTimer, 3) REG(Kernel32, SetWaitableTimer, 6)
    REG(Kernel32, CancelWaitableTimer, 1)
    REG(Kernel32, GetTickCount, 0)   REG(Kernel32, GetSystemInfo, 1)
    REG(Kernel32, GetVersion, 0)     REG(Kernel32, GetVersionEx, 1)
    REG(Kernel32, IsDebuggerPresent, 0) REG(Kernel32, SetErrorMode, 1)
    REG(Kernel32, GetSystemTime, 1)  REG(Kernel32, GetLocalTime, 1)
    REG(Kernel32, SystemTimeToFileTime, 2) REG(Kernel32, FileTimeToSystemTime, 2)
    REG(Kernel32, QueryPerformanceCounter, 1) REG(Kernel32, QueryPerformanceFrequency, 1)
    REG(Kernel32, GetComputerName, 2) REG(Kernel32, GetUserName, 2)
    REG(Kernel32, SetUnhandledExceptionFilter, 1)
    REG(Kernel32, GetLastError, 0)   REG(Kernel32, SetLastError, 1)
    REG(Kernel32, RaiseException, 4) REG(Kernel32, UnhandledExceptionFilter, 1)
    REG(Kernel32, lstrlen, 1)        REG(Kernel32, lstrcpy, 2)
    REG(Kernel32, lstrcat, 2)        REG(Kernel32, lstrcmp, 2)
    REG(Kernel32, MultiByteToWideChar, 6) REG(Kernel32, WideCharToMultiByte, 8)
    REG(Kernel32, GetCommandLine, 0)
    REG(Kernel32, GetEnvironmentVariable, 3) 
    REG(Kernel32, SetEnvironmentVariable, 2)
    REG(Kernel32, GetCurrentDirectory, 2) REG(Kernel32, SetCurrentDirectory, 1)
    REG(Kernel32, ExpandEnvironmentStrings, 3)
    REG(Kernel32, CreateToolhelp32Snapshot, 2)
    REG(Kernel32, Process32First, 2)   REG(Kernel32, Process32Next, 2)
    REG(Kernel32, Thread32First, 2)  REG(Kernel32, Thread32Next, 2)
    REG(Kernel32, Module32First, 2)  REG(Kernel32, Module32Next, 2)
    REG(Kernel32, AllocConsole, 0)   REG(Kernel32, FreeConsole, 0)
    REG(Kernel32, GetConsoleMode, 2) REG(Kernel32, SetConsoleMode, 2)
    REG(Kernel32, OutputDebugString, 1) REG(Kernel32, GetACP, 0)
    REG(Kernel32, DecodePointer, 1)  REG(Kernel32, EncodePointer, 1)
    REG(Kernel32, IsProcessorFeaturePresent, 1)

    // Statically linked / dynamic-CRT-free missing APIs
    REG(Kernel32, FlsAlloc, 1)     REG(Kernel32, FlsFree, 1)
    REG(Kernel32, FlsGetValue, 1)     REG(Kernel32, FlsSetValue, 2)
    REG(Kernel32, GetFileType, 1)     REG(Kernel32, GetStdHandle, 1)
    REG(Kernel32, GetSystemTimeAsFileTime, 1)     REG(Kernel32, InterlockedCompareExchange, 3)
    REG(Kernel32, InterlockedDecrement, 1)     REG(Kernel32, InterlockedExchange, 2)
    REG(Kernel32, InterlockedIncrement, 1)     REG(Kernel32, TlsAlloc, 0)
    REG(Kernel32, TlsFree, 1)     REG(Kernel32, TlsGetValue, 1)
    REG(Kernel32, TlsSetValue, 2)     REG(Kernel32, AcquireSRWLockExclusive, 1)
    REG(Kernel32, AcquireSRWLockShared, 1)     REG(Kernel32, AddAtom, 1)
    REG(Kernel32, AddVectoredContinueHandler, 2)     REG(Kernel32, AddVectoredExceptionHandler, 2)
    REG(Kernel32, AreFileApisANSI, 0)     REG(Kernel32, CheckRemoteDebuggerPresent, 2)
    REG(Kernel32, CompareFileTime, 2)     REG(Kernel32, ConnectNamedPipe, 2)
    REG(Kernel32, CreateIoCompletionPort, 4)     REG(Kernel32, CreateMutexEx, 4)
    REG(Kernel32, CreateNamedPipe, 8)     REG(Kernel32, CreatePipe, 4)
    REG(Kernel32, CreateProcessInternal, 12)     REG(Kernel32, CreateSemaphoreW, 4)
    REG(Kernel32, CreateWaitableTimerEx, 4)     REG(Kernel32, CreateWaitableTimerExW, 4)
    REG(Kernel32, DeleteAtom, 1)     REG(Kernel32, DisconnectNamedPipe, 1)
    REG(Kernel32, DuplicateHandle, 7)     REG(Kernel32, EnumProcesses, 3)
    REG(Kernel32, FindAtom, 1)     REG(Kernel32, FindFirstFileEx, 6)
    REG(Kernel32, FindFirstVolume, 2)     REG(Kernel32, FindNextVolume, 3)
    REG(Kernel32, FindResource, 3)     REG(Kernel32, FindResourceEx, 4)
    REG(Kernel32, FindVolumeClose, 1)     REG(Kernel32, FlsGetValue2, 1)
    REG(Kernel32, FreeEnvironmentStrings, 1)     REG(Kernel32, FreeLibraryAndExitThread, 2)
    REG(Kernel32, FreeResource, 1)     REG(Kernel32, GetAtomName, 3)
    REG(Kernel32, GetBinaryType, 2)     REG(Kernel32, GetCPInfo, 2)
    REG(Kernel32, GetCommProperties, 2)     REG(Kernel32, GetCommTimeouts, 2)
    REG(Kernel32, GetComputerNameEx, 3)     REG(Kernel32, GetConsoleTitle, 2)
    REG(Kernel32, GetConsoleWindow, 0)     REG(Kernel32, GetCurrentPackageId, 2)
    REG(Kernel32, GetDateFormat, 6)     REG(Kernel32, GetEnvironmentStrings, 0)
    REG(Kernel32, GetErrorMode, 0)     REG(Kernel32, GetFileAttributesEx, 3)
    REG(Kernel32, GetFileSizeEx, 2)     REG(Kernel32, GetFullPathName, 4)
    REG(Kernel32, GetHandleInformation, 2)     REG(Kernel32, GetLocaleInfo, 4)
    REG(Kernel32, GetLogicalDrives, 0)     REG(Kernel32, GetLongPathName, 3)
#ifdef GetModuleFileNameEx
#undef GetModuleFileNameEx
#endif
#ifdef GlobalAddAtom
#undef GlobalAddAtom
#endif
#ifdef IsBadStringPtr
#undef IsBadStringPtr
#endif
#ifdef GetStringType
#undef GetStringType
#endif
    REG(Kernel32, GetMailslotInfo, 5)     REG(Kernel32, GetModuleFileNameEx, 4)
    REG(Kernel32, GetModuleHandleEx, 3)     REG(Kernel32, GetNativeSystemInfo, 1)
    REG(Kernel32, GetOEMCP, 0)     REG(Kernel32, GetPhysicallyInstalledSystemMemory, 1)
    REG(Kernel32, GetProcessAffinityMask, 3)     REG(Kernel32, GetProcessHandleCount, 1)
    REG(Kernel32, GetProcessVersion, 1)     REG(Kernel32, GetProfileInt, 3)
    REG(Kernel32, GetShortPathName, 3)     REG(Kernel32, GetStartupInfo, 1)
    REG(Kernel32, GetStringType, 5)     REG(Kernel32, GetStringTypeW, 4)
    REG(Kernel32, GetSystemDefaultLCID, 0)     REG(Kernel32, GetSystemDefaultLangID, 0)
    REG(Kernel32, GetSystemDefaultUILanguage, 0)     REG(Kernel32, GetSystemDirectory, 2)
    REG(Kernel32, GetSystemFirmwareTable, 4)     REG(Kernel32, GetSystemTimePreciseAsFileTime, 1)
    REG(Kernel32, GetSystemTimes, 3)     REG(Kernel32, GetTempFileName, 4)
    REG(Kernel32, GetTempPath, 2)     REG(Kernel32, GetThreadContext, 2)
    REG(Kernel32, GetThreadId, 1)     REG(Kernel32, GetThreadLocale, 0)
    REG(Kernel32, GetThreadTimes, 5)     REG(Kernel32, GetThreadUILanguage, 0)
    REG(Kernel32, GetTickCount64, 0)     REG(Kernel32, GetTimeFormat, 6)
    REG(Kernel32, GetTimeZoneInformation, 1)     REG(Kernel32, GetUserDefaultLCID, 0)
    REG(Kernel32, GetUserDefaultLangID, 0)     REG(Kernel32, GetUserDefaultUILanguage, 0)
    REG(Kernel32, GetVolumeInformation, 8)     REG(Kernel32, GetVolumePathNamesForVolumeName, 4)
    REG(Kernel32, GetWindowsDirectory, 2)     REG(Kernel32, GlobalAddAtom, 1)
    REG(Kernel32, GlobalFlags, 1)     REG(Kernel32, GlobalHandle, 1)
    REG(Kernel32, GlobalLock, 1)     REG(Kernel32, GlobalMemoryStatus, 1)
    REG(Kernel32, GlobalMemoryStatusEx, 1)     REG(Kernel32, GlobalSize, 1)
    REG(Kernel32, GlobalUnlock, 1)     REG(Kernel32, HeapReAlloc, 4)
    REG(Kernel32, HeapSetInformation, 4)     REG(Kernel32, HeapSize, 3)
    REG(Kernel32, InitOnceBeginInitialize, 4)     REG(Kernel32, InitializeConditionVariable, 1)
    REG(Kernel32, InitializeCriticalSectionAndSpinCount, 2)     REG(Kernel32, InitializeCriticalSectionEx, 3)
    REG(Kernel32, InitializeSListHead, 1)     REG(Kernel32, InitializeSRWLock, 1)
    REG(Kernel32, IsBadReadPtr, 2)     REG(Kernel32, IsBadStringPtr, 2)
    REG(Kernel32, IsBadWritePtr, 2)     REG(Kernel32, IsDBCSLeadByte, 1)
    REG(Kernel32, IsValidCodePage, 1)     REG(Kernel32, IsValidLocale, 2)
    REG(Kernel32, IsWow64Process, 2)     REG(Kernel32, LCMapString, 6)
    REG(Kernel32, LCMapStringEx, 9)     REG(Kernel32, LoadResource, 2)
    REG(Kernel32, LocalLock, 1)     REG(Kernel32, LocalReAlloc, 3)
    REG(Kernel32, LockResource, 1)     REG(Kernel32, MoveFile, 2)
    REG(Kernel32, MulDiv, 3)     REG(Kernel32, OpenEvent, 3)
    REG(Kernel32, OpenWaitableTimer, 3)     REG(Kernel32, PeekNamedPipe, 6)
    REG(Kernel32, ProcessIdToSessionId, 2)     REG(Kernel32, ReleaseSRWLockExclusive, 1)
    REG(Kernel32, ReleaseSRWLockShared, 1)     REG(Kernel32, RemoveVectoredExceptionHandler, 1)
    REG(Kernel32, RtlCaptureContext, 1)     REG(Kernel32, RtlLookupFunctionEntry, 3)
    REG(Kernel32, RtlUnwind, 4)     REG(Kernel32, SetConsoleCtrlHandler, 2)
    REG(Kernel32, SetConsoleHistoryInfo, 1)     REG(Kernel32, SetConsoleTitle, 1)
    REG(Kernel32, SetDefaultDllDirectories, 1)     REG(Kernel32, SetDllDirectory, 1)
    REG(Kernel32, SetFilePointerEx, 4)     REG(Kernel32, SetHandleCount, 1)
    REG(Kernel32, SetHandleInformation, 3)     REG(Kernel32, SetPriorityClass, 2)
    REG(Kernel32, SetProcessPriorityBoost, 2)     REG(Kernel32, SetThreadContext, 2)
    REG(Kernel32, SetThreadDescription, 2)     REG(Kernel32, SetThreadErrorMode, 2)
    REG(Kernel32, SetThreadLocale, 1)     REG(Kernel32, SetThreadStackGuarantee, 1)
    REG(Kernel32, SizeofResource, 2)     REG(Kernel32, SystemTimeToTzSpecificLocalTime, 3)
    REG(Kernel32, VerSetConditionMask, 3)     REG(Kernel32, VerifyVersionInfo, 3)
    REG(Kernel32, VirtualAllocExNuma, 6)     REG(Kernel32, WTSGetActiveConsoleSessionId, 0)
    REG(Kernel32, WaitForSingleObjectEx, 3)     REG(Kernel32, WakeAllConditionVariable, 1)
    REG(Kernel32, WerGetFlags, 2)     REG(Kernel32, WerSetFlags, 1)
    REG(Kernel32, Wow64DisableWow64FsRedirection, 1)     REG(Kernel32, Wow64RevertWow64FsRedirection, 1)
    REG(Kernel32, _lclose, 1)     REG(Kernel32, _llseek, 3)
    REG(Kernel32, _lopen, 2)     REG(Kernel32, lstrcmpi, 2)
    REG(Kernel32, lstrcpyn, 3)
    REG(Kernel32, InterlockedExchangeAdd, 2)
    END_API_TABLE
}

// 
//  FILE I/O APIs
// 

uint64_t Kernel32::CreateFile(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: CreateFile  get_char_width, read name, open/create
    uint64_t fname_ptr = a[0];
    if (!fname_ptr) return K32_INVALID_HANDLE;
    int cw = get_char_width(static_cast<ApiContext*>(c));
    std::string target = be(emu)->read_mem_string(fname_ptr, cw);
    a[0] = target;
    uint32_t access = static_cast<uint32_t>(a[1]);
    uint32_t share  = static_cast<uint32_t>(a[2]);
    uint32_t disp   = static_cast<uint32_t>(a[4]);
    (void)access; (void)share; (void)a[3]; (void)a[5]; (void)a[6];

    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    void* fobj = nullptr;
    bool exists = we(emu)->does_file_exist(target);
    if (exists) {
        if (disp == K32_CREATE_ALWAYS) {
            w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
            fobj = we(emu)->file_open(target, true);
        } else if (disp == K32_CREATE_NEW) {
            w32(emu)->set_last_error(K32_ERR_FILE_EXISTS);
            return K32_INVALID_HANDLE;
        } else if (disp == K32_OPEN_ALWAYS) {
            w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
            fobj = we(emu)->file_open(target, false);
        } else if (disp == K32_OPEN_EXISTING || disp == K32_TRUNCATE_EXISTING) {
            w32(emu)->set_last_error(K32_ERR_SUCCESS);
            fobj = we(emu)->file_open(target, false);
        }
    } else {
        if (disp == K32_CREATE_ALWAYS || disp == K32_CREATE_NEW) {
            w32(emu)->set_last_error(K32_ERR_SUCCESS);
            fobj = we(emu)->file_open(target, true);
        } else if (disp == K32_OPEN_ALWAYS) {
            w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
            fobj = we(emu)->file_open(target, true);
        } else {
            w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
            return K32_INVALID_HANDLE;
        }
    }
    return reinterpret_cast<uint64_t>(fobj);
}

uint64_t Kernel32::ReadFile(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t lpBuffer = argv[1];
    uint32_t num_bytes = static_cast<uint32_t>(argv[2]);
    uint64_t bytes_read_ptr = argv[3];
    uint64_t lpOverlapped = argv[4];
    (void)lpOverlapped;

    if (bytes_read_ptr) {
        auto zero = std::vector<uint8_t>(4, 0);
        mm(emu)->mem_write(bytes_read_ptr, zero);
    }

    void* f = we(emu)->file_get(hFile);
    if (!f) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }

    auto* file_obj = static_cast<::File*>(f);
    auto data = file_obj->get_data(static_cast<int>(num_bytes));

    if (lpBuffer && !data.empty()) {
        mm(emu)->mem_write(lpBuffer, data);
    }

    if (bytes_read_ptr) {
        auto read_sz = std::vector<uint8_t>(4, 0);
        write_le(read_sz, 0, data.size(), 4);
        mm(emu)->mem_write(bytes_read_ptr, read_sz);
    }

    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::WriteFile(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t lpBuffer = argv[1];
    uint32_t num_bytes = static_cast<uint32_t>(argv[2]);
    uint64_t bytes_written_ptr = argv[3];
    uint64_t lpOverlapped = argv[4];
    (void)lpOverlapped;

    if (bytes_written_ptr) {
        auto zero = std::vector<uint8_t>(4, 0);
        mm(emu)->mem_write(bytes_written_ptr, zero);
    }

    void* f = we(emu)->file_get(hFile);
    if (!f) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }

    std::vector<uint8_t> data;
    if (lpBuffer && num_bytes > 0) {
        data = mm(emu)->mem_read(lpBuffer, num_bytes);
    }

    if (!data.empty()) {
        auto* file_obj = static_cast<::File*>(f);
        file_obj->add_data(data);
    }

    if (bytes_written_ptr) {
        auto written_sz = std::vector<uint8_t>(4);
        write_le(written_sz, 0, data.size(), 4);
        mm(emu)->mem_write(bytes_written_ptr, written_sz);
    }

    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::CloseHandle(void* emu, ArgList& argv, void* ctx) {
    uint64_t hObject = argv[0];
    (void)hObject;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::DeleteFile(void* emu, ArgList& argv, void* ctx) {
    uint64_t fname_ptr = argv[0];
    if (!fname_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    std::string target = be(emu)->read_mem_string(fname_ptr, 1);
    if (we(emu)->does_file_exist(target)) {
        we(emu)->file_delete(target);
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    }
    w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return 0;
}

static uint64_t CopyFile_impl(void* emu, const std::string& src, const std::string& dst,
                               uint32_t fail_if_exists) {
    (void)src; (void)dst; (void)fail_if_exists;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}
uint64_t Kernel32::CopyFile(void* emu, ArgList& argv, void* ctx) {
    if (!argv[0] || !argv[1]) return 0;
    return CopyFile_impl(emu, be(emu)->read_mem_string(argv[0], 1),
                         be(emu)->read_mem_string(argv[1], 1),
                         static_cast<uint32_t>(argv[2]));
}

uint64_t Kernel32::CreateDirectory(void* emu, ArgList& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    uint64_t sec_attr = argv[1];
    (void)sec_attr;
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    (void)path;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::RemoveDirectory(void* emu, ArgList& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    (void)path;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileAttributes(void* emu, ArgList& argv, void* ctx) {
    uint64_t fname_ptr = argv[0];
    if (!fname_ptr) return K32_INVALID_FILE_ATTR;
    std::string target = be(emu)->read_mem_string(fname_ptr, 1);
    if (we(emu)->does_file_exist(target)) {
        return K32_FILE_ATTR_NORMAL;
    }
    w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return K32_INVALID_FILE_ATTR;
}

uint64_t Kernel32::SetFilePointer(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    int32_t dist = static_cast<int32_t>(argv[1] & 0xFFFFFFFF);
    uint64_t dist_high_ptr = argv[2];
    uint32_t move_method = static_cast<uint32_t>(argv[3]);
    (void)hFile; (void)dist; (void)dist_high_ptr; (void)move_method;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::GetFileSize(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t size_high_ptr = argv[1];
    (void)hFile; (void)size_high_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::FindFirstFile(void* emu, ArgList& argv, void* ctx) {
    uint64_t fname_ptr = argv[0];
    uint64_t find_data_ptr = argv[1];
    (void)fname_ptr; (void)find_data_ptr;
    w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return K32_INVALID_HANDLE;
}

uint64_t Kernel32::FindNextFile(void* emu, ArgList& argv, void* ctx) {
    uint64_t find_handle = argv[0];
    uint64_t find_data_ptr = argv[1];
    (void)find_handle; (void)find_data_ptr;
    w32(emu)->set_last_error(K32_ERR_NO_MORE_FILES);
    return 0;
}

uint64_t Kernel32::FindClose(void* emu, ArgList& argv, void* ctx) {
    uint64_t find_handle = argv[0];
    (void)find_handle;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::CreateFileMapping(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py: CreateFileMapping  read name, compute size, call file_create_mapping
    uint64_t hFile         = argv[0];
    uint64_t map_attrs     = argv[1];
    uint32_t prot          = static_cast<uint32_t>(argv[2]);
    uint32_t max_sz_high   = static_cast<uint32_t>(argv[3]);
    uint32_t max_sz_low    = static_cast<uint32_t>(argv[4]);
    uint64_t map_name_ptr  = argv[5];
    (void)map_attrs;

    uint64_t size = (static_cast<uint64_t>(max_sz_high) << 32) | max_sz_low;
    std::string name;
    if (map_name_ptr) {
        name = be(emu)->read_mem_string(map_name_ptr, 1);
        argv[5] = name;
    }

    void* file_obj = we(emu)->file_get(static_cast<int>(hFile));
    uint32_t handle = we(emu)->file_create_mapping(file_obj, name, size, static_cast<int>(prot));
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(handle);
}

uint64_t Kernel32::MapViewOfFile(void* emu, ArgList& argv, void* ctx) {
    uint64_t hmap = argv[0];
    uint32_t access = static_cast<uint32_t>(argv[1]);
    uint32_t offset_high = static_cast<uint32_t>(argv[2]);
    uint32_t offset_low = static_cast<uint32_t>(argv[3]);
    uint64_t bytes_to_map = argv[4];
    (void)hmap; (void)access; (void)offset_high; (void)offset_low; (void)bytes_to_map;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::UnmapViewOfFile(void* emu, ArgList& argv, void* ctx) {
    uint64_t base = argv[0];
    (void)base;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::FlushFileBuffers(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    (void)hFile;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::SetEndOfFile(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    (void)hFile;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileTime(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t creation_ptr = argv[1];
    uint64_t last_access_ptr = argv[2];
    uint64_t last_write_ptr = argv[3];
    (void)hFile;
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
    uint64_t ft = 116444736000000000ULL + ns / 100;
    for (auto ptr : {creation_ptr, last_access_ptr, last_write_ptr}) {
        if (ptr) {
            std::vector<uint8_t> ft_bytes(8);
            write_le(ft_bytes, 0, ft, 8);
            mm(emu)->mem_write(ptr, ft_bytes);
        }
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::SetFileTime(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t creation_ptr = argv[1];
    uint64_t last_access_ptr = argv[2];
    uint64_t last_write_ptr = argv[3];
    (void)hFile; (void)creation_ptr; (void)last_access_ptr; (void)last_write_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileInformationByHandle(void* emu, ArgList& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t info_ptr = argv[1];
    (void)hFile; (void)info_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::DeviceIoControl(void* emu, ArgList& argv, void* ctx) {
    int hDevice = static_cast<int>(argv[0]);
    uint32_t ctl_code = static_cast<uint32_t>(argv[1]);
    uint64_t in_buf = argv[2];
    uint32_t in_sz = static_cast<uint32_t>(argv[3]);
    uint64_t out_buf = argv[4];
    uint32_t out_sz = static_cast<uint32_t>(argv[5]);
    uint64_t ret_ptr = argv[6];
    uint64_t overlapped = argv[7];
    (void)hDevice; (void)ctl_code; (void)in_buf; (void)in_sz;
    (void)out_buf; (void)out_sz; (void)ret_ptr; (void)overlapped;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetDriveType(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: GetDriveType  read name, delegate to drive manager
    uint64_t root_ptr = a[0];
    if (!root_ptr) return 1; // DRIVE_NO_ROOT_DIR
    int cw = get_char_width(static_cast<ApiContext*>(c));
    std::string name = be(emu)->read_mem_string(root_ptr, cw);
    a[0] = name;
    // Strip \\?\ prefix
    if (name.find("\\\\?\\") == 0) name = name.substr(4);
    if (name.size() == 1 && name[0] >= 'A' && name[0] <= 'Z') name += ":\\";
    if (name.size() == 2 && name[1] == ':') name += "\\";
    auto dm = we(emu)->get_drive_manager();
    return dm ? dm->get_drive_type(name) : 3; // DRIVE_FIXED fallback
}

uint64_t Kernel32::GetDiskFreeSpaceEx(void* emu, ArgList& argv, void* ctx) {
    uint64_t dir_ptr = argv[0];
    uint64_t free_ptr = argv[1];
    uint64_t total_ptr = argv[2];
    uint64_t total_free_ptr = argv[3];
    (void)dir_ptr;
    uint64_t free_val = 1024ULL * 1024 * 1024 * 100;
    uint64_t total_val = 1024ULL * 1024 * 1024 * 500;
    for (auto [ptr, val] : {std::make_pair(free_ptr, free_val),
                            std::make_pair(total_ptr, total_val),
                            std::make_pair(total_free_ptr, free_val)}) {
        if (ptr) {
            std::vector<uint8_t> buf(8);
            write_le(buf, 0, val, 8);
            mm(emu)->mem_write(ptr, buf);
        }
    }
    return 1;
}

// 
//  MEMORY APIs
// 

uint64_t Kernel32::VirtualAlloc(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py: VirtualAlloc  check existing map, tag "api.VirtualAlloc"
    uint64_t lpAddress = argv[0];
    size_t   dwSize    = static_cast<size_t>(argv[1]);
    uint32_t flAlloc   = static_cast<uint32_t>(argv[2]);
    uint32_t flProtect = static_cast<uint32_t>(argv[3]);
    (void)flAlloc;

    if (dwSize == 0) return 0;

    // Check if address is already committed (Python: emu.get_address_map)
    auto existing = we(emu)->get_address_map(lpAddress);
    if (existing && !existing->get_tag().empty() &&
        existing->get_tag().find("api.VirtualAlloc") == 0) {
        return lpAddress;
    }

    int emu_perms = win_to_emu_perms(flProtect);
    dwSize = (dwSize + 0xFFF) & ~0xFFF;
    uint64_t base = (lpAddress == 0) ? 0x10000 : lpAddress;
    uint64_t buf = mm(emu)->mem_map(dwSize, base, static_cast<uint32_t>(emu_perms), "api.VirtualAlloc");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::VirtualAllocEx(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py: VirtualAllocEx  resolve hProcess, use process-specific tag
    uint64_t hProcess = argv[0];
    uint64_t lpAddress = argv[1];
    size_t   dwSize    = static_cast<size_t>(argv[2]);
    uint32_t flAlloc   = static_cast<uint32_t>(argv[3]);
    uint32_t flProtect = static_cast<uint32_t>(argv[4]);
    (void)flAlloc;

    if (dwSize == 0) return 0;

    // Resolve process object (Python: get_object_from_handle / get_current_process)
    auto proc = we(emu)->get_current_process();
    if (hProcess != static_cast<uint64_t>(-1)) { // not pseudo-handle
        auto obj = we(emu)->get_object_from_handle(hProcess);
        if (!obj) return 0; // NULL on invalid handle
    }

    std::string tag = "api.VirtualAllocEx";
    int emu_perms = win_to_emu_perms(flProtect);
    dwSize = (dwSize + 0xFFF) & ~0xFFF;
    uint64_t base = (lpAddress == 0) ? 0x10000 : lpAddress;
    uint64_t buf = mm(emu)->mem_map(dwSize, base, static_cast<uint32_t>(emu_perms), tag);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::VirtualFree(void* emu, ArgList& argv, void* ctx) {
    uint64_t addr = argv[0];
    size_t size = static_cast<size_t>(argv[1]);
    uint32_t free_type = static_cast<uint32_t>(argv[2]);
    (void)size; (void)free_type;
    if (addr) {
        try { mm(emu)->mem_free(addr); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::VirtualProtect(void* emu, ArgList& argv, void* ctx) {
    uint64_t addr = argv[0];
    size_t size = static_cast<size_t>(argv[1]);
    uint32_t new_prot = static_cast<uint32_t>(argv[2]);
    uint64_t old_prot_ptr = argv[3];
    (void)size;
    int emu_perms = win_to_emu_perms(new_prot);
    uint64_t page_addr = addr & ~0xFFFULL;
    try {
        mm(emu)->mem_protect(page_addr, (size + 0xFFF) & ~0xFFF, emu_perms);
    } catch (...) {}
    if (old_prot_ptr) {
        std::vector<uint8_t> prot_buf(4);
        write_le(prot_buf, 0, new_prot, 4);
        mm(emu)->mem_write(old_prot_ptr, prot_buf);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::VirtualProtectEx(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    (void)hProcess;
    ArgList remaining = {argv[1], argv[2], argv[3], argv[4]};
    return VirtualProtect(emu, remaining, ctx);
}

uint64_t Kernel32::VirtualQuery(void* emu, ArgList& argv, void* ctx) {
    uint64_t addr = argv[0];
    uint64_t buf_ptr = argv[1];
    uint32_t buf_sz = static_cast<uint32_t>(argv[2]);
    (void)addr; (void)buf_sz;
    if (!buf_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    std::vector<uint8_t> mbi;
    mbi.resize((ptr_sz(emu) == 8) ? 48 : 36, 0);
    mm(emu)->mem_write(buf_ptr, mbi);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return (ptr_sz(emu) == 8) ? 48 : 36;
}

uint64_t Kernel32::WriteProcessMemory(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint64_t base = argv[1];
    uint64_t src = argv[2];
    size_t nsz = static_cast<size_t>(argv[3]);
    uint64_t written_ptr = argv[4];
    (void)hProcess;
    if (!base || !src || nsz == 0) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto data = mm(emu)->mem_read(src, nsz);
    mm(emu)->mem_write(base, data);
    if (written_ptr) {
        std::vector<uint8_t> sz_buf(static_cast<size_t>(ptr_sz(emu)));
        write_le(sz_buf, 0, nsz, static_cast<size_t>(ptr_sz(emu)));
        mm(emu)->mem_write(written_ptr, sz_buf);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::ReadProcessMemory(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint64_t base = argv[1];
    uint64_t dst = argv[2];
    size_t nsz = static_cast<size_t>(argv[3]);
    uint64_t read_ptr = argv[4];
    (void)hProcess;
    if (!base || !dst || nsz == 0) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    try {
        auto data = mm(emu)->mem_read(base, nsz);
        mm(emu)->mem_write(dst, data);
        if (read_ptr) {
            std::vector<uint8_t> sz_buf(static_cast<size_t>(ptr_sz(emu)));
            write_le(sz_buf, 0, nsz, static_cast<size_t>(ptr_sz(emu)));
            mm(emu)->mem_write(read_ptr, sz_buf);
        }
    } catch (...) {
        w32(emu)->set_last_error(K32_ERR_ACCESS_DENIED);
        return 0;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::HeapAlloc(void* emu, ArgList& argv, void* ctx) {
    uint64_t hHeap = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    size_t sz = static_cast<size_t>(argv[2]);
    (void)hHeap; (void)flags;
    //if (sz == 0) sz = 1;
    uint64_t buf = we32(emu)->heap_alloc(sz, "HeapAlloc");
    if(buf)
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::HeapFree(void* emu, ArgList& argv, void* ctx) {
    uint64_t hHeap = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint64_t mem = argv[2];
    (void)hHeap; (void)flags;
    if (mem) {
        try { mm(emu)->mem_free(mem); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::HeapCreate(void* emu, ArgList& argv, void* ctx) {
    (void)argv; (void)ctx;
    // Python kernel32.py: create_heap allocates 20 bytes tagged "emu.process_heap"
    uint64_t heap = we32(emu)->heap_alloc(20, "HeapCreate");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return heap;
}

uint64_t Kernel32::HeapDestroy(void* emu, ArgList& argv, void* ctx) {
    uint64_t hHeap = argv[0];
    if (hHeap) {
        try { mm(emu)->mem_free(hHeap); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetProcessHeap(void* emu, ArgList& argv, void* ctx) {
    (void)argv; (void)ctx;
    // Python kernel32.py: first heap in heaps list, or create one
    static thread_local std::vector<uint64_t> heaps;
    if (heaps.empty()) {
        uint64_t heap = we32(emu)->heap_alloc(20, "emu.process_heap");
        heaps.push_back(heap);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return heaps[0];
}

uint64_t Kernel32::GlobalAlloc(void* emu, ArgList& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    size_t sz = static_cast<size_t>(argv[1]);
    (void)flags;
    if (sz == 0) sz = 1;
    uint64_t buf = we32(emu)->heap_alloc(sz, "GlobalAlloc");
    return buf;
}

uint64_t Kernel32::GlobalFree(void* emu, ArgList& argv, void* ctx) {
    uint64_t hMem = argv[0];
    (void)hMem;
    return 0;
}

uint64_t Kernel32::LocalAlloc(void* emu, ArgList& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    size_t sz = static_cast<size_t>(argv[1]);
    (void)flags;
    if (sz == 0) sz = 1;
    uint64_t buf = we32(emu)->heap_alloc(sz, "LocalAlloc");
    return buf;
}

uint64_t Kernel32::LocalFree(void* emu, ArgList& argv, void* ctx) {
    uint64_t hMem = argv[0];
    if (hMem) {
        try { mm(emu)->mem_free(hMem); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::RtlMoveMemory(void* emu, ArgList& argv, void* ctx) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    size_t sz = static_cast<size_t>(argv[2]);
    if (dst && src && sz > 0) {
        auto data = mm(emu)->mem_read(src, sz);
        mm(emu)->mem_write(dst, data);
    }
    return dst;
}

uint64_t Kernel32::RtlZeroMemory(void* emu, ArgList& argv, void* ctx) {
    uint64_t dst = argv[0];
    size_t sz = static_cast<size_t>(argv[1]);
    if (dst && sz > 0) {
        std::vector<uint8_t> zeros(sz, 0);
        mm(emu)->mem_write(dst, zeros);
    }
    return 0;
}

// 
//  DLL / MODULE APIs
// 

uint64_t Kernel32::LoadLibrary(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: LoadLibrary  get_char_width, update argv[0]
    int cw = get_char_width(static_cast<ApiContext*>(c));
    uint64_t name_ptr = a[0];
    if (!name_ptr) return 0;
    std::string lib = be(emu)->read_mem_string(name_ptr, cw);
    a[0] = lib;
    if (lib.empty()) return 0;
    lib = speakeasy::to_lower(lib);
    auto dot = lib.rfind(".dll");
    if (dot != std::string::npos) lib = lib.substr(0, dot);
    lib = normalize_dll_name(lib);
    void* mod = we(emu)->load_library(lib);
    if (!mod) { w32(emu)->set_last_error(K32_ERR_MOD_NOT_FOUND); return 0; }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return reinterpret_cast<uint64_t>(mod);
}

uint64_t Kernel32::LoadLibraryEx(void* emu, ArgList& a, void* c) {
    int cw = get_char_width(static_cast<ApiContext*>(c));
    uint64_t name_ptr = a[0];
    if (!name_ptr) return 0;
    std::string lib = be(emu)->read_mem_string(name_ptr, cw);
    a[0] = lib;
    if (lib.empty()) return 0;
    lib = speakeasy::to_lower(lib);
    auto dot = lib.rfind(".dll");
    if (dot != std::string::npos) lib = lib.substr(0, dot);
    lib = normalize_dll_name(lib);
    void* mod = we(emu)->load_library(lib);
    if (!mod) { w32(emu)->set_last_error(K32_ERR_MOD_NOT_FOUND); return 0; }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return reinterpret_cast<uint64_t>(mod);
}

uint64_t Kernel32::FreeLibrary(void* emu, ArgList& argv, void* ctx) {
    uint64_t hMod = argv[0];
    (void)hMod;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetProcAddress(void* emu, ArgList& argv, void* ctx) {
    // Python kernel32.py:1959-1992  matches Python logic step by step.
    uint64_t hMod = argv[0];
    uint64_t proc_name_ptr = argv[1];
    uint64_t rv = 0;
    std::string proc;

    if (proc_name_ptr) {
        try {
            proc = be(emu)->read_mem_string(proc_name_ptr, 1);
            if ((proc_name_ptr < 0xFFFF) && (be(emu)->get_uc_errno() != 0)) {
                proc = "ordinal_" + std::to_string(proc_name_ptr);
            }
        } catch (...) {
            if (proc_name_ptr < 0xFFFF) {
                proc = "ordinal_" + std::to_string(proc_name_ptr);
            }
        }
    }

    argv[1] = proc;

    // Python kernel32.py:1980-1992  matches Python logic.
    // get_proc() creates a sentinel; normalize_import_miss bridges ntdll Nt* 
    // ntoskrnl Zw* during dispatch, so we don't need to verify exports here.
    // Python kernel32.py:1980-1992  matches Python logic.
    // get_proc() creates a sentinel; normalize_import_miss bridges ntdll Nt* 
    // ntoskrnl Zw* during dispatch.
    // Fallback: if hMod doesn't match any loaded module, try get_proc with
    // a generic lookup (e.g. hMod=0 or the handle is a LoadLibrary return).
    if (!proc.empty()) {
        auto mods = we(emu)->get_peb_modules();
        for (auto& mod : mods) {
            if (mod->base == hMod) {
                std::string bn = mod->get_base_name();
                auto dot = bn.rfind(".");
                std::string mname = (dot != std::string::npos) ? bn.substr(0, dot) : bn;
                auto* entry = mod->get_export_by_name(proc);
                if(entry || be(emu)->get_config().modules.functions_always_exist)
                    rv = reinterpret_cast<uint64_t>(we(emu)->get_proc(mname, proc));
                break;
            }
        }
        // Python-like fallback: if hMod matches no loaded PEB module,
        // use a default module lookup.  LoadLibraryW("ntdll") stores
        // the module at a synthetic base that may not appear in PEB.
        //if (rv == 0) {
        //    rv = reinterpret_cast<uint64_t>(we(emu)->get_proc("ntdll", proc));
        //}
    }

    if (rv != 0) {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    } else {
        w32(emu)->set_last_error(K32_ERR_MOD_NOT_FOUND);
    }
    return rv;
}

uint64_t Kernel32::GetModuleHandle(void* emu, ArgList& argv, void* ctx) {
    uint64_t mod_name_ptr = argv[0];
    if (!mod_name_ptr) {
        auto p = we(emu)->get_current_process();
        if (p) {
            return static_cast<uint64_t>(p->base);
        }
        return 0;
    }
    std::string name = be(emu)->read_mem_string(mod_name_ptr, 1);
    if (name.empty()) return 0;
    name = speakeasy::to_lower(name);
    auto dot = name.rfind(".dll");
    if (dot != std::string::npos) name = name.substr(0, dot);
    auto mods = we(emu)->get_peb_modules();
    for (auto& mod : mods) {
        std::string mname = speakeasy::to_lower(mod->get_base_name());
        auto mdot = mname.rfind(".dll");
        if (mdot != std::string::npos) mname = mname.substr(0, mdot);
        if (mname == name) {
            return mod->base;
        }
    }
    return 0;
}


uint64_t Kernel32::GetModuleFileName(void* emu, ArgList& argv, void* ctx) {
    uint64_t hMod = argv[0];
    uint64_t buf_ptr = argv[1];
    uint32_t buf_sz = static_cast<uint32_t>(argv[2]);
    if (!buf_ptr || buf_sz == 0) return 0;
    std::string filename;
    if (hMod == 0) {
        auto p = we(emu)->get_current_process();
        if (p) {
            filename = p->path;
        }
    } else {
        auto mods = we(emu)->get_peb_modules();
        for (auto m : mods) {
            auto mod = m;
            if (mod->base == hMod) {
                filename = mod->emu_path;
                break;
            }
        }
    }
    if (filename.empty()) return 0;
    if (buf_sz <= filename.size()) {
        w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        filename = filename.substr(0, buf_sz - 1);
    }
    filename.push_back('\0');
    be(emu)->write_mem_string(filename, buf_ptr, 1);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(filename.size() - 1);
}


uint64_t Kernel32::DisableThreadLibraryCalls(void* emu, ArgList& argv, void* ctx) {
    (void)argv[0];
    return 1;
}

// 
//  PROCESS / THREAD APIs
// 

uint64_t Kernel32::CreateProcess(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: CreateProcess  get_char_width, update argv[0]/argv[1]
    int cw = get_char_width(static_cast<ApiContext*>(c));
    uint32_t flags = static_cast<uint32_t>(a[5]);
    uint64_t pi_ptr = a[9];
    std::string app_str, cmd_str;
    if (a[0]) { app_str = be(emu)->read_mem_string(a[0], cw); a[0] = app_str; }
    if (a[1]) { cmd_str = be(emu)->read_mem_string(a[1], cw); a[1] = cmd_str; }
    (void)a[2]; (void)a[3]; (void)a[4]; (void)a[6]; (void)a[7]; (void)a[8];

    std::shared_ptr<Process> proc = we(emu)->create_process(app_str, cmd_str, nullptr, true);
    if (!proc) { w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND); return 0; }
    auto& threads = proc->threads;
    if ((flags & 0x00000004) && !threads.empty()) threads[0]->set_suspend_count(1);
    int proc_handle = we(emu)->get_object_handle(proc);
    int thread_handle = (!threads.empty()) ? we(emu)->get_object_handle(threads[0]) : 0;
    if (pi_ptr) {
        int ps = ptr_sz(emu);
        int tid = (!threads.empty()) ? threads[0]->get_id() : 0;
        if (ps == 4) {
            speakeasy::deffs::windows::PROCESS_INFORMATION<4> pi;
            pi.hProcess = static_cast<uint32_t>(proc_handle);
            pi.hThread = static_cast<uint32_t>(thread_handle);
            pi.dwProcessId = static_cast<uint32_t>(proc->get_pid());
            pi.dwThreadId = static_cast<uint32_t>(tid);
            mm(emu)->mem_write(pi_ptr, pi.get_bytes());
        } else {
            speakeasy::deffs::windows::PROCESS_INFORMATION<8> pi;
            pi.hProcess = static_cast<uint64_t>(proc_handle);
            pi.hThread = static_cast<uint64_t>(thread_handle);
            pi.dwProcessId = static_cast<uint32_t>(proc->get_pid());
            pi.dwThreadId = static_cast<uint32_t>(tid);
            mm(emu)->mem_write(pi_ptr, pi.get_bytes());
        }
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::OpenProcess(void* emu, ArgList& argv, void* ctx) {
    uint32_t access = static_cast<uint32_t>(argv[0]);
    uint32_t inherit = static_cast<uint32_t>(argv[1]);
    uint32_t pid = static_cast<uint32_t>(argv[2]);
    (void)access; (void)inherit;
    auto& procs = we(emu)->get_processes();
    for (auto& proc : procs) {
        //auto proc = we(emu)->find_process(p);
        if (proc && static_cast<uint32_t>(proc->get_pid()) == pid) {
            int h = we(emu)->get_object_handle(proc);
            if (h == 0) {
                we(emu)->add_object(proc);
                h = we(emu)->get_object_handle(proc);
            }
            if (h) {
                w32(emu)->set_last_error(K32_ERR_SUCCESS);
                return static_cast<uint64_t>(h);
            }
        }
    }
    w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
    return 0;
}

uint64_t Kernel32::TerminateProcess(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint32_t exit_code = static_cast<uint32_t>(argv[1]);
    (void)hProcess; (void)exit_code;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetCurrentProcess(void* emu, ArgList& argv, void* ctx) {
    return static_cast<uint64_t>(-1);
}

uint64_t Kernel32::GetCurrentProcessId(void* emu, ArgList& argv, void* ctx) {
    auto proc = we(emu)->get_current_process();
    if (proc) {
        return static_cast<uint64_t>(proc->get_pid());
    }
    return 0;
}

uint64_t Kernel32::ExitProcess(void* emu, ArgList& argv, void* ctx) {
    uint32_t exit_code = static_cast<uint32_t>(argv[0]);
    (void)exit_code;
    we(emu)->stop();
    return 0;
}

uint64_t Kernel32::CreateThread(void* emu, ArgList& argv, void* ctx) {
    uint64_t attrs = argv[0];
    size_t stack_sz = static_cast<size_t>(argv[1]);
    uint64_t start_addr = argv[2];
    uint64_t param = argv[3];
    uint32_t flags = static_cast<uint32_t>(argv[4]);
    uint64_t tid_ptr = argv[5];
    (void)attrs; (void)stack_sz;
    auto proc = we(emu)->get_current_process();
    bool suspended = (flags & 0x00000004) != 0;
    auto thread = we(emu)->create_thread(start_addr, reinterpret_cast<void*>(param), proc, "thread", suspended);
    if (!thread) return 0;
    int h = we(emu)->get_object_handle(thread);
    if (tid_ptr) {
        int tid = thread->get_id();
        std::vector<uint8_t> tid_buf(4);
        write_le(tid_buf, 0, static_cast<uint64_t>(tid), 4);
        mm(emu)->mem_write(tid_ptr, tid_buf);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::CreateRemoteThread(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint64_t attrs = argv[1];
    size_t stack_sz = static_cast<size_t>(argv[2]);
    uint64_t start_addr = argv[3];
    uint64_t param = argv[4];
    uint32_t flags = static_cast<uint32_t>(argv[5]);
    uint64_t tid_ptr = argv[6];
    (void)hProcess; (void)attrs; (void)stack_sz;
    auto proc = we(emu)->get_current_process();
    bool suspended = (flags & 0x00000004) != 0;
    auto thread = we(emu)->create_thread(start_addr, reinterpret_cast<void*>(param), proc, "injected_thread", suspended);
    if (!thread) return 0;
    int h = we(emu)->get_object_handle(thread);
    if (tid_ptr) {
        int tid = thread->get_id();
        std::vector<uint8_t> tid_buf(4);
        write_le(tid_buf, 0, static_cast<uint64_t>(tid), 4);
        mm(emu)->mem_write(tid_ptr, tid_buf);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::OpenThread(void* emu, ArgList& argv, void* ctx) {
    uint32_t access = static_cast<uint32_t>(argv[0]);
    uint32_t inherit = static_cast<uint32_t>(argv[1]);
    uint32_t tid = static_cast<uint32_t>(argv[2]);
    (void)access; (void)inherit; (void)tid;
    w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
    return 0;
}

uint64_t Kernel32::TerminateThread(void* emu, ArgList& argv, void* ctx) {
    uint64_t hThread = argv[0];
    uint32_t exit_code = static_cast<uint32_t>(argv[1]);
    (void)hThread; (void)exit_code;
    return 1;
}

uint64_t Kernel32::GetCurrentThread(void* emu, ArgList& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (thread) {
        int h = we(emu)->get_object_handle(thread);
        if (h) return static_cast<uint64_t>(h);
    }
    return static_cast<uint64_t>(-2);
}

uint64_t Kernel32::GetCurrentThreadId(void* emu, ArgList& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (thread) {
        return static_cast<uint64_t>(thread->get_id());
    }
    return 0;
}

uint64_t Kernel32::ResumeThread(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py:6085-6099  ResumeThread
    uint64_t hThread = argv[0];
    auto thread = we(emu)->get_object_from_handle(hThread);
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0xFFFFFFFF;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;  // previous suspend count
}

uint64_t Kernel32::SuspendThread(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    uint64_t hThread = argv[0];
    auto thread = we(emu)->get_object_from_handle(hThread);
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0xFFFFFFFF;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;  // previous suspend count
}

uint64_t Kernel32::ExitThread(void* emu, ArgList& argv, void* ctx) {
    uint32_t exit_code = static_cast<uint32_t>(argv[0]);
    (void)exit_code;
    we(emu)->stop();
    return 0;
}

uint64_t Kernel32::Sleep(void* emu, ArgList& argv, void* ctx) {
    if (!argv.empty()) {
        auto ms = std::chrono::milliseconds(argv[0]);
        // std::this_thread::sleep_for(ms);
    }
    return 0;
}

uint64_t Kernel32::SleepEx(void* emu, ArgList& argv, void* ctx) {
    uint32_t ms = static_cast<uint32_t>(argv[0]);
    uint32_t alertable = static_cast<uint32_t>(argv[1]);
    (void)alertable;
    if (ms > 0) {
        // std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
    return 0;
}

uint64_t Kernel32::SwitchToThread(void* emu, ArgList& argv, void* ctx) {
    std::this_thread::yield();
    return 0;
}

uint64_t Kernel32::GetExitCodeProcess(void* emu, ArgList& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint64_t code_ptr = argv[1];
    (void)hProcess;
    if (code_ptr) {
        std::vector<uint8_t> buf(4);
        write_le(buf, 0, 0ULL, 4);
        mm(emu)->mem_write(code_ptr, buf);
    }
    return 1;
}

uint64_t Kernel32::GetExitCodeThread(void* emu, ArgList& argv, void* ctx) {
    uint64_t hThread = argv[0];
    uint64_t code_ptr = argv[1];
    (void)hThread;
    if (code_ptr) {
        std::vector<uint8_t> buf(4);
        write_le(buf, 0, 0x103ULL, 4);
        mm(emu)->mem_write(code_ptr, buf);
    }
    return 1;
}

uint64_t Kernel32::QueueUserAPC(void* emu, ArgList& argv, void* ctx) {
    uint64_t func = argv[0];
    uint64_t hThread = argv[1];
    uint64_t data = argv[2];
    (void)func; (void)hThread; (void)data;
    return 1;
}

uint64_t Kernel32::WinExec(void* emu, ArgList& argv, void* ctx) {
    uint64_t cmd_ptr = argv[0];
    uint32_t show = static_cast<uint32_t>(argv[1]);
    (void)show;
    std::string cmd;
    if (cmd_ptr) cmd = be(emu)->read_mem_string(cmd_ptr, 1);
    if (!cmd.empty()) {
        auto space = cmd.find(' ');
        std::string app = (space != std::string::npos) ? cmd.substr(0, space) : cmd;
        we(emu)->create_process(app, cmd, nullptr, false);
    }
    return 32;
}

uint64_t Kernel32::SetThreadPriority(void* emu, ArgList& argv, void* ctx) {
    uint64_t hThread = argv[0];
    int32_t priority = static_cast<int32_t>(argv[1]);
    (void)hThread; (void)priority;
    return 1;
}

uint64_t Kernel32::GetThreadPriority(void* emu, ArgList& argv, void* ctx) {
    uint64_t hThread = argv[0];
    (void)hThread;
    return 0;
}

// 
//  SYNC APIs
// 

uint64_t Kernel32::CreateEvent(void* emu, ArgList& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t manual_reset = static_cast<uint32_t>(argv[1]);
    uint32_t initial_state = static_cast<uint32_t>(argv[2]);
    uint64_t name_ptr = argv[3];
    (void)attrs; (void)manual_reset; (void)initial_state;
    std::string name;
    if (name_ptr) name = be(emu)->read_mem_string(name_ptr, 1);

    auto[h, evt] = we(emu)->create_event(name);
    if (h == 0) {
        w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
    } else {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    }
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::CreateMutex(void* emu, ArgList& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t initial_owner = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)attrs; (void)initial_owner;
    std::string name;
    if (name_ptr) name = be(emu)->read_mem_string(name_ptr, 1);
    argv[2] = name;

    auto [h, mut] = we(emu)->create_mutant(name);
    if (h == 0) {
        w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
    } else {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    }
    return static_cast<uint64_t>(h);
}


uint64_t Kernel32::OpenMutex(void* emu, ArgList& argv, void* ctx) {
    uint32_t access = static_cast<uint32_t>(argv[0]);
    uint32_t inherit = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)access; (void)inherit;
    if (!name_ptr) return 0;
    std::string name = be(emu)->read_mem_string(name_ptr, 1);
    auto obj = we(emu)->get_object_from_name(name);
    if (!obj) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    int h = we(emu)->get_object_handle(obj);
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::ReleaseMutex(void* emu, ArgList& argv, void* ctx) {
    uint64_t hMutex = argv[0];
    (void)hMutex;
    return 1;
}

uint64_t Kernel32::SetEvent(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py:4264-4279  SetEvent
    uint64_t hEvent = argv[0];
    auto obj = we(emu)->get_object_from_handle(hEvent);
    if (!obj) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::ResetEvent(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py:6039-6046  ResetEvent (no-op in emulation)
    uint64_t hEvent = argv[0];
    (void)hEvent;
    return 1;
}

uint64_t Kernel32::WaitForSingleObject(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python: returns WAIT_OBJECT_0 (0) immediately
    uint64_t hHandle = argv[0];
    uint32_t ms = static_cast<uint32_t>(argv[1]);
    (void)hHandle; (void)ms;
    return 0;  // WAIT_OBJECT_0
}

uint64_t Kernel32::WaitForMultipleObjects(void* emu, ArgList& argv, void* ctx) {
    uint32_t count = static_cast<uint32_t>(argv[0]);
    uint64_t handles_ptr = argv[1];
    uint32_t wait_all = static_cast<uint32_t>(argv[2]);
    uint32_t ms = static_cast<uint32_t>(argv[3]);
    (void)count; (void)handles_ptr; (void)wait_all; (void)ms;
    return 0;
}

uint64_t Kernel32::InitializeCriticalSection(void* emu, ArgList& argv, void* ctx) {
    uint64_t cs_ptr = argv[0];
    if (cs_ptr) {
        std::vector<uint8_t> cs_data(24, 0);
        mm(emu)->mem_write(cs_ptr, cs_data);
    }
    return 0;
}

uint64_t Kernel32::DeleteCriticalSection(void* emu, ArgList& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::EnterCriticalSection(void* emu, ArgList& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::LeaveCriticalSection(void* emu, ArgList& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::CreateWaitableTimer(void* emu, ArgList& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t manual_reset = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)attrs; (void)manual_reset; (void)name_ptr;
    return 1;
}

uint64_t Kernel32::SetWaitableTimer(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py:4196-4216  SetWaitableTimer
    uint64_t hTimer = argv[0];
    auto obj = we(emu)->get_object_from_handle(hTimer);
    if (!obj) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::CancelWaitableTimer(void* emu, ArgList& argv, void* ctx) {
    (void)ctx;
    // Python kernel32.py:4218-4233  CancelWaitableTimer
    uint64_t hTimer = argv[0];
    auto obj = we(emu)->get_object_from_handle(hTimer);
    if (!obj) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

// 
//  SYSTEM APIs
// 

uint64_t Kernel32::GetTickCount(void* emu, ArgList& argv, void* ctx) {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count() & 0xFFFFFFFF;
}

uint64_t Kernel32::GetSystemInfo(void* emu, ArgList& argv, void* ctx) {
    uint64_t lpSystemInfo = argv[0];
    if (!lpSystemInfo) return 0;
    int ps = ptr_sz(emu);
    if (ps == 8) {
        speakeasy::deffs::windows::SYSTEM_INFO<8> si;
        si.wProcessorArchitecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
        si.dwPageSize = 0x1000;
        si.lpMinimumApplicationAddress = 0x10000;
        si.lpMaximumApplicationAddress = 0x7FFFFFFF0000;
        si.dwActiveProcessorMask = 1;
        si.dwNumberOfProcessors = 1;
        si.dwProcessorType = 0;
        si.dwAllocationGranularity = 0x10000;
        si.wProcessorLevel = 0;
        si.wProcessorRevision = 0;
        mm(emu)->mem_write(lpSystemInfo, si.get_bytes());
    } else {
        speakeasy::deffs::windows::SYSTEM_INFO<4> si;
        si.wProcessorArchitecture = 0; // PROCESSOR_ARCHITECTURE_INTEL
        si.dwPageSize = 0x1000;
        si.lpMinimumApplicationAddress = 0x10000;
        si.lpMaximumApplicationAddress = 0x7FFEFFFF;
        si.dwActiveProcessorMask = 1;
        si.dwNumberOfProcessors = 1;
        si.dwProcessorType = 0;
        si.dwAllocationGranularity = 0x10000;
        si.wProcessorLevel = 0;
        si.wProcessorRevision = 0;
        mm(emu)->mem_write(lpSystemInfo, si.get_bytes());
    }
    return 0;
}

uint64_t Kernel32::GetVersion(void* emu, ArgList& argv, void* ctx) {
    (void)argv; (void)ctx;
    // Python kernel32.py: GetVersion  use config.os_ver
    auto& ver = we(emu)->get_config().os_ver;
    return 0xFFFFFFFF & ((static_cast<uint64_t>(ver.build) << 16) |
                         (static_cast<uint64_t>(ver.minor) << 8) |
                          static_cast<uint64_t>(ver.major));
}

uint64_t Kernel32::GetVersionEx(void* emu, ArgList& argv, void* ctx) {
    uint64_t info_ptr = argv[0];
    if (!info_ptr) return 0;
    auto& os = be(emu)->get_config().os_ver;
    speakeasy::deffs::windows::OSVERSIONINFO ver;
    ver.dwOSVersionInfoSize = 276;  // Size of OSVERSIONINFOW
    ver.dwMajorVersion = static_cast<uint32_t>(os.major);
    ver.dwMinorVersion = static_cast<uint32_t>(os.minor);
    ver.dwBuildNumber = static_cast<uint32_t>(os.build);
    ver.dwPlatformId = 2; // VER_PLATFORM_WIN32_NT
    mm(emu)->mem_write(info_ptr, ver.get_bytes());
    return 1;
}

uint64_t Kernel32::IsDebuggerPresent(void* emu, ArgList& argv, void* ctx) {
    return 0;
}

uint64_t Kernel32::SetErrorMode(void* emu, ArgList& argv, void* ctx) {
    uint32_t mode = static_cast<uint32_t>(argv[0]);
    (void)mode;
    return 0;
}

uint64_t Kernel32::GetSystemTime(void* emu, ArgList& argv, void* ctx) {
    uint64_t st_ptr = argv[0];
    if (!st_ptr) return 0;
    auto now = std::time(nullptr);
    auto* tm = std::gmtime(&now);
    speakeasy::deffs::windows::SYSTEMTIME st;
    st.wYear         = static_cast<uint16_t>(tm->tm_year + 1900);
    st.wMonth        = static_cast<uint16_t>(tm->tm_mon + 1);
    st.wDayOfWeek    = static_cast<uint16_t>(tm->tm_wday);
    st.wDay          = static_cast<uint16_t>(tm->tm_mday);
    st.wHour         = static_cast<uint16_t>(tm->tm_hour);
    st.wMinute       = static_cast<uint16_t>(tm->tm_min);
    st.wSecond       = static_cast<uint16_t>(tm->tm_sec);
    st.wMilliseconds = 0;
    mm(emu)->mem_write(st_ptr, st.get_bytes());
    return 0;
}

uint64_t Kernel32::GetLocalTime(void* emu, ArgList& argv, void* ctx) {
    return GetSystemTime(emu, argv, ctx);
}

uint64_t Kernel32::SystemTimeToFileTime(void* emu, ArgList& argv, void* ctx) {
    uint64_t st_ptr = argv[0];
    uint64_t ft_ptr = argv[1];
    (void)st_ptr;
    if (ft_ptr) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        uint64_t ft = 116444736000000000ULL + ns / 100;
        std::vector<uint8_t> ft_bytes(8);
        write_le(ft_bytes, 0, ft, 8);
        mm(emu)->mem_write(ft_ptr, ft_bytes);
    }
    return 1;
}

uint64_t Kernel32::FileTimeToSystemTime(void* emu, ArgList& argv, void* ctx) {
    uint64_t ft_ptr = argv[0];
    uint64_t st_ptr = argv[1];
    (void)ft_ptr;
    if (st_ptr) {
        auto now = std::time(nullptr);
        auto* tm = std::gmtime(&now);
        speakeasy::deffs::windows::SYSTEMTIME st;
        st.wYear         = static_cast<uint16_t>(tm->tm_year + 1900);
        st.wMonth        = static_cast<uint16_t>(tm->tm_mon + 1);
        st.wDayOfWeek    = static_cast<uint16_t>(tm->tm_wday);
        st.wDay          = static_cast<uint16_t>(tm->tm_mday);
        st.wHour         = static_cast<uint16_t>(tm->tm_hour);
        st.wMinute       = static_cast<uint16_t>(tm->tm_min);
        st.wSecond       = static_cast<uint16_t>(tm->tm_sec);
        st.wMilliseconds = 0;
        mm(emu)->mem_write(st_ptr, st.get_bytes());
    }
    return 1;
}

uint64_t Kernel32::QueryPerformanceCounter(void* emu, ArgList& argv, void* ctx) {
    uint64_t ptr = argv[0];
    if (ptr) {
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        std::vector<uint8_t> buf(8);
        write_le(buf, 0, ns, 8);
        mm(emu)->mem_write(ptr, buf);
    }
    return 1;
}

uint64_t Kernel32::QueryPerformanceFrequency(void* emu, ArgList& argv, void* ctx) {
    uint64_t ptr = argv[0];
    if (ptr) {
        std::vector<uint8_t> buf(8);
        write_le(buf, 0, 10000000ULL, 8);
        mm(emu)->mem_write(ptr, buf);
    }
    return 1;
}

uint64_t Kernel32::GetComputerName(void* emu, ArgList& argv, void* ctx) {
    uint64_t buf_ptr = argv[0];
    uint64_t size_ptr = argv[1];
    if (!buf_ptr || !size_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto sz_data = mm(emu)->mem_read(size_ptr, 4);
    uint32_t buf_sz = (sz_data.size() >= 4) ? static_cast<uint32_t>(read_le(sz_data, 0, 4)) : 0;
    std::string name = "DESKTOP";
    if (buf_sz <= name.size()) {
        w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        return 0;
    }
    name.push_back('\0');
    be(emu)->write_mem_string(name, buf_ptr, 1);
    write_le(sz_data, 0, static_cast<uint64_t>(name.size() - 1), 4);
    mm(emu)->mem_write(size_ptr, sz_data);
    return 1;
}

uint64_t Kernel32::GetUserName(void* emu, ArgList& argv, void* ctx) {
    uint64_t buf_ptr = argv[0];
    uint64_t size_ptr = argv[1];
    if (!buf_ptr || !size_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto sz_data = mm(emu)->mem_read(size_ptr, 4);
    uint32_t buf_sz = (sz_data.size() >= 4) ? static_cast<uint32_t>(read_le(sz_data, 0, 4)) : 0;
    std::string name = "User";
    if (buf_sz <= name.size()) {
        w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        return 0;
    }
    name.push_back('\0');
    be(emu)->write_mem_string(name, buf_ptr, 1);
    write_le(sz_data, 0, static_cast<uint64_t>(name.size() - 1), 4);
    mm(emu)->mem_write(size_ptr, sz_data);
    return 1;
}

uint64_t Kernel32::SetUnhandledExceptionFilter(void* emu, ArgList& argv, void* ctx) {
    uint64_t filter = argv[0];
    (void)filter;
    return 0;
}

// 
//  ERROR APIs
// 

uint64_t Kernel32::GetLastError(void* emu, ArgList& argv, void* ctx) {
    uint32_t err = static_cast<uint32_t>(w32(emu)->get_last_error());
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(err);
}

uint64_t Kernel32::SetLastError(void* emu, ArgList& argv, void* ctx) {
    uint32_t err = static_cast<uint32_t>(argv[0]);
    w32(emu)->set_last_error(static_cast<int>(err));
    return 0;
}

uint64_t Kernel32::RaiseException(void* emu, ArgList& argv, void* ctx) {
    uint32_t code = static_cast<uint32_t>(argv[0]);
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint32_t num_args = static_cast<uint32_t>(argv[2]);
    uint64_t args_ptr = argv[3];
    (void)code; (void)flags; (void)num_args; (void)args_ptr;
    return 0;
}

uint64_t Kernel32::UnhandledExceptionFilter(void* emu, ArgList& argv, void* ctx) {
    uint64_t exc_ptr = argv[0];
    (void)exc_ptr;
    return 0;
}

// 
//  STRING APIs
// 

uint64_t Kernel32::lstrlen(void* emu, ArgList& argv, void* ctx) {
    uint64_t str_ptr = argv[0];
    if (!str_ptr) return 0;
    std::string s = be(emu)->read_mem_string(str_ptr, 1);
    return static_cast<uint64_t>(s.size());
}

uint64_t Kernel32::lstrcpy(void* emu, ArgList& argv, void* ctx) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    if (!dst || !src) return dst;
    std::string s = be(emu)->read_mem_string(src, 1);
    s.push_back('\0');
    be(emu)->write_mem_string(s, dst, 1);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return dst;
}

uint64_t Kernel32::lstrcat(void* emu, ArgList& argv, void* ctx) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    if (!dst || !src) return dst;
    std::string s1 = be(emu)->read_mem_string(dst, 1);
    std::string s2 = be(emu)->read_mem_string(src, 1);
    s1 += s2;
    s1.push_back('\0');
    be(emu)->write_mem_string(s1, dst, 1);
    return dst;
}

uint64_t Kernel32::lstrcmp(void* emu, ArgList& argv, void* ctx) {
    uint64_t s1_ptr = argv[0];
    uint64_t s2_ptr = argv[1];
    if (!s1_ptr || !s2_ptr) return 1;
    std::string s1 = be(emu)->read_mem_string(s1_ptr, 1);
    std::string s2 = be(emu)->read_mem_string(s2_ptr, 1);
    if (s1 == s2) return 0;
    return (s1 < s2) ? -1 : 1;
}

uint64_t Kernel32::MultiByteToWideChar(void* emu, ArgList& argv, void* ctx) {
    uint32_t code_page = static_cast<uint32_t>(argv[0]);
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint64_t mb_str_ptr = argv[2];
    int32_t mb_len = static_cast<int32_t>(argv[3]);
    uint64_t wc_buf_ptr = argv[4];
    int32_t wc_buf_sz = static_cast<int32_t>(argv[5]);
    (void)code_page; (void)flags;
    if (!mb_str_ptr) return 0;
    std::string mb_str;
    if (mb_len < 0) {
        mb_str = be(emu)->read_mem_string(mb_str_ptr, 1);
    } else if (mb_len > 0) {
        auto data = mm(emu)->mem_read(mb_str_ptr, static_cast<size_t>(mb_len));
        mb_str.assign(data.begin(), data.end());
        auto null_pos = mb_str.find('\0');
        if (null_pos != std::string::npos) mb_str = mb_str.substr(0, null_pos);
    }
    std::vector<uint8_t> wc_buf;
    for (char c : mb_str) {
        wc_buf.push_back(static_cast<uint8_t>(c));
        wc_buf.push_back(0);
    }
    wc_buf.push_back(0);
    wc_buf.push_back(0);
    size_t wc_chars = (wc_buf.size() / 2);
    if (wc_buf_ptr && wc_buf_sz > 0) {
        size_t copy_len = std::min(static_cast<size_t>(wc_buf_sz * 2), wc_buf.size());
        mm(emu)->mem_write(wc_buf_ptr, std::vector<uint8_t>(wc_buf.begin(), wc_buf.begin() + copy_len));
    }
    if (wc_buf_sz == 0 || wc_buf_ptr == 0) {
        return static_cast<uint64_t>(wc_chars);
    }
    return static_cast<uint64_t>(wc_chars - 1);
}

uint64_t Kernel32::WideCharToMultiByte(void* emu, ArgList& argv, void* ctx) {
    uint32_t code_page = static_cast<uint32_t>(argv[0]);
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint64_t wc_str_ptr = argv[2];
    int32_t wc_len = static_cast<int32_t>(argv[3]);
    uint64_t mb_buf_ptr = argv[4];
    int32_t mb_buf_sz = static_cast<int32_t>(argv[5]);
    uint64_t default_char_ptr = argv[6];
    uint64_t used_ptr = argv[7];
    (void)code_page; (void)flags; (void)default_char_ptr; (void)used_ptr;
    if (!wc_str_ptr) return 0;
    std::string wc_str;
    if (wc_len < 0) {
        wc_str = be(emu)->read_mem_string(wc_str_ptr, 2);
    } else if (wc_len > 0) {
        auto data = mm(emu)->mem_read(wc_str_ptr, static_cast<size_t>(wc_len * 2));
        wc_str.resize(static_cast<size_t>(wc_len));
        for (int i = 0; i < wc_len && i * 2 + 1 < static_cast<int>(data.size()); i++) {
            wc_str[static_cast<size_t>(i)] = static_cast<char>(data[static_cast<size_t>(i) * 2]);
        }
    }
    std::vector<uint8_t> mb_buf;
    for (char c : wc_str) {
        if (c != 0) mb_buf.push_back(static_cast<uint8_t>(c));
    }
    mb_buf.push_back(0);
    if (mb_buf_ptr && mb_buf_sz > 0) {
        size_t copy_len = std::min(static_cast<size_t>(mb_buf_sz), mb_buf.size());
        mm(emu)->mem_write(mb_buf_ptr, std::vector<uint8_t>(mb_buf.begin(), mb_buf.begin() + copy_len));
    }
    if (mb_buf_sz == 0 || mb_buf_ptr == 0) {
        return static_cast<uint64_t>(mb_buf.size());
    }
    return static_cast<uint64_t>(mb_buf.size() - 1);
}

uint64_t Kernel32::GetCommandLine(void* emu, ArgList& argv, void* ctx) {
    (void)argv; (void)ctx;
    // Python kernel32.py: GetCommandLine  read from process cmdline, cache pointer
    auto proc = we(emu)->get_current_process();
    std::string cmdline = proc ? proc->get_command_line() : "emulated.exe";
    if (cmdline.empty()) cmdline = "emulated.exe";

    static thread_local std::map<int, uint64_t> cmdline_ptrs;
    uint64_t& ptr = cmdline_ptrs[1]; // cw=1 (ANSI)
    if (!ptr) {
        ptr = mm(emu)->mem_map((cmdline.size() + 1) * 2, 0, PERM_MEM_RW, "api.command_line");
    }
    cmdline.push_back('\0');
    be(emu)->write_mem_string(cmdline, ptr, 1);
    return ptr;
}


// 
//  ENVIRONMENT APIs
// 

uint64_t Kernel32::GetEnvironmentVariable(void* emu, ArgList& argv, void* ctx) {
    uint64_t name_ptr = argv[0];
    uint64_t buf_ptr = argv[1];
    uint32_t buf_sz = static_cast<uint32_t>(argv[2]);
    if (!name_ptr) return 0;
    std::string name = be(emu)->read_mem_string(name_ptr, 1);
    auto env = we(emu)->get_env();
    auto it = env.find(name);
    if (it == env.end()) {
        w32(emu)->set_last_error(K32_ERR_BAD_ENVIRONMENT);
        return 0;
    }
    std::string val = it->second;
    if (buf_ptr && buf_sz > 0) {
        if (buf_sz <= val.size()) {
            w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        } else {
            val.push_back('\0');
            be(emu)->write_mem_string(val, buf_ptr, 1);
        }
    }
    return static_cast<uint64_t>(val.size());
}

uint64_t Kernel32::SetEnvironmentVariable(void* emu, ArgList& argv, void* ctx) {
    uint64_t name_ptr = argv[0];
    uint64_t val_ptr = argv[1];
    if (!name_ptr) return 0;
    std::string name = be(emu)->read_mem_string(name_ptr, 1);
    if (val_ptr) {
        std::string val = be(emu)->read_mem_string(val_ptr, 1);
        argv[0] = name;
        argv[1] = val;
        we(emu)->set_env(name, val);
    }
    return 1;
}

uint64_t Kernel32::GetCurrentDirectory(void* emu, ArgList& argv, void* ctx) {
    uint64_t buf_ptr = argv[0];
    uint32_t buf_sz = static_cast<uint32_t>(argv[1]);
    std::string cd = we(emu)->get_cd();
    if (cd.empty()) cd = "C:\\";
    if (buf_ptr && buf_sz > 0) {
        if (buf_sz <= static_cast<uint32_t>(cd.size())) {
            w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        } else {
            cd.push_back('\0');
            be(emu)->write_mem_string(cd, buf_ptr, 1);
        }
    }
    return static_cast<uint64_t>(cd.size());
}

uint64_t Kernel32::SetCurrentDirectory(void* emu, ArgList& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    we(emu)->set_cd(path);
    return 1;
}

uint64_t Kernel32::ExpandEnvironmentStrings(void* emu, ArgList& argv, void* ctx) {
    uint64_t src_ptr = argv[0];
    uint64_t dst_ptr = argv[1];
    uint32_t dst_sz = static_cast<uint32_t>(argv[2]);
    if (!src_ptr) return 0;
    std::string src = be(emu)->read_mem_string(src_ptr, 1);
    std::string result;
    size_t i = 0;
    while (i < src.size()) {
        if (src[i] == '%') {
            size_t end = src.find('%', i + 1);
            if (end != std::string::npos) {
                std::string var = src.substr(i + 1, end - i - 1);
                auto env = we(emu)->get_env();
                auto it = env.find(var);
                if (it != env.end()) {
                    result += it->second;
                }
                i = end + 1;
                continue;
            }
        }
        result += src[i];
        i++;
    }
    if (dst_ptr && dst_sz > 0) {
        if (dst_sz <= static_cast<uint32_t>(result.size())) {
            w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        } else {
            result.push_back('\0');
            be(emu)->write_mem_string(result, dst_ptr, 1);
        }
    }
    return static_cast<uint64_t>(result.size());
}

// 
//  TOOLHELP APIs
// 

uint64_t Kernel32::CreateToolhelp32Snapshot(void* emu, ArgList& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    uint32_t pid = static_cast<uint32_t>(argv[1]);
    uint64_t hnd = g_next_snap_handle++;
    std::unordered_map<uint32_t, SnapEntry> entries;
    if (flags & K32_TH32CS_SNAPPROCESS) {
        auto& procs = we(emu)->get_processes();
        SnapEntry se;
        se.index = 0;
        se.pid = 0;
        for (auto& proc : procs) {
            se.items.push_back(proc.get());  // raw ptr resolved later by find_process()
        }
        entries[K32_TH32CS_SNAPPROCESS] = se;
    }
    if (flags & K32_TH32CS_SNAPTHREAD) {
        std::shared_ptr<Process> proc_obj = nullptr;
        auto& procs = we(emu)->get_processes();
        for (auto proc : procs) {
            if (proc && (pid == 0 || proc->get_pid() == static_cast<int>(pid))) {
                proc_obj = proc;
                break;
            }
        }
        SnapEntry se;
        se.index = 0;
        se.items.clear();
        se.pid = static_cast<int>(pid);
        if (proc_obj) {
            for (auto& t : proc_obj->threads) {
                se.items.push_back(t.get());
            }
        }
        entries[K32_TH32CS_SNAPTHREAD] = se;
    }
    if (flags & K32_TH32CS_SNAPMODULE) {
        auto mods = we(emu)->get_peb_modules();
        SnapEntry se;
        se.index = 0;
        se.pid = static_cast<int>(pid);
        for (auto& mod : mods) {
            se.items.push_back(mod.get());  // raw ptr resolved later
        }
        entries[K32_TH32CS_SNAPMODULE] = se;
    }
    g_snapshots[hnd] = entries;
    return hnd;
}

static uint64_t process32_impl(void* emu, const ArgList& argv, bool first) {
    uint64_t hSnap = argv[0];
    uint64_t pe32 = argv[1];
    if (!pe32) return 0;
    auto snap_it = g_snapshots.find(hSnap);
    if (snap_it == g_snapshots.end()) return 0;
    auto& snap = snap_it->second;
    auto proc_it = snap.find(K32_TH32CS_SNAPPROCESS);
    if (proc_it == snap.end()) return 0;
    auto& entry = proc_it->second;
    if (first) entry.index = 1;
    int idx = first ? 0 : entry.index;
    if (!first) entry.index++;
    if (idx >= static_cast<int>(entry.items.size())) {
        w32(emu)->set_last_error(K32_ERR_NO_MORE_FILES);
        return 0;
    }
    int ps = ptr_sz(emu);
    auto proc = we(emu)->find_process(entry.items[static_cast<size_t>(idx)]);
    if (!proc) return 0;
    std::string exe = proc->image.empty() ? "emulated.exe" : proc->image;
    if (ps == 8) {
        speakeasy::deffs::windows::PROCESSENTRY32<8> pe;
        pe.dwSize = pe.sizeof_obj();
        pe.th32ProcessID = static_cast<uint32_t>(proc->get_pid());
        size_t n = std::min(exe.size(), sizeof(pe.szExeFile) - 1);
        std::memcpy(pe.szExeFile, exe.c_str(), n);
        pe.szExeFile[n] = 0;
        mm(emu)->mem_write(pe32, pe.get_bytes());
    } else {
        speakeasy::deffs::windows::PROCESSENTRY32<4> pe;
        pe.dwSize = pe.sizeof_obj();
        pe.th32ProcessID = static_cast<uint32_t>(proc->get_pid());
        size_t n = std::min(exe.size(), sizeof(pe.szExeFile) - 1);
        std::memcpy(pe.szExeFile, exe.c_str(), n);
        pe.szExeFile[n] = 0;
        mm(emu)->mem_write(pe32, pe.get_bytes());
    }
    return 1;
}

uint64_t Kernel32::Process32First(void* emu, ArgList& argv, void* ctx) {
    return process32_impl(emu, argv, true);
}

uint64_t Kernel32::Process32Next(void* emu, ArgList& argv, void* ctx) {
    return process32_impl(emu, argv, false);
}

static uint64_t thread32_impl(void* emu, const ArgList& argv, bool first) {
    uint64_t hSnap = argv[0];
    uint64_t te32 = argv[1];
    if (!te32) return 0;
    auto snap_it = g_snapshots.find(hSnap);
    if (snap_it == g_snapshots.end()) return 0;
    auto& snap = snap_it->second;
    auto thr_it = snap.find(K32_TH32CS_SNAPTHREAD);
    if (thr_it == snap.end()) return 0;
    auto& entry = thr_it->second;
    if (first) entry.index = 1;
    int idx = first ? 0 : entry.index;
    if (!first) entry.index++;
    if (idx >= static_cast<int>(entry.items.size())) {
        w32(emu)->set_last_error(K32_ERR_NO_MORE_FILES);
        return 0;
    }
    auto* thread = static_cast<Thread*>(entry.items[static_cast<size_t>(idx)]);
    speakeasy::deffs::windows::THREADENTRY32 te;
    te.dwSize = te.sizeof_obj();
    te.th32ThreadID = static_cast<uint32_t>(thread->get_id());
    te.th32OwnerProcessID = static_cast<uint32_t>(entry.pid);
    mm(emu)->mem_write(te32, te.get_bytes());
    return 1;
}

uint64_t Kernel32::Thread32First(void* emu, ArgList& argv, void* ctx) {
    return thread32_impl(emu, argv, true);
}

uint64_t Kernel32::Thread32Next(void* emu, ArgList& argv, void* ctx) {
    return thread32_impl(emu, argv, false);
}

static uint64_t module32_impl(void* emu, const ArgList& argv, bool first) {
    uint64_t hSnap = argv[0];
    uint64_t me32 = argv[1];
    if (!me32) return 0;
    auto snap_it = g_snapshots.find(hSnap);
    if (snap_it == g_snapshots.end()) return 0;
    auto& snap = snap_it->second;
    auto mod_it = snap.find(K32_TH32CS_SNAPMODULE);
    if (mod_it == snap.end()) return 0;
    auto& entry = mod_it->second;
    if (first) entry.index = 1;
    int idx = first ? 0 : entry.index;
    if (!first) entry.index++;
    if (idx >= static_cast<int>(entry.items.size())) {
        w32(emu)->set_last_error(K32_ERR_NO_MORE_FILES);
        return 0;
    }
    int ps = ptr_sz(emu);
    auto* mod = static_cast<KernelObject*>(entry.items[static_cast<size_t>(idx)]);
    std::string mname = mod->get_obj_name();
    if (ps == 8) {
        speakeasy::deffs::windows::MODULEENTRY32<8> me;
        me.dwSize = me.sizeof_obj();
        me.th32ModuleID = static_cast<uint32_t>(mod->get_id());
        me.th32ProcessID = static_cast<uint32_t>(entry.pid);
        me.modBaseAddr = reinterpret_cast<uint64_t>(mod);
        me.modBaseSize = 0x1000;
        size_t n = std::min(mname.size(), sizeof(me.szModule) - 1);
        std::memcpy(me.szModule, mname.c_str(), n); me.szModule[n] = 0;
        std::memcpy(me.szExePath, mname.c_str(), n); me.szExePath[n] = 0;
        mm(emu)->mem_write(me32, me.get_bytes());
    } else {
        speakeasy::deffs::windows::MODULEENTRY32<4> me;
        me.dwSize = me.sizeof_obj();
        me.th32ModuleID = static_cast<uint32_t>(mod->get_id());
        me.th32ProcessID = static_cast<uint32_t>(entry.pid);
        me.modBaseAddr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(mod));
        me.modBaseSize = 0x1000;
        size_t n = std::min(mname.size(), sizeof(me.szModule) - 1);
        std::memcpy(me.szModule, mname.c_str(), n); me.szModule[n] = 0;
        std::memcpy(me.szExePath, mname.c_str(), n); me.szExePath[n] = 0;
        mm(emu)->mem_write(me32, me.get_bytes());
    }
    return 1;
}

uint64_t Kernel32::Module32First(void* emu, ArgList& argv, void* ctx) {
    return module32_impl(emu, argv, true);
}

uint64_t Kernel32::Module32Next(void* emu, ArgList& argv, void* ctx) {
    return module32_impl(emu, argv, false);
}

// 
//  CONSOLE / MISC APIs
// 

uint64_t Kernel32::AllocConsole(void* emu, ArgList& argv, void* ctx) {
    return 1;
}

uint64_t Kernel32::FreeConsole(void* emu, ArgList& argv, void* ctx) {
    return 1;
}

uint64_t Kernel32::GetConsoleMode(void* emu, ArgList& argv, void* ctx) {
    uint64_t hConsole = argv[0];
    uint64_t mode_ptr = argv[1];
    (void)hConsole;
    if (mode_ptr) {
        std::vector<uint8_t> mode_buf(4);
        write_le(mode_buf, 0, 0x7ULL, 4);
        mm(emu)->mem_write(mode_ptr, mode_buf);
    }
    return 1;
}

uint64_t Kernel32::SetConsoleMode(void* emu, ArgList& argv, void* ctx) {
    uint64_t hConsole = argv[0];
    uint32_t mode = static_cast<uint32_t>(argv[1]);
    (void)hConsole; (void)mode;
    return 1;
}

uint64_t Kernel32::OutputDebugString(void* emu, ArgList& argv, void* ctx) {
    uint64_t str_ptr = argv[0];
    if (str_ptr) {
        std::string msg = be(emu)->read_mem_string(str_ptr, 1);
        (void)msg;
    }
    return 0;
}

uint64_t Kernel32::GetACP(void* emu, ArgList& argv, void* ctx) {
    (void)emu; (void)argv; (void)ctx;
    // Python: return 1252 (ANSI Latin-1 / Windows-1252)
    return 1252;
}

uint64_t Kernel32::DecodePointer(void* emu, ArgList& argv, void* ctx) {
    (void)emu; (void)ctx;
    // Python: DecodePointer returns Ptr - 1
    return static_cast<uint64_t>(argv[0]) - 1;
}

uint64_t Kernel32::EncodePointer(void* emu, ArgList& argv, void* ctx) {
    (void)emu; (void)ctx;
    // Python: EncodePointer returns Ptr + 1
    return static_cast<uint64_t>(argv[0]) + 1;
}

uint64_t Kernel32::IsProcessorFeaturePresent(void* emu, ArgList& argv, void* ctx) {
    uint32_t feature = static_cast<uint32_t>(argv[0]);
    switch (feature) {
        case 0: case 1: return 0;
        default: return 1;
    }
}

// ==========================================
//  W function implementations (read UTF-16LE strings, delegate to A logic)
// ==========================================

uint64_t Kernel32::Process32FirstW(void* e, ArgList& a, void* c) {
    return process32_impl(e, a, true);
}
uint64_t Kernel32::Process32NextW(void* e, ArgList& a, void* c) {
    return process32_impl(e, a, false);
}
uint64_t Kernel32::Module32FirstW(void* e, ArgList& a, void* c) {
    return module32_impl(e, a, true);
}
uint64_t Kernel32::Module32NextW(void* e, ArgList& a, void* c) {
    return module32_impl(e, a, false);
}
// ==========================================
//  Synchronization primitives (no-ops in emulator)
// ==========================================

uint64_t Kernel32::AcquireSRWLockExclusive(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0; // void
}
uint64_t Kernel32::AcquireSRWLockShared(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::ReleaseSRWLockExclusive(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::ReleaseSRWLockShared(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::InitializeSRWLock(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::InitializeConditionVariable(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::InitializeCriticalSectionAndSpinCount(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
}
uint64_t Kernel32::InitializeCriticalSectionEx(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
}
uint64_t Kernel32::InitializeSListHead(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::InitOnceBeginInitialize(void* e, ArgList& a, void* c) {
    (void)a; return 1; // INIT_ONCE_ASYNC  caller should call InitOnceComplete
}
uint64_t Kernel32::WakeAllConditionVariable(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0;
}
uint64_t Kernel32::WaitForSingleObjectEx(void* e, ArgList& a, void* c) {
    (void)a; (void)c; return 0; // WAIT_OBJECT_0
}

// ==========================================
//  Simple getters / info functions
// ==========================================

uint64_t Kernel32::AddAtom(void* e, ArgList& a, void* c) {
    uint64_t str_ptr = a[0]; if (!str_ptr) return 0;
    std::string s = be(e)->read_mem_string(str_ptr, 1);
    static std::map<std::string, uint16_t> atoms; static uint16_t next = 0xC000;
    auto it = atoms.find(s); if (it != atoms.end()) return it->second;
    uint16_t id = next++; atoms[s] = id; return id;
}
uint64_t Kernel32::AddVectoredContinueHandler(void* e, ArgList& a, void* c) {
    (void)e; (void)c;
    // Python kernel32.py: AddVectoredContinueHandler returns Handler
    uint64_t First = a[0]; uint64_t Handler = a[1]; (void)First;
    return Handler;
}
uint64_t Kernel32::AddVectoredExceptionHandler(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: AddVectoredExceptionHandler calls emu.add_vectored_exception_handler
    uint64_t First = a[0]; uint64_t Handler = a[1];
    w32(e)->add_vectored_exception_handler(First != 0, Handler);
    return Handler;
}
uint64_t Kernel32::AreFileApisANSI(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 1; // TRUE
}
uint64_t Kernel32::CheckRemoteDebuggerPresent(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[1];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{0, 0, 0, 0}); // FALSE
    return 1;
}
uint64_t Kernel32::CompareFileTime(void* e, ArgList& a, void* c) {
    (void)a; return 0; // equal
}
uint64_t Kernel32::ConnectNamedPipe(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: ConnectNamedPipe  check pipe_get for valid handle
    uint64_t hNamedPipe = a[0]; uint64_t lpOverlapped = a[1]; (void)lpOverlapped;
    auto pipe = we(e)->pipe_get(static_cast<int>(hNamedPipe));
    if (pipe) { w32(e)->set_last_error(K32_ERR_SUCCESS); return 1; }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE); return 0;
}
uint64_t Kernel32::CreateIoCompletionPort(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: CreateIoCompletionPort  return a new handle
    uint64_t FileHandle = a[0]; uint64_t Existing = a[1];
    uint64_t Key = a[2]; uint64_t Threads = a[3];
    (void)FileHandle; (void)Existing; (void)Key; (void)Threads;
    auto result = we(e)->create_event("");  // placeholder handle
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::CreateMutexEx(void* e, ArgList& a, void* c) {
    uint64_t name_ptr = a[1];
    std::string name = name_ptr ? be(e)->read_mem_string(name_ptr, 2) : "";
    auto result = we(e)->create_mutant(name);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::CreateNamedPipe(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: CreateNamedPipe  read name, open pipe via pipe_open
    uint64_t name_ptr = a[0];
    uint64_t open_mode = a[1]; uint64_t pipe_mode = a[2];
    uint64_t max_inst = a[3]; uint64_t out_sz = a[4];
    uint64_t in_sz = a[5]; uint64_t timeout = a[6]; uint64_t attrs = a[7];
    (void)open_mode; (void)pipe_mode; (void)max_inst; (void)timeout; (void)attrs;
    if (name_ptr) {
        std::string name = be(e)->read_mem_string(name_ptr, 1);
        a[0] = name;
    }
    void* hnd = we(e)->pipe_open("", "rw", 1,
        static_cast<int>(out_sz ? out_sz : 4096),
        static_cast<int>(in_sz ? in_sz : 4096));
    if (hnd) { w32(e)->set_last_error(K32_ERR_SUCCESS); return reinterpret_cast<uint64_t>(hnd); }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE); return K32_INVALID_HANDLE;
}
uint64_t Kernel32::CreatePipe(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py:4586-4608  CreatePipe
    uint64_t read_pipe_ptr  = a[0];
    uint64_t write_pipe_ptr = a[1];
    uint64_t pipe_attrs     = a[2];
    uint64_t nSize          = a[3];
    (void)pipe_attrs;

    if (!read_pipe_ptr || !write_pipe_ptr) {
        w32(e)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    size_t sz = nSize ? static_cast<size_t>(nSize) : 4096;
    void* hnd = we(e)->pipe_open("", "rw", 1, static_cast<int>(sz), static_cast<int>(sz));
    if (!hnd) {
        w32(e)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    uint64_t hval = reinterpret_cast<uint64_t>(hnd);
    int ps = we(e)->get_ptr_size();
    std::vector<uint8_t> buf(ps == 8 ? 8 : 4);
    write_le(buf, 0, hval, buf.size());
    mm(e)->mem_write(read_pipe_ptr, buf);
    mm(e)->mem_write(write_pipe_ptr, buf);
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}
uint64_t Kernel32::CreateProcessInternal(void* e, ArgList& a, void* c) {
    // Python kernel32.py: CreateProcessInternal  delegate to CreateProcess (args shifted by 1)
    ArgList shifted = {a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10]};
    return Kernel32::CreateProcess(e, shifted, c);
}
uint64_t Kernel32::CreateSemaphoreW(void* e, ArgList& a, void* c) {
    // Python kernel32.py:3999-4046  CreateSemaphoreW
    (void)c;
    uint64_t attrs = a[0];
    uint64_t init_count = a[1];
    uint64_t max_count = a[2];
    uint64_t name_ptr = a[3];
    (void)attrs; (void)init_count; (void)max_count;
    std::string name;
    if (name_ptr) name = be(e)->read_mem_string(name_ptr, 2);
    auto result = we(e)->create_mutant(name);  // reused Mutant as generic named object
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::CreateWaitableTimerEx(void* e, ArgList& a, void* c) {
    // Python kernel32.py:4137-4170  CreateWaitableTimerEx
    (void)c;
    uint64_t attrs = a[0];
    uint64_t name_ptr = a[1];
    uint64_t flags = a[2];
    uint64_t access = a[3];
    (void)attrs; (void)flags; (void)access;
    std::string name;
    if (name_ptr) name = be(e)->read_mem_string(name_ptr, 1);
    auto result = we(e)->create_event(name);  // reused Event as generic waitable object
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::CreateWaitableTimerExW(void* e, ArgList& a, void* c) {
    (void)c;
    uint64_t name_ptr = a[1];
    std::string name;
    if (name_ptr) name = be(e)->read_mem_string(name_ptr, 2);
    auto result = we(e)->create_event(name);
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::DeleteAtom(void* e, ArgList& a, void* c) {
    (void)e; (void)c;
    // Python kernel32.py: DeleteAtom  check reserved range
    static const uint16_t ATOM_RESERVED = 0xC000;
    uint16_t nAtom = static_cast<uint16_t>(a[0]);
    if (nAtom < ATOM_RESERVED) return 0;
    w32(e)->set_last_error(K32_ERR_SUCCESS); return 0;
}
uint64_t Kernel32::DisconnectNamedPipe(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: DisconnectNamedPipe  check pipe_get
    uint64_t hNamedPipe = a[0];
    auto pipe = we(e)->pipe_get(static_cast<int>(hNamedPipe));
    if (pipe) { w32(e)->set_last_error(K32_ERR_SUCCESS); return 1; }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE); return 0;
}
uint64_t Kernel32::DuplicateHandle(void* e, ArgList& a, void* c) {
    uint64_t dst_ptr = a[4]; // lpTargetHandle
    if (dst_ptr) mm(e)->mem_write(dst_ptr, std::vector<uint8_t>{0x80, 0, 0, 0, 0, 0, 0, 0}); // dummy handle
    return 1;
}
uint64_t Kernel32::EnumProcesses(void* e, ArgList& a, void* c) {
    uint64_t buf_ptr = a[0]; uint32_t buf_sz = static_cast<uint32_t>(a[1]); uint64_t ret_ptr = a[2];
    auto& procs = we(e)->get_processes();
    uint32_t count = 0;
    for (size_t i = 0; i < procs.size() && (i + 1) * 4 <= buf_sz; i++) {
        uint32_t pid = static_cast<uint32_t>(procs[i]->get_pid());
        mm(e)->mem_write(buf_ptr + i * 4, std::vector<uint8_t>{(uint8_t)pid, (uint8_t)(pid >> 8), (uint8_t)(pid >> 16), (uint8_t)(pid >> 24)});
        count++;
    }
    if (ret_ptr) mm(e)->mem_write(ret_ptr, std::vector<uint8_t>{(uint8_t)(count * 4), 0, 0, 0});
    return 1;
}
uint64_t Kernel32::FindAtom(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: FindAtom  read string, search atom table
    uint64_t str_ptr = a[0];
    if (!str_ptr) { w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0; }
    std::string s = be(e)->read_mem_string(str_ptr, 1);
    a[0] = s;
    if (!s.empty() && s[0] == '#') {
        try { uint16_t n = static_cast<uint16_t>(std::stoi(s.substr(1))); if (n < 0xC000) return n; } catch (...) {}
    }
    // Search atom table (reuse AddAtom's static map via a shared lookup)
    return 0; // not found in our table
}
uint64_t Kernel32::FindFirstFileEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: delegates to FindFirstFile  fileman.find_files()
    uint64_t fname_ptr = a[0]; uint64_t level = a[1]; uint64_t data_ptr = a[2];
    uint64_t search_op = a[3]; uint64_t filter_ptr = a[4]; uint64_t flags = a[5];
    (void)level; (void)search_op; (void)filter_ptr; (void)flags;
    if (fname_ptr) {
        std::string fname = be(e)->read_mem_string(fname_ptr, 1);
        a[0] = fname;
        if (data_ptr) {
            std::vector<uint8_t> buf(320, 0); // WIN32_FIND_DATA
            size_t max_fn = (fname.size() > 259) ? 259 : fname.size();
            for (size_t i = 0; i < max_fn; i++) buf[44 + i] = static_cast<uint8_t>(fname[i]);
            mm(e)->mem_write(data_ptr, buf);
        }
        w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
    }
    w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND); return K32_INVALID_HANDLE;
}
uint64_t Kernel32::FindFirstVolume(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: get first drive's volume GUID via drive manager
    uint64_t name_ptr = a[0]; uint32_t buf_len = static_cast<uint32_t>(a[1]);
    auto dm = we(e)->get_drive_manager();
    if (dm) {
        auto it = dm->walk_drives();
        auto end = decltype(it)();
        (void)end;
        if (it != end) {
            std::string vol = it->volume_guid_path;
            a[0] = vol;
            if (name_ptr && buf_len > 0) be(e)->write_mem_string(vol, name_ptr, 2);
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return 0xB001; // search handle
        }
    }
    w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND); return K32_INVALID_HANDLE;
}
uint64_t Kernel32::FindNextVolume(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c;
    // Python: walks to next drive; C++ limitation: iterator can't be stored
    w32(e)->set_last_error(K32_ERR_NO_MORE_FILES); return 0;
}
uint64_t Kernel32::FindResource(void* e, ArgList& a, void* c) {
    (void)c;
    // Python: normalize identifier, search PE resource directory
    uint64_t hModule = a[0]; uint64_t name_ptr = a[1]; uint64_t type_ptr = a[2];
    auto mod = hModule ? we(e)->get_mod_from_addr(hModule) : nullptr;
    if (!mod) {
        auto mods = we32(e)->get_user_modules();
        if (!mods.empty()) mod = mods[0];
    }
    if (mod && name_ptr && type_ptr) {
        std::string name = be(e)->read_mem_string(name_ptr, 1);
        std::string type = be(e)->read_mem_string(type_ptr, 1);
        a[1] = name; a[2] = type;
        // Return a non-zero RVA as HRSRC handle
        return mod->base + 0x1000; // placeholder HRSRC
    }
    return 0; // NULL
}
uint64_t Kernel32::FindResourceEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python: same as FindResource plus language ID
    uint64_t hModule = a[0]; uint64_t type_ptr = a[1]; uint64_t name_ptr = a[2]; uint64_t lang = a[3];
    (void)lang;
    auto mod = hModule ? we(e)->get_mod_from_addr(hModule) : nullptr;
    if (!mod) { auto mods = we32(e)->get_user_modules(); if (!mods.empty()) mod = mods[0]; }
    if (mod && name_ptr && type_ptr) {
        a[1] = be(e)->read_mem_string(name_ptr, 2);
        a[2] = be(e)->read_mem_string(type_ptr, 2);
        return mod->base + 0x2000; // placeholder HRSRC
    }
    return 0;
}
uint64_t Kernel32::FindVolumeClose(void* e, ArgList& a, void* c) {
    (void)e; (void)c;
    // Python: pop hFindVolume from find_volumes dict
    uint64_t hFind = a[0];
    static std::map<uint64_t, size_t> vol_walkers;
    vol_walkers.erase(hFind);
    return 1;
}
uint64_t Kernel32::FlsGetValue2(void* e, ArgList& a, void* c) {
/*
        fls_index = argv[0]
        try:
            val = emu.get_fls_value(fls_index)  # get_fls_value can not be found anywhere
            return val if val else 0x1000
        except Exception:
            return 0x1000
*/
    (void)a; return 0x1000;
}
uint64_t Kernel32::FreeEnvironmentStrings(void* e, ArgList& a, void* c) {
    uint64_t penv = a[0];
    if (penv) {
        try { mm(e)->mem_free(penv); } catch (...) {}
    }
    return 1;
}

uint64_t Kernel32::FreeLibraryAndExitThread(void* e, ArgList& a, void* c) {
    (void)a; we(e)->on_run_complete(); return 0;
}
uint64_t Kernel32::FreeResource(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::GetAtomName(void* e, ArgList& a, void* c) {
    uint16_t atom = static_cast<uint16_t>(a[0]); uint64_t buf = a[1]; int sz = static_cast<int>(a[2]);
    (void)atom; (void)buf; (void)sz; return 0;
}
uint64_t Kernel32::GetBinaryType(void* e, ArgList& a, void* c) {
    (void)c;
    // Python: read file path, check if PE
    uint64_t path_ptr = a[0]; uint64_t out_ptr = a[1];
    if (path_ptr && out_ptr) {
        std::string path = be(e)->read_mem_string(path_ptr, 1);
        a[0] = path;
        // SCS_32BIT_BINARY = 0, SCS_64BIT_BINARY = 6
        uint32_t type = 0; // default 32-bit
        if (path.size() > 4) { std::string ext = path.substr(path.size() - 4); (void)ext; }
        mm(e)->mem_write(out_ptr, std::vector<uint8_t>{(uint8_t)type, 0, 0, 0});
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    }
    w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND); return 0;
}
uint64_t Kernel32::GetCPInfo(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GetCPInfo  returns code page info
    uint32_t CodePage = static_cast<uint32_t>(a[0]);
    uint64_t out_ptr = a[1];
    if (out_ptr) {
        std::vector<uint8_t> buf(20, 0); // CPINFOEX structure
        write_le(buf, 0, 4, 4); // MaxCharSize
        buf[2] = (CodePage == 65001) ? 0xA0 : 0; // UTF-8 lead byte
        mm(e)->mem_write(out_ptr, buf);
    }
    w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
}
uint64_t Kernel32::GetCommProperties(void* e, ArgList& a, void* c) {
    (void)a; return 0; // fail  no comm port in emulator
}
uint64_t Kernel32::GetCommTimeouts(void* e, ArgList& a, void* c) {
    (void)a; return 0;
}
uint64_t Kernel32::GetComputerNameEx(void* e, ArgList& a, void* c) {
    uint64_t buf_ptr = a[1]; uint64_t size_ptr = a[2];
    if (!buf_ptr || !size_ptr) { w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0; }
    std::string name = we(e)->get_hostname();
    be(e)->write_mem_string(name, buf_ptr, 2);
    uint32_t sz = static_cast<uint32_t>(name.size() + 1);
    mm(e)->mem_write(size_ptr, std::vector<uint8_t>{(uint8_t)sz, 0, 0, 0});
    return 1;
}
uint64_t Kernel32::GetConsoleTitle(void* e, ArgList& a, void* c) {
    (void)a; return 0; // no console
}
uint64_t Kernel32::GetConsoleWindow(void* e, ArgList& a, void* c) {
    (void)a; (void)c;
    // Python: get process console window handle
    auto proc = we(e)->get_current_process();
    if (proc) {
        return 1; // placeholder console window handle
    }
    return 0; // NULL = no console
}
uint64_t Kernel32::GetCurrentPackageId(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(15700); return 0; // APPMODEL_ERROR_NO_PACKAGE
}
uint64_t Kernel32::GetDateFormat(void* e, ArgList& a, void* c) {
    uint64_t buf_ptr = a[2];
    if (buf_ptr) be(e)->write_mem_string("2026-06-09", buf_ptr, 2);
    return 11; // strlen("2026-06-09") + 1 (including null)
}
uint64_t Kernel32::GetEnvironmentStrings(void* e, ArgList& a, void* c) {
    (void)a; (void)c;
    std::string out;
    auto env = we(e)->get_env();
    for (const auto& kv : env) {
        if (!out.empty()) out.push_back(' ');
        out += kv.first;
        out.push_back(' ');
        out += kv.second;
    }

    uint64_t env_ptr = mm(e)->mem_map(out.size() + 1, std::nullopt, 3, "api.environment.GetEnvironmentStringsA");
    if (!env_ptr) return 0;

    std::vector<uint8_t> data(out.begin(), out.end());
    data.push_back(0);
    mm(e)->mem_write(env_ptr, data);
    return env_ptr;
}

uint64_t Kernel32::GetErrorMode(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0; // SEM_FAILCRITICALERRORS = 0
}
uint64_t Kernel32::GetFileAttributesEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GetFileAttributesEx  read filename, get file attributes
    uint64_t fname_ptr = a[0]; uint64_t level = a[1]; uint64_t out_ptr = a[2];
    if (fname_ptr) {
        std::string fname = be(e)->read_mem_string(fname_ptr, 1);
        a[0] = fname;
        if (level == 0 && out_ptr) { // GetFileExInfoStandard
            std::vector<uint8_t> buf(24, 0); // WIN32_FILE_ATTRIBUTE_DATA
            write_le(buf, 0, 0x20, 4); // FILE_ATTRIBUTE_ARCHIVE
            mm(e)->mem_write(out_ptr, buf);
            w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
        }
    }
    w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND); return 0;
}
uint64_t Kernel32::GetFileSizeEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py:3994-4013  GetFileSizeEx
    int hFile = static_cast<int>(a[0]);
    uint64_t size_ptr = a[1];
    auto* f = static_cast<::File*>(we(e)->file_get(hFile));
    if (f) {
        uint64_t full_size = f->get_size();
        if (size_ptr) {
            std::vector<uint8_t> buf(8);
            write_le(buf, 0, full_size, 8);
            mm(e)->mem_write(size_ptr, buf);
        }
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    }
    w32(e)->set_last_error(K32_ERR_INVALID_PARAM);
    return 0;
}
uint64_t Kernel32::GetFullPathName(void* e, ArgList& a, void* c) {
    uint64_t fname_ptr = a[0]; uint32_t buf_sz = static_cast<uint32_t>(a[1]); uint64_t buf_ptr = a[2];
    if (!fname_ptr) return 0;
    std::string fname = be(e)->read_mem_string(fname_ptr, 1);
    if (buf_ptr && buf_sz > fname.size()) be(e)->write_mem_string(fname, buf_ptr, 1);
    return static_cast<uint64_t>(fname.size() + 1);
}
uint64_t Kernel32::GetHandleInformation(void* e, ArgList& a, void* c) {
    (void)a; return 0; // no flags
}
uint64_t Kernel32::GetLocaleInfo(void* e, ArgList& a, void* c) {
    uint32_t lcType = static_cast<uint32_t>(a[1]); uint64_t buf = a[2]; int sz = static_cast<int>(a[3]);
    if (buf && sz > 0) {
        if (lcType == 0x0001) be(e)->write_mem_string("0409", buf, 2); // LOCALE_ILANGUAGE
        else if (lcType == 0x0002) be(e)->write_mem_string("04090409", buf, 2); // LOCALE_SLANGUAGE
        else be(e)->write_mem_string("", buf, 2);
    }
    return 0;
}
uint64_t Kernel32::GetLogicalDrives(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c;
    return 0x1F; // C:, D:, E:, F:, G:
}
uint64_t Kernel32::GetLongPathName(void* e, ArgList& a, void* c) {
    uint64_t src = a[0]; uint64_t dst = a[1]; uint32_t sz = static_cast<uint32_t>(a[2]);
    if (!src) return 0;
    std::string s = be(e)->read_mem_string(src, 1);
    if (dst && sz > s.size()) be(e)->write_mem_string(s, dst, 1);
    return static_cast<uint64_t>(s.size() + 1);
}
uint64_t Kernel32::GetMailslotInfo(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(6); return 0; // ERROR_INVALID_HANDLE
}
uint64_t Kernel32::GetModuleFileNameEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GetModuleFileNameExA  get module path
    uint64_t hProcess = a[0]; uint64_t hModule = a[1];
    uint64_t buf_ptr = a[2]; uint32_t buf_sz = static_cast<uint32_t>(a[3]);
    (void)hProcess;
    auto mod = we(e)->get_mod_from_addr(hModule);
    if (mod && buf_ptr && buf_sz > 0) {
        std::string path = mod->emu_path;
        if (path.empty()) path = mod->name;
        if (path.size() >= buf_sz) path = path.substr(0, buf_sz - 1);
        be(e)->write_mem_string(path, buf_ptr, 1);
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return static_cast<uint64_t>(path.size());
    }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE);
    return 0;
}
uint64_t Kernel32::GetModuleHandleEx(void* e, ArgList& a, void* c) {
    // BOOL GetModuleHandleEx(DWORD dwFlags, LPCTSTR lpModuleName, HMODULE *phModule)
    uint32_t dwFlags = static_cast<uint32_t>(a[0]);
    uint64_t mod_name_ptr = a[1];
    uint64_t phModule = a[2];
    (void)dwFlags;

    uint64_t hmod = 0;
    if (!mod_name_ptr) {
        // NULL module name  return handle to the EXE that created the process
        auto p = we(e)->get_current_process();
        if (p) hmod = static_cast<uint64_t>(p->base);
    } else {
        std::string name = be(e)->read_mem_string(mod_name_ptr, 1);
        if (!name.empty()) {
            name = speakeasy::to_lower(name);
            auto dot = name.rfind(".dll");
            if (dot != std::string::npos) name = name.substr(0, dot);
            auto mods = we(e)->get_peb_modules();
            for (auto& mod : mods) {
                std::string mname = speakeasy::to_lower(mod->get_base_name());
                auto mdot = mname.rfind(".dll");
                if (mdot != std::string::npos) mname = mname.substr(0, mdot);
                if (mname == name) {
                    hmod = mod->base;
                    break;
                }
            }
        }
    }

    if (phModule) {
        std::vector<uint8_t> buf(static_cast<size_t>(ptr_sz(e)), 0);
        write_le(buf, 0, hmod, static_cast<size_t>(ptr_sz(e)));
        mm(e)->mem_write(phModule, buf);
    }

    return hmod ? 1 : 0;
}
uint64_t Kernel32::GetNativeSystemInfo(void* e, ArgList& a, void* c) {
    uint64_t info_ptr = a[0]; if (!info_ptr) return 0;
    int ps = ptr_sz(e);
    auto info = std::vector<uint8_t>(static_cast<size_t>(ps == 4 ? 36 : 48), 0);
    info[0] = static_cast<uint8_t>(ps == 4 ? 0 : 9); // PROCESSOR_ARCHITECTURE
    info[1] = 1; // page size low byte
    info[24] = 1; // number of processors low byte
    mm(e)->mem_write(info_ptr, info);
    return 0;
}
uint64_t Kernel32::GetOEMCP(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 437; // OEM United States
}
uint64_t Kernel32::GetPhysicallyInstalledSystemMemory(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[0];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{0, 0, 0x10, 0, 0, 0, 0, 0}); // 1GB
    return 1;
}
uint64_t Kernel32::GetProcessAffinityMask(void* e, ArgList& a, void* c) {
    uint64_t proc_ptr = a[1]; uint64_t sys_ptr = a[2];
    if (proc_ptr) mm(e)->mem_write(proc_ptr, std::vector<uint8_t>{1, 0, 0, 0, 0, 0, 0, 0});
    if (sys_ptr) mm(e)->mem_write(sys_ptr, std::vector<uint8_t>{0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0});
    return 1;
}
uint64_t Kernel32::GetProcessHandleCount(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[1];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{42, 0, 0, 0});
    return 1;
}
uint64_t Kernel32::GetProcessVersion(void* e, ArgList& a, void* c) {
    uint32_t pid = static_cast<uint32_t>(a[0]); (void)pid;
    return (6 << 16) | 1; // Windows 6.1
}
uint64_t Kernel32::GetProfileInt(void* e, ArgList& a, void* c) {
    (void)a; return 0;
}
uint64_t Kernel32::GetShortPathName(void* e, ArgList& a, void* c) {
    uint64_t src = a[0]; uint64_t dst = a[1]; uint32_t sz = static_cast<uint32_t>(a[2]);
    if (!src) return 0;
    std::string s = be(e)->read_mem_string(src, 1);
    if (dst && sz > s.size()) be(e)->write_mem_string(s, dst, 1);
    return static_cast<uint64_t>(s.size() + 1);
}
uint64_t Kernel32::GetStartupInfo(void* e, ArgList& a, void* c) {
    // Python kernel32.py: GetStartupInfo  fill STARTUPINFO with desktop/title/standard handles
    uint64_t info_ptr = a[0];
    if (!info_ptr) return 0;

    int ps = ptr_sz(e);
    auto proc = we(e)->get_current_process();

    std::string desk_name = proc ? proc->get_desktop_name() : "Default";
    std::string title_name = proc ? proc->get_title_name() : "";
    if (title_name.empty()) title_name = proc ? proc->path : "emulated.exe";

    if (ps == 4) {
        speakeasy::deffs::windows::STARTUPINFO<4> si;
        si.cb = si.sizeof_obj();
        si.hStdInput = 0;
        si.hStdOutput = 1;
        si.hStdError = 2;
        // Allocate desktop name as UTF-8 (ANSI path  common for x86)
        {
            std::string out = desk_name;
            uint64_t ptr = mm(e)->mem_map(out.size() + 2, std::nullopt, PERM_MEM_RW,
                                         "api.struct.STARTUPINFOA.lpDesktop");
            be(e)->write_mem_string(out, ptr, 1);
            si.lpDesktop = static_cast<uint32_t>(ptr);
        }
        // Allocate title as UTF-8
        {
            std::string out = title_name;
            uint64_t ptr = mm(e)->mem_map(out.size() + 2, std::nullopt, PERM_MEM_RW,
                                         "api.struct.STARTUPINFOA.lpTitle");
            be(e)->write_mem_string(out, ptr, 1);
            si.lpTitle = static_cast<uint32_t>(ptr);
        }
        mm(e)->mem_write(info_ptr, si.get_bytes());
    } else {
        speakeasy::deffs::windows::STARTUPINFO<8> si;
        si.cb = si.sizeof_obj();
        si.hStdInput = 0;
        si.hStdOutput = 1;
        si.hStdError = 2;
        // Allocate desktop name as UTF-16 (Unicode path  default for x64)
        {
            uint64_t ptr = mm(e)->mem_map((desk_name.size() + 1) * 2, std::nullopt, PERM_MEM_RW,
                                         "api.struct.STARTUPINFOW.lpDesktop");
            be(e)->write_mem_string(desk_name, ptr, 2);
            si.lpDesktop = ptr;
        }
        // Allocate title as UTF-16
        {
            uint64_t ptr = mm(e)->mem_map((title_name.size() + 1) * 2, std::nullopt, PERM_MEM_RW,
                                         "api.struct.STARTUPINFOW.lpTitle");
            be(e)->write_mem_string(title_name, ptr, 2);
            si.lpTitle = ptr;
        }
        mm(e)->mem_write(info_ptr, si.get_bytes());
    }
    return 0;
}
uint64_t Kernel32::GetStringType(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: GetStringTypeA  delegate to GetStringTypeW (first arg is Locale, shift)
    ArgList shifted = {a[1], a[2], a[3], a[4]};
    return Kernel32::GetStringTypeW(emu, shifted, c);
}
uint64_t Kernel32::GetStringTypeW(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: GetStringTypeW  classify chars, write CT_CTYPE1 flags
    uint32_t dwInfoType = static_cast<uint32_t>(a[0]);
    uint64_t lpSrcStr   = a[1];
    int      cchSrc     = static_cast<int>(a[2]);
    uint64_t lpCharType = a[3];

    if (dwInfoType != 1) return 0; // only CT_CTYPE1 supported
    if (!lpSrcStr || cchSrc <= 0 || !lpCharType) return 0;

    int cw = get_char_width(static_cast<ApiContext*>(c));
    if (cw == 0) cw = 2;

    // Character type flags (prefix to avoid Windows SDK macro conflicts)
    const uint16_t CT1_UPPER = 0x0001, CT1_LOWER = 0x0002, CT1_DIGIT = 0x0004, CT1_SPACE = 0x0008;
    const uint16_t CT1_PUNCT = 0x0010, CT1_CNTRL = 0x0020, CT1_BLANK = 0x0040, CT1_XDIGIT = 0x0080;
    const uint16_t CT1_ALPHA = 0x0100, CT1_DEFINED = 0x0200;

    auto raw = mm(emu)->mem_read(lpSrcStr, static_cast<size_t>(cchSrc * cw));
    std::vector<uint8_t> output;
    output.reserve(static_cast<size_t>(cchSrc) * 2);

    for (int i = 0; i + cw <= static_cast<int>(raw.size()); i += cw) {
        uint64_t wc = (cw == 2) ? read_le(raw, static_cast<size_t>(i), 2)
                                : static_cast<uint64_t>(raw[static_cast<size_t>(i)]);
        uint16_t ctype = 0;
        // Punct
        if ((wc > 0x20 && wc < 0x30) || (wc >= 0x3A && wc <= 0x40) ||
            (wc >= 0x5B && wc <= 0x60) || (wc >= 0x7B && wc <= 0x7E))
            ctype |= CT1_PUNCT;
        // Control
        if (wc < 0x20 || wc == 0x7F)
            ctype |= CT1_CNTRL;
        // Space (tab, newline, etc.)
        if (wc >= 0x9 && wc <= 0xD)
            ctype |= CT1_SPACE;
        if (wc == 0x20)
            ctype |= CT1_BLANK | CT1_SPACE;
        // Upper
        if (wc >= 0x41 && wc <= 0x5A)
            ctype |= CT1_UPPER;
        // Lower
        if (wc >= 0x61 && wc <= 0x7A)
            ctype |= CT1_LOWER;
        // Digit
        if (wc >= 0x30 && wc <= 0x39)
            ctype |= CT1_DIGIT;
        // XDigit
        if ((wc >= 0x30 && wc <= 0x39) || (wc >= 0x41 && wc <= 0x46) || (wc >= 0x61 && wc <= 0x66))
            ctype |= CT1_XDIGIT;
        // Alpha
        if (ctype & (CT1_UPPER | CT1_LOWER))
            ctype |= CT1_ALPHA;
        // Defined
        if (wc != 0)
            ctype |= CT1_DEFINED;

        std::vector<uint8_t> b(2);
        write_le(b, 0, ctype, 2);
        output.insert(output.end(), b.begin(), b.end());
    }

    if (!output.empty()) {
        mm(emu)->mem_write(lpCharType, output);
        return 1;
    }
    return 0;
}
uint64_t Kernel32::GetSystemDefaultLCID(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409; // en-US
}
uint64_t Kernel32::GetSystemDefaultLangID(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetSystemDefaultUILanguage(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetSystemDirectory(void* e, ArgList& a, void* c) {
    uint64_t buf = a[0]; uint32_t sz = static_cast<uint32_t>(a[1]);
    std::string dir = "C:\\Windows\\System32";
    if (buf && sz > dir.size()) be(e)->write_mem_string(dir, buf, 1);
    return static_cast<uint64_t>(dir.size());
}
uint64_t Kernel32::GetSystemFirmwareTable(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(1); return 0; // ERROR_INVALID_FUNCTION
}
uint64_t Kernel32::GetSystemTimePreciseAsFileTime(void* e, ArgList& a, void* c) {
    uint64_t ft_ptr = a[0];
    if (!ft_ptr) return 0;
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    uint64_t ft = static_cast<uint64_t>(us) * 10 + 116444736000000000ULL; // 100ns intervals since 1601
    std::vector<uint8_t> ft_bytes(8, 0);
    for (int i = 0; i < 8; i++) ft_bytes[i] = static_cast<uint8_t>((ft >> (i * 8)) & 0xFF);
    mm(e)->mem_write(ft_ptr, ft_bytes);
    return 0;
}
uint64_t Kernel32::GetSystemTimes(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GetSystemTimes  write FILETIME structs to output pointers
    uint64_t idle_ptr   = a[0];
    uint64_t kernel_ptr = a[1];
    uint64_t user_ptr   = a[2];
    static uint64_t tick = 0;
    tick += 10000000;
    auto write_ft = [&](uint64_t ptr) {
        if (ptr) { std::vector<uint8_t> buf(8); write_le(buf, 0, tick, 8); mm(e)->mem_write(ptr, buf); }
    };
    write_ft(idle_ptr);
    write_ft(kernel_ptr);
    write_ft(user_ptr);
    return 1;
}
uint64_t Kernel32::GetTempFileName(void* e, ArgList& a, void* c) {
    uint64_t dir_ptr = a[0]; uint64_t prefix_ptr = a[1]; uint32_t unique = static_cast<uint32_t>(a[2]); uint64_t buf = a[3];
    std::string dir = dir_ptr ? be(e)->read_mem_string(dir_ptr, 1) : "C:\\Windows\\Temp";
    std::string prefix = prefix_ptr ? be(e)->read_mem_string(prefix_ptr, 1) : "TMP";
    if (unique == 0) unique = 1;
    char tmp[256]; snprintf(tmp, sizeof(tmp), "%s\\%s%04X.tmp", dir.c_str(), prefix.c_str(), unique & 0xFFFF);
    if (buf) be(e)->write_mem_string(std::string(tmp), buf, 1);
    return static_cast<uint64_t>(unique);
}
uint64_t Kernel32::GetTempPath(void* e, ArgList& a, void* c) {
    uint32_t sz = static_cast<uint32_t>(a[0]); uint64_t buf = a[1];
    std::string path = "C:\\Windows\\Temp\\";
    if (buf && sz > path.size()) be(e)->write_mem_string(path, buf, 1);
    return static_cast<uint64_t>(path.size() + 1);
}
uint64_t Kernel32::GetThreadContext(void* emu, ArgList& argv, void* ctx) {
    // BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
    uint64_t hThread = argv[0];
    uint64_t lpContext = argv[1];
    if (!lpContext) return 0;

    // Look up the thread by handle
    auto thread = we(emu)->find_thread(static_cast<int>(hThread));
    if (!thread) {
        w32(emu)->set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    // Get the thread's saved context
    auto saved_ctx = thread->get_context();
    if (!saved_ctx) {
        auto ctx_data = saved_ctx->get_bytes();
        we(emu)->mem_write(lpContext, ctx_data);
        return 1;
    }

    return 0;
}
// ==========================================
//  Thread / time / misc getters
// ==========================================
uint64_t Kernel32::GetThreadId(void* e, ArgList& a, void* c) {
    uint64_t hThread = a[0]; auto t = we(e)->find_thread(static_cast<int>(hThread));
    return t ? static_cast<uint64_t>(t->get_tid()) : 0;
}
uint64_t Kernel32::GetThreadLocale(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409; // en-US
}
uint64_t Kernel32::GetThreadTimes(void* e, ArgList& a, void* c) {
    (void)a; return 1; // success, times left at 0
}
uint64_t Kernel32::GetThreadUILanguage(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetTickCount64(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c;
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return static_cast<uint64_t>(ms);
}
uint64_t Kernel32::GetTimeFormat(void* e, ArgList& a, void* c) {
    uint64_t buf = a[2]; (void)a[0]; (void)a[1]; (void)a[3];
    if (buf) be(e)->write_mem_string("12:00:00", buf, 2);
    return 9;
}
uint64_t Kernel32::GetTimeZoneInformation(void* e, ArgList& a, void* c) {
    uint64_t info_ptr = a[0]; if (!info_ptr) return 0xFFFFFFFF;
    auto buf = std::vector<uint8_t>(172, 0); // TIME_ZONE_INFORMATION size
    buf[0] = static_cast<uint8_t>(0xFF); buf[1] = static_cast<uint8_t>(0xFF); // Bias = -60 (UTC-1) stored as LONG
    be(e)->write_mem_string("GMT Standard Time", info_ptr + 4, 2);   // StandardName at offset 4
    be(e)->write_mem_string("GMT Daylight Time", info_ptr + 68, 2);  // DaylightName at offset 68
    return 1; // TIME_ZONE_ID_STANDARD
}
uint64_t Kernel32::GetUserDefaultLCID(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetUserDefaultLangID(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetUserDefaultUILanguage(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0x0409;
}
uint64_t Kernel32::GetVolumeInformation(void* e, ArgList& a, void* c) {
    uint64_t name_buf = a[1]; uint64_t vol_buf = a[3]; uint64_t fs_buf = a[7];
    if (name_buf) be(e)->write_mem_string("SPEAKEASY", name_buf, 2);
    if (vol_buf) mm(e)->mem_write(vol_buf, std::vector<uint8_t>{0xFF, 0xFF, 0xFF, 0xFF});
    if (fs_buf) be(e)->write_mem_string("NTFS", fs_buf, 2);
    return 1;
}
uint64_t Kernel32::GetVolumePathNamesForVolumeName(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(1); return 0; // ERROR_INVALID_FUNCTION
}
uint64_t Kernel32::GetWindowsDirectory(void* e, ArgList& a, void* c) {
    uint64_t buf = a[0]; uint32_t sz = static_cast<uint32_t>(a[1]);
    std::string dir = "C:\\Windows";
    if (buf && sz > dir.size()) be(e)->write_mem_string(dir, buf, 1);
    return static_cast<uint64_t>(dir.size());
}
uint64_t Kernel32::GlobalAddAtom(void* e, ArgList& a, void* c) {
    uint64_t str_ptr = a[0]; if (!str_ptr) return 0;
    std::string s = be(e)->read_mem_string(str_ptr, 1);
    static std::map<std::string, uint16_t> atoms; static uint16_t next = 0xC100;
    auto it = atoms.find(s); if (it != atoms.end()) return it->second;
    uint16_t id = next++; atoms[s] = id; return id;
}
uint64_t Kernel32::GlobalFlags(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GlobalFlags  lookup hMem in memory maps, return flags
    uint64_t hMem = a[0];
    if (!hMem) { w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0; }
    auto maps = we(e)->get_mem_maps();
    for (auto& mmap : maps) {
        if (hMem == mmap->get_base()) {
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return static_cast<uint64_t>(mmap->get_flags());
        }
    }
    w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0;
}
uint64_t Kernel32::GlobalHandle(void* e, ArgList& a, void* c) {
    (void)e; (void)c;
    // Python kernel32.py: GlobalHandle returns hMem (handle == address in emulation)
    return static_cast<uint64_t>(a[0]);
}
uint64_t Kernel32::GlobalLock(void* e, ArgList& a, void* c) {
    return a[0]; // hMem is the same as the locked address in emulation
}
uint64_t Kernel32::GlobalMemoryStatus(void* e, ArgList& a, void* c) {
    uint64_t buf = a[0]; if (!buf) return 0;
    auto s = std::vector<uint8_t>(32, 0); // MEMORYSTATUS size
    s[0] = 32; // dwLength
    s[4] = 0xFF; s[5] = 0xFF; s[6] = 0xFF; s[7] = 0xFF; // dwMemoryLoad
    s[8] = 0; s[9] = 0; s[10] = 0x10; s[11] = 0; // dwTotalPhys ~1GB
    s[16] = 0; s[17] = 0; s[18] = 0x08; s[19] = 0; // dwAvailPhys ~512MB
    mm(e)->mem_write(buf, s); return 0;
}
uint64_t Kernel32::GlobalMemoryStatusEx(void* e, ArgList& a, void* c) {
    uint64_t buf = a[0]; if (!buf) return 0;
    auto s = std::vector<uint8_t>(64, 0); s[0] = 64;
    s[8] = 0; s[9] = 0; s[10] = 0x10; s[11] = 0; // ullTotalPhys
    s[24] = 0; s[25] = 0; s[26] = 0x08; s[27] = 0; // ullAvailPhys
    mm(e)->mem_write(buf, s); return 1;
}
uint64_t Kernel32::GlobalSize(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: GlobalSize  lookup hMem in memory maps, return size
    uint64_t hMem = a[0];
    if (!hMem) { w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0; }
    auto maps = we(e)->get_mem_maps();
    for (auto& mmap : maps) {
        if (hMem == mmap->get_base()) {
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return mmap->get_size();
        }
    }
    w32(e)->set_last_error(K32_ERR_INVALID_PARAM); return 0;
}
uint64_t Kernel32::GlobalUnlock(void* e, ArgList& a, void* c) {
    (void)e; (void)c;
    // Python kernel32.py: GlobalUnlock returns TRUE (1); not locked count is 0 (success)
    uint64_t hMem = a[0]; (void)hMem;
    return 1; // success, not locked count = 0
}
uint64_t Kernel32::HeapReAlloc(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py:2256-2280  HeapReAlloc
    uint64_t hHeap   = a[0];
    uint64_t dwFlags = a[1];
    uint64_t lpMem   = a[2];
    uint64_t dwBytes = a[3];
    (void)dwFlags;

    if (!hHeap || !lpMem || !dwBytes) return 0;

    auto region = we(e)->get_address_map(lpMem);
    if (!region) return 0;
    if (region->get_tag().find("api.heap") != 0) return 0;

    // Copy existing data into new allocation
    std::vector<uint8_t> data = mm(e)->mem_read(lpMem, static_cast<size_t>(region->get_size()));
    uint64_t new_buf = we32(e)->heap_alloc(static_cast<size_t>(dwBytes), "HeapReAlloc");
    if (new_buf && !data.empty()) {
        mm(e)->mem_write(new_buf, data);
    }
    return new_buf;
}
uint64_t Kernel32::HeapSetInformation(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::HeapSize(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: HeapSize  lookup lpMem in memory maps
    uint64_t lpMem = a[2];
    if (!lpMem) return 0xFFFFFFFF; // SIZE_T(-1)
    auto maps = we(e)->get_mem_maps();
    for (auto& mmap : maps) {
        if (lpMem == mmap->get_base()) {
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return mmap->get_size();
        }
    }
    w32(e)->set_last_error(K32_ERR_INVALID_PARAM);
    return 0xFFFFFFFF;
}
uint64_t Kernel32::IsBadReadPtr(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: IsBadReadPtr  check is_address_valid for [lp, lp+ucb-1]
    uint64_t lp = a[0]; uint64_t ucb = a[1];
    if (!lp || !ucb) return 1; // TRUE = bad pointer
    if (we(e)->is_address_valid(lp) && we(e)->is_address_valid(lp + ucb - 1))
        return 0; // FALSE = valid
    return 1; // TRUE = bad pointer
}
uint64_t Kernel32::IsBadStringPtr(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: IsBadStringPtrA  check address range with char_width=1
    uint64_t lp = a[0]; uint64_t ucchMax = a[1];
    if (!lp || !ucchMax) return 1; // TRUE = bad pointer
    int cw = 1;
    if (we(e)->is_address_valid(lp) && we(e)->is_address_valid(lp + cw * ucchMax - cw))
        return 0; // FALSE = valid
    return 1; // TRUE = bad pointer
}
uint64_t Kernel32::IsBadWritePtr(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: IsBadWritePtr  check is_address_valid for [lp, lp+ucb-1]
    uint64_t lp = a[0]; uint64_t ucb = a[1];
    if (!lp || !ucb) return 1; // TRUE = bad pointer
    if (we(e)->is_address_valid(lp) && we(e)->is_address_valid(lp + ucb - 1))
        return 0; // FALSE = valid
    return 1; // TRUE = bad pointer
}
uint64_t Kernel32::IsDBCSLeadByte(void* e, ArgList& a, void* c) {
    (void)a; return 0; // No DBCS in emulated environment
}
uint64_t Kernel32::IsValidCodePage(void* e, ArgList& a, void* c) {
    uint32_t cp = static_cast<uint32_t>(a[0]);
    if (cp == 437 || cp == 850 || cp == 1252 || cp == 65001) return 1;
    return 0;
}
uint64_t Kernel32::IsValidLocale(void* e, ArgList& a, void* c) {
    (void)a; return 1; // All locales valid
}
uint64_t Kernel32::IsWow64Process(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[1];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{0, 0, 0, 0}); // FALSE  we're 32-bit native
    return 1;
}
uint64_t Kernel32::LCMapString(void* e, ArgList& a, void* c) {
    uint64_t src = a[2]; int src_len = static_cast<int>(a[3]); uint64_t dst = a[4]; int dst_len = static_cast<int>(a[5]);
    if (!src || !dst) return 0;
    if (src_len < 0) src_len = static_cast<int>(be(e)->read_mem_string(src, 1).size());
    std::string s = be(e)->read_mem_string(src, 1);
    be(e)->write_mem_string(s, dst, 1);
    return static_cast<uint64_t>(std::min(src_len, dst_len));
}
uint64_t Kernel32::LCMapStringEx(void* e, ArgList& a, void* c) {
    return LCMapString(e, a, c); // same behavior
}
uint64_t Kernel32::LoadResource(void* e, ArgList& a, void* c) {
    (void)a; return 0; // NULL  not found
}
uint64_t Kernel32::LocalLock(void* e, ArgList& a, void* c) {
    return a[0]; // hMem == locked address
}
uint64_t Kernel32::LocalReAlloc(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py:2282-2313  LocalReAlloc
    uint64_t hMem   = a[0];
    uint64_t uBytes = a[1];
    uint64_t uFlags = a[2];
    (void)uFlags;

    if (!hMem || !uBytes) return 0;

    auto region = we(e)->get_address_map(hMem);
    if (!region) return 0;
    if (region->get_tag().find("api.heap") != 0) return 0;

    // Copy existing data into new allocation
    std::vector<uint8_t> data = mm(e)->mem_read(hMem, static_cast<size_t>(region->get_size()));
    uint64_t new_buf = we32(e)->heap_alloc(static_cast<size_t>(uBytes), "LocalReAlloc");
    if (new_buf && !data.empty()) {
        mm(e)->mem_write(new_buf, data);
    }
    return new_buf;
}
uint64_t Kernel32::LockResource(void* e, ArgList& a, void* c) {
    return a[0]; // hResData == locked address
}
uint64_t Kernel32::MoveFile(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: MoveFile  resolve src/dst names, delegate to file manager
    uint64_t src_ptr = a[0];
    uint64_t dst_ptr = a[1];
    std::string src = src_ptr ? be(e)->read_mem_string(src_ptr, 1) : "";
    std::string dst = dst_ptr ? be(e)->read_mem_string(dst_ptr, 1) : "";
    a[0] = src;
    a[1] = dst;
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}
uint64_t Kernel32::MulDiv(void* e, ArgList& a, void* c) {
    int32_t n = static_cast<int32_t>(a[0]); int32_t num = static_cast<int32_t>(a[1]); int32_t den = static_cast<int32_t>(a[2]);
    if (den == 0) return static_cast<uint64_t>(-1);
    return static_cast<uint64_t>(static_cast<int64_t>(n) * num / den);
}
uint64_t Kernel32::OpenEvent(void* e, ArgList& a, void* c) {
    // Python kernel32.py:4235-4259  OpenEvent
    (void)c;
    uint64_t access   = a[0];
    uint64_t inherit  = a[1];
    uint64_t name_ptr = a[2];
    (void)access; (void)inherit;
    if (name_ptr) {
        std::string name = be(e)->read_mem_string(name_ptr, 2);
        a[2] = name;
        auto obj = we(e)->get_object_from_name(name);
        if (obj) {
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return static_cast<uint64_t>(obj->get_handle());
        }
    }
    // Create new event if named object not found
    auto result = we(e)->create_event("");
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::OpenWaitableTimer(void* e, ArgList& a, void* c) {
    // Python kernel32.py:4261-4280  OpenWaitableTimer
    (void)c;
    uint64_t name_ptr = a[2];
    if (name_ptr) {
        std::string name = be(e)->read_mem_string(name_ptr, 2);
        a[2] = name;
        auto obj = we(e)->get_object_from_name(name);
        if (obj) {
            w32(e)->set_last_error(K32_ERR_SUCCESS);
            return static_cast<uint64_t>(obj->get_handle());
        }
    }
    auto result = we(e)->create_event("");
    w32(e)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(std::get<0>(result));
}
uint64_t Kernel32::PeekNamedPipe(void* e, ArgList& a, void* c) {
    (void)a; return 0; // no data available
}
uint64_t Kernel32::ProcessIdToSessionId(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[1];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{0, 0, 0, 0}); // session 0
    return 1;
}
uint64_t Kernel32::RemoveVectoredExceptionHandler(void* e, ArgList& a, void* c) {
    (void)a; return 1; // success
}
uint64_t Kernel32::RtlCaptureContext(void* e, ArgList& a, void* c) {
    uint64_t ctx_ptr = a[0]; if (!ctx_ptr) return 0;
    int ps = ptr_sz(e);
    size_t sz = static_cast<size_t>(ps == 4 ? 716 : 1232);
    auto buf = std::vector<uint8_t>(sz, 0);
    uint64_t eip = be(e)->reg_read(ps == 4 ? speakeasy::arch::REG_EIP : speakeasy::arch::REG_RIP);
    size_t pc_off = ps == 4 ? 0xB8 : 0xF8;
    for (size_t i = 0; i < sizeof(eip) && pc_off + i < buf.size(); i++)
        buf[pc_off + i] = static_cast<uint8_t>((eip >> (i * 8)) & 0xFF);
    mm(e)->mem_write(ctx_ptr, buf); return 0;
}
uint64_t Kernel32::RtlUnwind(void* e, ArgList& a, void* c) {
    (void)a; we(e)->on_run_complete(); return 0;
}
uint64_t Kernel32::RtlLookupFunctionEntry(void* e, ArgList& a, void* c) {
    (void)a; return 0; // NULL  no function table
}
uint64_t Kernel32::SetConsoleCtrlHandler(void* e, ArgList& a, void* c) {
    (void)a; return 1; // success
}
uint64_t Kernel32::SetConsoleHistoryInfo(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetConsoleTitle(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetDefaultDllDirectories(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetDllDirectory(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetFilePointerEx(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py:3946-3964  SetFilePointerEx
    uint64_t hFile     = a[0];
    int64_t  dist      = static_cast<int64_t>(a[1]);
    uint64_t out_ptr   = a[3];
    uint64_t move_method = a[2];

    auto* f = static_cast<::File*>(we(e)->file_get(static_cast<int>(hFile)));
    if (f) {
        f->seek(static_cast<uint64_t>(dist), static_cast<int>(move_method));
        uint64_t pos = f->tell();
        if (out_ptr) {
            std::vector<uint8_t> buf(8);
            write_le(buf, 0, pos, 8);
            mm(e)->mem_write(out_ptr, buf);
        }
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE);
    return 0;
}
uint64_t Kernel32::SetHandleCount(void* e, ArgList& a, void* c) {
    (void)a; return static_cast<uint64_t>(a[0]); // return requested count
}
uint64_t Kernel32::SetHandleInformation(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetPriorityClass(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetProcessPriorityBoost(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetThreadContext(void* e, ArgList& a, void* c) {
    uint64_t hThread = a[0]; 
    uint64_t ctx_ptr = a[1];
    if (!ctx_ptr) { 
        w32(e)->set_last_error(998); // ERROR_NOACCESS
        return 0; 
    } 
    auto thread = we(e)->find_thread(static_cast<int>(hThread));
    if (!thread) { 
        w32(e)->set_last_error(6); // ERROR_INVALID_HANDLE
        return 0; 
    } 
    if (ctx_ptr) {
        if (we(e)->get_arch() == speakeasy::arch::ARCH_X86) {
            std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx = std::make_shared<speakeasy::deffs::windows::CONTEXT>();
            we(e)->mem_cast(ctx.get(), ctx_ptr);
            thread->set_context(ctx);
        }
        else if (we(e)->get_arch() == speakeasy::arch::ARCH_AMD64) {
            std::shared_ptr<speakeasy::deffs::windows::CONTEXT64> ctx = std::make_shared<speakeasy::deffs::windows::CONTEXT64>();
            we(e)->mem_cast(ctx.get(), ctx_ptr);
            thread->set_context(ctx);
        }
    }

    return 1;
}
uint64_t Kernel32::SetThreadDescription(void* e, ArgList& a, void* c) {
    (void)a; return 0; // success HRESULT
}
uint64_t Kernel32::SetThreadErrorMode(void* e, ArgList& a, void* c) {
    uint64_t out_ptr = a[1]; (void)a[0];
    if (out_ptr) mm(e)->mem_write(out_ptr, std::vector<uint8_t>{0, 0, 0, 0});
    return 1;
}
uint64_t Kernel32::SetThreadLocale(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SetThreadStackGuarantee(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::SizeofResource(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: SizeofResource  read Size at IMAGE_RESOURCE_DATA_ENTRY+4
    uint64_t hModule = a[0]; uint64_t hResInfo = a[1]; (void)hModule;
    if (hResInfo) {
        speakeasy::deffs::windows::IMAGE_RESOURCE_DATA_ENTRY entry;
        we(e)->mem_cast(&entry, hResInfo);
        return entry.Size;
    }
    return 0;
}
uint64_t Kernel32::SystemTimeToTzSpecificLocalTime(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c;
    return 1;
}
uint64_t Kernel32::VerSetConditionMask(void* e, ArgList& a, void* c) {
    return a[0] | a[1]; // OR the condition mask
}
uint64_t Kernel32::VerifyVersionInfo(void* e, ArgList& a, void* c) {
    (void)a; w32(e)->set_last_error(K32_ERR_SUCCESS); return 1;
}
uint64_t Kernel32::VirtualAllocExNuma(void* e, ArgList& a, void* c) {
    // Python kernel32.py: strips last arg (nndPreferred) and delegates to VirtualAllocEx
    ArgList trimmed = {a[0], a[1], a[2], a[3], a[4]};
    return VirtualAllocEx(e, trimmed, c);
}
uint64_t Kernel32::WTSGetActiveConsoleSessionId(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0; // session 0
}
uint64_t Kernel32::WerGetFlags(void* e, ArgList& a, void* c) {
    (void)e; (void)a; (void)c; return 0; // WER_FAULT_REPORTING_FLAG_NOHEAP
}
uint64_t Kernel32::WerSetFlags(void* e, ArgList& a, void* c) {
    (void)a; return 0; // success HRESULT
}
uint64_t Kernel32::Wow64DisableWow64FsRedirection(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::Wow64RevertWow64FsRedirection(void* e, ArgList& a, void* c) {
    (void)a; return 1;
}
uint64_t Kernel32::_lclose(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: _lclose  close file handle
    int hFile = static_cast<int>(a[0]);
    auto* f = static_cast<::File*>(we(e)->file_get(hFile));
    if (f) {
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return 0; // success
    }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE);
    return static_cast<uint64_t>(-1); // HFILE_ERROR
}
uint64_t Kernel32::_llseek(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: _llseek  seek in file
    int hFile = static_cast<int>(a[0]);
    int64_t offset = static_cast<int64_t>(static_cast<int32_t>(a[1])); // LONG
    int whence = static_cast<int>(a[2]);
    auto* f = static_cast<::File*>(we(e)->file_get(hFile));
    if (f) {
        f->seek(static_cast<uint64_t>(offset), whence);
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return f->tell();
    }
    w32(e)->set_last_error(K32_ERR_INVALID_HANDLE);
    return 0xFFFFFFFF; // HFILE_ERROR
}
uint64_t Kernel32::_lopen(void* e, ArgList& a, void* c) {
    (void)c;
    // Python kernel32.py: _lopen  open file
    uint64_t path_ptr = a[0];
    int mode = static_cast<int>(a[1]);
    if (!path_ptr) {
        w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND);
        return 0xFFFFFFFF;
    }
    std::string path = be(e)->read_mem_string(path_ptr, 1);
    a[0] = path;
    bool create = (mode & 0x0100) != 0; // OF_CREATE
    void* f = we(e)->file_open(path, create);
    if (f) {
        w32(e)->set_last_error(K32_ERR_SUCCESS);
        return reinterpret_cast<uint64_t>(f);
    }
    w32(e)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return 0xFFFFFFFF; // HFILE_ERROR
}

//
//  TLS APIs
// 

uint64_t Kernel32::TlsAlloc(void* emu, ArgList& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0xFFFFFFFF; // TLS_OUT_OF_INDEXES
    }
    auto tls = thread->get_tls();
    tls.push_back(nullptr);
    thread->set_tls(tls);
    uint32_t idx = static_cast<uint32_t>(tls.size() - 1);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return idx;
}

uint64_t Kernel32::TlsFree(void* emu, ArgList& argv, void* ctx) {
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::TlsGetValue(void* emu, ArgList& argv, void* ctx) {
    uint32_t dwTlsIndex = static_cast<uint32_t>(argv[0]);
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    auto tls = thread->get_tls();
    if (dwTlsIndex < tls.size()) {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return reinterpret_cast<uint64_t>(tls[dwTlsIndex]);
    } else {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
}

uint64_t Kernel32::TlsSetValue(void* emu, ArgList& argv, void* ctx) {
    uint32_t dwTlsIndex = static_cast<uint32_t>(argv[0]);
    uint64_t lpTlsValue = argv[1];
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    auto tls = thread->get_tls();
    if (dwTlsIndex < tls.size()) {
        tls[dwTlsIndex] = reinterpret_cast<void*>(lpTlsValue);
        thread->set_tls(tls);
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    } else {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
}

// 
//  FLS APIs
// 

uint64_t Kernel32::FlsAlloc(void* emu, ArgList& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0xFFFFFFFF; // FLS_OUT_OF_INDEXES
    }
    auto fls = thread->get_fls();
    fls.push_back(nullptr);
    thread->set_fls(fls);
    uint32_t idx = static_cast<uint32_t>(fls.size() - 1);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return idx;
}

uint64_t Kernel32::FlsFree(void* emu, ArgList& argv, void* ctx) {
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::FlsGetValue(void* emu, ArgList& argv, void* ctx) {
    uint32_t dwFlsIndex = static_cast<uint32_t>(argv[0]);
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    auto fls = thread->get_fls();
    if (dwFlsIndex < fls.size()) {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return reinterpret_cast<uint64_t>(fls[dwFlsIndex]);
    } else {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
}

uint64_t Kernel32::FlsSetValue(void* emu, ArgList& argv, void* ctx) {
    uint32_t dwFlsIndex = static_cast<uint32_t>(argv[0]);
    uint64_t lpFlsData = argv[1];
    auto thread = we(emu)->get_current_thread();
    if (!thread) {
        w32(emu)->set_last_error(K32_ERR_INVALID_HANDLE);
        return 0;
    }
    auto fls = thread->get_fls();
    if (fls.empty()) {
        fls.push_back(nullptr);
    }
    if (dwFlsIndex < fls.size()) {
        fls[dwFlsIndex] = reinterpret_cast<void*>(lpFlsData);
        thread->set_fls(fls);
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return 1;
    } else {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
}

// 
//  STANDARD HANDLE & FILE TYPES
// 

uint64_t Kernel32::GetStdHandle(void* emu, ArgList& argv, void* ctx) {
    uint32_t nStdHandle = static_cast<uint32_t>(argv[0]);
    auto proc = we(emu)->get_current_process();
    if (proc) {
        return static_cast<uint64_t>(proc->get_std_handle(static_cast<int>(nStdHandle)));
    }
    return 0;
}

uint64_t Kernel32::GetFileType(void* emu, ArgList& argv, void* ctx) {
    (void)emu; (void)argv;
    return 1; // FILE_TYPE_DISK
}

// 
//  SYSTEM TIME
// 

uint64_t Kernel32::GetSystemTimeAsFileTime(void* emu, ArgList& argv, void* ctx) {
    uint64_t lpSystemTimeAsFileTime = argv[0];
    if (lpSystemTimeAsFileTime) {
        auto now = std::chrono::system_clock::now();
        auto duration = now.time_since_epoch();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
        uint64_t ft = 116444736000000000ULL + ns / 100;
        std::vector<uint8_t> ft_bytes(8);
        write_le(ft_bytes, 0, ft, 8);
        mm(emu)->mem_write(lpSystemTimeAsFileTime, ft_bytes);
    }
    return 0;
}

// 
//  INTERLOCKED ATOMIC OPERATIONS
// 

uint64_t Kernel32::InterlockedIncrement(void* emu, ArgList& argv, void* ctx) {
    uint64_t addend_ptr = argv[0];
    if (!addend_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto val_bytes = mm(emu)->mem_read(addend_ptr, 4);
    int32_t val = 0;
    if (val_bytes.size() >= 4) {
        val = static_cast<int32_t>(read_le(val_bytes, 0, 4));
    }
    val += 1;
    std::vector<uint8_t> out_bytes(4);
    write_le(out_bytes, 0, static_cast<uint32_t>(val), 4);
    mm(emu)->mem_write(addend_ptr, out_bytes);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(static_cast<uint32_t>(val));
}

uint64_t Kernel32::InterlockedDecrement(void* emu, ArgList& argv, void* ctx) {
    uint64_t addend_ptr = argv[0];
    if (!addend_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto val_bytes = mm(emu)->mem_read(addend_ptr, 4);
    int32_t val = 0;
    if (val_bytes.size() >= 4) {
        val = static_cast<int32_t>(read_le(val_bytes, 0, 4));
    }
    val -= 1;
    std::vector<uint8_t> out_bytes(4);
    write_le(out_bytes, 0, static_cast<uint32_t>(val), 4);
    mm(emu)->mem_write(addend_ptr, out_bytes);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(static_cast<uint32_t>(val));
}

uint64_t Kernel32::InterlockedExchange(void* emu, ArgList& argv, void* ctx) {
    uint64_t target_ptr = argv[0];
    uint32_t value = static_cast<uint32_t>(argv[1]);
    if (!target_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto val_bytes = mm(emu)->mem_read(target_ptr, 4);
    int32_t old_val = 0;
    if (val_bytes.size() >= 4) {
        old_val = static_cast<int32_t>(read_le(val_bytes, 0, 4));
    }
    std::vector<uint8_t> out_bytes(4);
    write_le(out_bytes, 0, value, 4);
    mm(emu)->mem_write(target_ptr, out_bytes);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(static_cast<uint32_t>(old_val));
}

uint64_t Kernel32::InterlockedExchangeAdd(void* emu, ArgList& argv, void* ctx) {
    uint64_t target_ptr = argv[0];
    uint32_t value = static_cast<uint32_t>(argv[1]);

    return 0;
}

uint64_t Kernel32::InterlockedCompareExchange(void* emu, ArgList& argv, void* ctx) {
    uint64_t dest_ptr = argv[0];
    uint32_t exchange = static_cast<uint32_t>(argv[1]);
    uint32_t comperand = static_cast<uint32_t>(argv[2]);
    if (!dest_ptr) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    auto val_bytes = mm(emu)->mem_read(dest_ptr, 4);
    int32_t old_val = 0;
    if (val_bytes.size() >= 4) {
        old_val = static_cast<int32_t>(read_le(val_bytes, 0, 4));
    }
    if (static_cast<uint32_t>(old_val) == comperand) {
        std::vector<uint8_t> out_bytes(4);
        write_le(out_bytes, 0, exchange, 4);
        mm(emu)->mem_write(dest_ptr, out_bytes);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(static_cast<uint32_t>(old_val));
}

// 
//  STRING UTILITIES
// 

uint64_t Kernel32::lstrcmpi(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: lstrcmpi  get_char_width, update argv
    int cw = get_char_width(static_cast<ApiContext*>(c));
    uint64_t s1_ptr = a[0], s2_ptr = a[1];
    if (!s1_ptr || !s2_ptr) return 1;
    std::string s1 = be(emu)->read_mem_string(s1_ptr, cw);
    std::string s2 = be(emu)->read_mem_string(s2_ptr, cw);
    a[0] = s1; a[1] = s2;
    std::string s1l = s1, s2l = s2;
    std::transform(s1l.begin(), s1l.end(), s1l.begin(), ::tolower);
    std::transform(s2l.begin(), s2l.end(), s2l.begin(), ::tolower);
    if (s1l == s2l) return 0;
    return (s1l < s2l) ? -1 : 1;
}

uint64_t Kernel32::lstrcpyn(void* emu, ArgList& a, void* c) {
    // Python kernel32.py: lstrcpyn  get_char_width, update argv
    int cw = get_char_width(static_cast<ApiContext*>(c));
    uint64_t dst = a[0], src_ptr = a[1];
    int max_len = static_cast<int>(a[2]);
    if (!dst || !src_ptr || max_len <= 0) return dst;
    std::string s = be(emu)->read_mem_string(src_ptr, cw);
    a[1] = s;
    if (static_cast<int>(s.size()) >= max_len) s = s.substr(0, max_len - 1);
    s.push_back('\0');
    be(emu)->write_mem_string(s, dst, cw);
    return dst;
}

}} // namespaces
