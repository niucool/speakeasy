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

using namespace speakeasy;

namespace speakeasy { namespace api {

//  Typed cast helpers 
static inline WindowsEmulator* we(void* e) {
    return static_cast<WindowsEmulator*>(e);
}
static inline BinaryEmulator* be(void* e) {
    return static_cast<BinaryEmulator*>(e);
}
static inline Win32Emulator* w32(void* e) {
    return static_cast<Win32Emulator*>(e);
}
static inline MemoryManager* mm(void* e) {
    return static_cast<MemoryManager*>(e);
}
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
#ifdef InterlockedExchange
#undef InterlockedExchange
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
static uint64_t g_next_handle = 0x1800;
static uint64_t g_next_snap_handle = 0x2000;

//  Constructor 
Kernel32::Kernel32(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Kernel32)
    REG(Kernel32, CreateFileA, 7)    REG(Kernel32, CreateFileW, 7)
    REG(Kernel32, ReadFile, 5)       REG(Kernel32, WriteFile, 5)
    REG(Kernel32, CloseHandle, 1)    REG(Kernel32, DeleteFileA, 1)     REG(Kernel32, DeleteFileW, 1)
    REG(Kernel32, CopyFileA, 3)      REG(Kernel32, CopyFileW, 3)
    REG(Kernel32, CreateDirectoryA, 2) REG(Kernel32, CreateDirectoryW, 2) REG(Kernel32, RemoveDirectoryA, 1)
    REG(Kernel32, GetFileAttributesA, 1) REG(Kernel32, GetFileAttributesW, 1) REG(Kernel32, SetFilePointer, 4)
    REG(Kernel32, GetFileSize, 2)    REG(Kernel32, FindFirstFileA, 2) REG(Kernel32, FindFirstFileW, 2)
    REG(Kernel32, FindNextFileA, 2)  REG(Kernel32, FindNextFileW, 2) REG(Kernel32, FindClose, 1)
    REG(Kernel32, CreateFileMappingA, 6) REG(Kernel32, CreateFileMappingW, 6) REG(Kernel32, MapViewOfFile, 5)
    REG(Kernel32, UnmapViewOfFile, 1) REG(Kernel32, FlushFileBuffers, 1)
    REG(Kernel32, SetEndOfFile, 1)   REG(Kernel32, GetFileTime, 4)
    REG(Kernel32, SetFileTime, 4)    REG(Kernel32, GetFileInformationByHandle, 2)
    REG(Kernel32, DeviceIoControl, 8) REG(Kernel32, GetDriveTypeA, 1) REG(Kernel32, GetDriveTypeW, 1)
    REG(Kernel32, GetDiskFreeSpaceExA, 4) REG(Kernel32, GetDiskFreeSpaceExW, 4)
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
    REG(Kernel32, LoadLibraryA, 1)   REG(Kernel32, LoadLibraryW, 1)
    REG(Kernel32, LoadLibraryExA, 3) REG(Kernel32, FreeLibrary, 1)
    REG(Kernel32, GetProcAddress, 2) REG(Kernel32, GetModuleHandleA, 1)
    REG(Kernel32, GetModuleHandleW, 1) REG(Kernel32, GetModuleFileNameA, 3) REG(Kernel32, GetModuleFileNameW, 3)
    REG(Kernel32, DisableThreadLibraryCalls, 1)
    REG(Kernel32, CreateProcessA, 10) REG(Kernel32, CreateProcessW, 10) REG(Kernel32, OpenProcess, 3)
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
    REG(Kernel32, CreateEventA, 4)   REG(Kernel32, CreateEventW, 4) REG(Kernel32, CreateMutexA, 3) REG(Kernel32, CreateMutexW, 3)
    REG(Kernel32, OpenMutexA, 3)     REG(Kernel32, OpenMutexW, 3) REG(Kernel32, ReleaseMutex, 1)
    REG(Kernel32, SetEvent, 1)       REG(Kernel32, ResetEvent, 1)
    REG(Kernel32, WaitForSingleObject, 2) REG(Kernel32, WaitForMultipleObjects, 4)
    REG(Kernel32, InitializeCriticalSection, 1) REG(Kernel32, DeleteCriticalSection, 1)
    REG(Kernel32, EnterCriticalSection, 1) REG(Kernel32, LeaveCriticalSection, 1)
    REG(Kernel32, CreateWaitableTimerA, 3) REG(Kernel32, CreateWaitableTimerW, 3) REG(Kernel32, SetWaitableTimer, 6)
    REG(Kernel32, CancelWaitableTimer, 1)
    REG(Kernel32, GetTickCount, 0)   REG(Kernel32, GetSystemInfo, 1)
    REG(Kernel32, GetVersion, 0)     REG(Kernel32, GetVersionExA, 1) REG(Kernel32, GetVersionExW, 1)
    REG(Kernel32, IsDebuggerPresent, 0) REG(Kernel32, SetErrorMode, 1)
    REG(Kernel32, GetSystemTime, 1)  REG(Kernel32, GetLocalTime, 1)
    REG(Kernel32, SystemTimeToFileTime, 2) REG(Kernel32, FileTimeToSystemTime, 2)
    REG(Kernel32, QueryPerformanceCounter, 1) REG(Kernel32, QueryPerformanceFrequency, 1)
    REG(Kernel32, GetComputerNameA, 2) REG(Kernel32, GetComputerNameW, 2) REG(Kernel32, GetUserNameA, 2) REG(Kernel32, GetUserNameW, 2)
    REG(Kernel32, SetUnhandledExceptionFilter, 1)
    REG(Kernel32, GetLastError, 0)   REG(Kernel32, SetLastError, 1)
    REG(Kernel32, RaiseException, 4) REG(Kernel32, UnhandledExceptionFilter, 1)
    REG(Kernel32, lstrlenA, 1)       REG(Kernel32, lstrlenW, 1) REG(Kernel32, lstrcpyA, 2) REG(Kernel32, lstrcpyW, 2)
    REG(Kernel32, lstrcatA, 2)       REG(Kernel32, lstrcatW, 2) REG(Kernel32, lstrcmpA, 2) REG(Kernel32, lstrcmpW, 2)
    REG(Kernel32, MultiByteToWideChar, 6) REG(Kernel32, WideCharToMultiByte, 8)
    REG(Kernel32, GetCommandLineA, 0) REG(Kernel32, GetCommandLineW, 0)
    REG(Kernel32, GetEnvironmentVariableA, 3) REG(Kernel32, GetEnvironmentVariableW, 3) REG(Kernel32, SetEnvironmentVariableA, 2)
    REG(Kernel32, GetCurrentDirectoryA, 2) REG(Kernel32, GetCurrentDirectoryW, 2) REG(Kernel32, SetCurrentDirectoryA, 1)
    REG(Kernel32, ExpandEnvironmentStringsA, 3) REG(Kernel32, ExpandEnvironmentStringsW, 3)
    REG(Kernel32, CreateToolhelp32Snapshot, 2)
    REG(Kernel32, Process32FirstA, 2) REG(Kernel32, Process32FirstW, 2) REG(Kernel32, Process32NextA, 2) REG(Kernel32, Process32NextW, 2)
    REG(Kernel32, Thread32First, 2)  REG(Kernel32, Thread32Next, 2)
    REG(Kernel32, Module32FirstA, 2) REG(Kernel32, Module32FirstW, 2) REG(Kernel32, Module32NextA, 2) REG(Kernel32, Module32NextW, 2)
    REG(Kernel32, AllocConsole, 0)   REG(Kernel32, FreeConsole, 0)
    REG(Kernel32, GetConsoleMode, 2) REG(Kernel32, SetConsoleMode, 2)
    REG(Kernel32, OutputDebugStringA, 1) REG(Kernel32, OutputDebugStringW, 1) REG(Kernel32, GetACP, 0)
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
    REG(Kernel32, GetMailslotInfo, 5)     REG(Kernel32, GetModuleFileNameExA, 4)
    REG(Kernel32, GetModuleHandleEx, 3)     REG(Kernel32, GetNativeSystemInfo, 1)
    REG(Kernel32, GetOEMCP, 0)     REG(Kernel32, GetPhysicallyInstalledSystemMemory, 1)
    REG(Kernel32, GetProcessAffinityMask, 3)     REG(Kernel32, GetProcessHandleCount, 1)
    REG(Kernel32, GetProcessVersion, 1)     REG(Kernel32, GetProfileInt, 3)
    REG(Kernel32, GetShortPathName, 3)     REG(Kernel32, GetStartupInfo, 1)
    REG(Kernel32, GetStringTypeA, 5)     REG(Kernel32, GetStringTypeW, 4)
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
    REG(Kernel32, GetWindowsDirectory, 2)     REG(Kernel32, GlobalAddAtomA, 1)
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
    REG(Kernel32, lstrcmpiA, 2)     REG(Kernel32, lstrcmpiW, 2)
    REG(Kernel32, lstrcpyn, 3)
    REG(Kernel32, lstrcpynA, 3)     REG(Kernel32, lstrcpynW, 3)
    END_API_TABLE
}

// 
//  FILE I/O APIs
// 

//  Common implementation for CreateFileA / CreateFileW.
//  The only difference between A and W is how the filename string is decoded.
static uint64_t CreateFile_impl(void* emu, const std::string& target,
                                 uint32_t access, uint32_t share, uint64_t sec_attr,
                                 uint32_t disp, uint32_t flags, uint64_t template_file) {
    (void)access; (void)share; (void)sec_attr; (void)flags; (void)template_file;

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

uint64_t Kernel32::CreateFileA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    if (!argv[0]) return K32_INVALID_HANDLE;
    return CreateFile_impl(emu,
        be(emu)->read_mem_string(argv[0], 1),               // filename (ANSI)
        static_cast<uint32_t>(argv[1]), static_cast<uint32_t>(argv[2]),
        argv[3], static_cast<uint32_t>(argv[4]),
        static_cast<uint32_t>(argv[5]), argv[6]);
}

uint64_t Kernel32::CreateFileW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    if (!argv[0]) return K32_INVALID_HANDLE;
    return CreateFile_impl(emu,
        be(emu)->read_mem_string(argv[0], 2),               // filename (UTF-16LE)
        static_cast<uint32_t>(argv[1]), static_cast<uint32_t>(argv[2]),
        argv[3], static_cast<uint32_t>(argv[4]),
        static_cast<uint32_t>(argv[5]), argv[6]);
}

uint64_t Kernel32::ReadFile(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

    auto* file_obj = static_cast<File*>(f);
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

uint64_t Kernel32::WriteFile(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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
        auto* file_obj = static_cast<File*>(f);
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

uint64_t Kernel32::CloseHandle(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hObject = argv[0];
    (void)hObject;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::DeleteFileA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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
uint64_t Kernel32::CopyFileA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    if (!argv[0] || !argv[1]) return 0;
    return CopyFile_impl(emu, be(emu)->read_mem_string(argv[0], 1),
                         be(emu)->read_mem_string(argv[1], 1),
                         static_cast<uint32_t>(argv[2]));
}
uint64_t Kernel32::CopyFileW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    if (!argv[0] || !argv[1]) return 0;
    return CopyFile_impl(emu, be(emu)->read_mem_string(argv[0], 2),
                         be(emu)->read_mem_string(argv[1], 2),
                         static_cast<uint32_t>(argv[2]));
}

uint64_t Kernel32::CreateDirectoryA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    uint64_t sec_attr = argv[1];
    (void)sec_attr;
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    (void)path;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::RemoveDirectoryA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    (void)path;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileAttributesA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t fname_ptr = argv[0];
    if (!fname_ptr) return K32_INVALID_FILE_ATTR;
    std::string target = be(emu)->read_mem_string(fname_ptr, 1);
    if (we(emu)->does_file_exist(target)) {
        return K32_FILE_ATTR_NORMAL;
    }
    w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return K32_INVALID_FILE_ATTR;
}

uint64_t Kernel32::SetFilePointer(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    int32_t dist = static_cast<int32_t>(argv[1] & 0xFFFFFFFF);
    uint64_t dist_high_ptr = argv[2];
    uint32_t move_method = static_cast<uint32_t>(argv[3]);
    (void)hFile; (void)dist; (void)dist_high_ptr; (void)move_method;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::GetFileSize(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t size_high_ptr = argv[1];
    (void)hFile; (void)size_high_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::FindFirstFileA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t fname_ptr = argv[0];
    uint64_t find_data_ptr = argv[1];
    (void)fname_ptr; (void)find_data_ptr;
    w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
    return K32_INVALID_HANDLE;
}

uint64_t Kernel32::FindNextFileA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t find_handle = argv[0];
    uint64_t find_data_ptr = argv[1];
    (void)find_handle; (void)find_data_ptr;
    w32(emu)->set_last_error(K32_ERR_NO_MORE_FILES);
    return 0;
}

uint64_t Kernel32::FindClose(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t find_handle = argv[0];
    (void)find_handle;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::CreateFileMappingA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t map_attrs = argv[1];
    uint32_t prot = static_cast<uint32_t>(argv[2]);
    uint32_t max_sz_high = static_cast<uint32_t>(argv[3]);
    uint32_t max_sz_low = static_cast<uint32_t>(argv[4]);
    uint64_t map_name_ptr = argv[5];
    (void)hFile; (void)map_attrs; (void)max_sz_high; (void)max_sz_low; (void)map_name_ptr;
    auto fmgr = we(emu)->get_file_manager();
    uint32_t handle = fmgr->file_create_mapping(
        static_cast<uint32_t>(hFile & 0xFFFFFFFF), 
        "", 
        (max_sz_high << 32) | max_sz_low, static_cast<int>(prot));
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(handle);
}

uint64_t Kernel32::MapViewOfFile(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hmap = argv[0];
    uint32_t access = static_cast<uint32_t>(argv[1]);
    uint32_t offset_high = static_cast<uint32_t>(argv[2]);
    uint32_t offset_low = static_cast<uint32_t>(argv[3]);
    uint64_t bytes_to_map = argv[4];
    (void)hmap; (void)access; (void)offset_high; (void)offset_low; (void)bytes_to_map;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::UnmapViewOfFile(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t base = argv[0];
    (void)base;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::FlushFileBuffers(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    (void)hFile;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::SetEndOfFile(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    (void)hFile;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetFileTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t creation_ptr = argv[1];
    uint64_t last_access_ptr = argv[2];
    uint64_t last_write_ptr = argv[3];
    (void)hFile; (void)creation_ptr; (void)last_access_ptr; (void)last_write_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetFileInformationByHandle(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    int hFile = static_cast<int>(argv[0]);
    uint64_t info_ptr = argv[1];
    (void)hFile; (void)info_ptr;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::DeviceIoControl(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetDriveTypeA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t root_ptr = argv[0];
    (void)root_ptr;
    return 3; // DRIVE_FIXED
}

uint64_t Kernel32::GetDiskFreeSpaceExA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::VirtualAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t addr = argv[0];
    size_t size = static_cast<size_t>(argv[1]);
    uint32_t alloc_type = static_cast<uint32_t>(argv[2]);
    uint32_t prot = static_cast<uint32_t>(argv[3]);
    (void)alloc_type;
    if (size == 0) return 0;
    int emu_perms = win_to_emu_perms(prot);
    size = (size + 0xFFF) & ~0xFFF;
    uint64_t base = (addr == 0) ? 0x10000 : addr;
    uint64_t buf = mm(emu)->mem_map(size, base, static_cast<uint32_t>(emu_perms), "api.VirtualAlloc");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::VirtualAllocEx(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint64_t addr = argv[1];
    size_t size = static_cast<size_t>(argv[2]);
    uint32_t alloc_type = static_cast<uint32_t>(argv[3]);
    uint32_t prot = static_cast<uint32_t>(argv[4]);
    (void)hProcess; (void)alloc_type;
    if (size == 0) return 0;
    int emu_perms = win_to_emu_perms(prot);
    size = (size + 0xFFF) & ~0xFFF;
    uint64_t base = (addr == 0) ? 0x10000 : addr;
    uint64_t buf = mm(emu)->mem_map(size, base, static_cast<uint32_t>(emu_perms), "api.VirtualAllocEx");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::VirtualFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::VirtualProtect(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::VirtualProtectEx(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    (void)hProcess;
    std::vector<uint64_t> remaining = {argv[1], argv[2], argv[3], argv[4]};
    return VirtualProtect(emu, remaining, ctx);
}

uint64_t Kernel32::VirtualQuery(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::WriteProcessMemory(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::ReadProcessMemory(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::HeapAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hHeap = argv[0];
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    size_t sz = static_cast<size_t>(argv[2]);
    (void)hHeap; (void)flags;
    if (sz == 0) sz = 1;
    uint64_t buf = mm(emu)->mem_map(sz, 0, 4, "heap");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return buf;
}

uint64_t Kernel32::HeapFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::HeapCreate(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t options = static_cast<uint32_t>(argv[0]);
    size_t initial_sz = static_cast<size_t>(argv[1]);
    size_t max_sz = static_cast<size_t>(argv[2]);
    (void)options; (void)initial_sz; (void)max_sz;
    uint64_t heap = mm(emu)->mem_map(0x10000, 0, 4, "heap");
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return heap;
}

uint64_t Kernel32::HeapDestroy(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hHeap = argv[0];
    if (hHeap) {
        try { mm(emu)->mem_free(hHeap); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetProcessHeap(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    static thread_local uint64_t process_heap = 0;
    if (process_heap == 0) {
        process_heap = mm(emu)->mem_map(0x10000, 0, 4, "process_heap");
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return process_heap;
}

uint64_t Kernel32::GlobalAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    size_t sz = static_cast<size_t>(argv[1]);
    (void)flags;
    if (sz == 0) sz = 1;
    uint64_t buf = mm(emu)->mem_map(sz, 0, 4, "GlobalAlloc");
    return buf;
}

uint64_t Kernel32::GlobalFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hMem = argv[0];
    (void)hMem;
    return 0;
}

uint64_t Kernel32::LocalAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    size_t sz = static_cast<size_t>(argv[1]);
    (void)flags;
    if (sz == 0) sz = 1;
    uint64_t buf = mm(emu)->mem_map(sz, 0, 4, "LocalAlloc");
    return buf;
}

uint64_t Kernel32::LocalFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hMem = argv[0];
    if (hMem) {
        try { mm(emu)->mem_free(hMem); } catch (...) {}
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 0;
}

uint64_t Kernel32::RtlMoveMemory(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    size_t sz = static_cast<size_t>(argv[2]);
    if (dst && src && sz > 0) {
        auto data = mm(emu)->mem_read(src, sz);
        mm(emu)->mem_write(dst, data);
    }
    return dst;
}

uint64_t Kernel32::RtlZeroMemory(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

static uint64_t do_load_library(void* emu, uint64_t name_ptr, int cw) {
    if (!name_ptr) return 0;
    std::string lib = be(emu)->read_mem_string(name_ptr, cw);
    if (lib.empty()) return 0;
    lib = speakeasy::to_lower(lib);
    auto dot = lib.rfind(".dll");
    if (dot != std::string::npos) lib = lib.substr(0, dot);
    void* mod = we(emu)->load_library(lib);
    if (!mod) {
        w32(emu)->set_last_error(K32_ERR_MOD_NOT_FOUND);
        return 0;
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return reinterpret_cast<uint64_t>(mod);
}

uint64_t Kernel32::LoadLibraryA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return do_load_library(emu, argv[0], 1);
}

uint64_t Kernel32::LoadLibraryW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return do_load_library(emu, argv[0], 2);
}

uint64_t Kernel32::LoadLibraryExA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t lib_name = argv[0];
    return do_load_library(emu, lib_name, 1);
}

uint64_t Kernel32::FreeLibrary(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hMod = argv[0];
    (void)hMod;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetProcAddress(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hMod = argv[0];
    uint64_t proc_name_ptr = argv[1];
    std::string proc_name;
    if (proc_name_ptr) {
        try {
            proc_name = be(emu)->read_mem_string(proc_name_ptr, 1);
        } catch (...) {
            if (proc_name_ptr < 0xFFFF) {
                proc_name = "ordinal_" + std::to_string(proc_name_ptr);
            }
        }
    }
    if (proc_name.empty()) {
        w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
        return 0;
    }
    void* func_ptr = we(emu)->get_proc("kernel32", proc_name);
    if (func_ptr) {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
        return reinterpret_cast<uint64_t>(func_ptr);
    }
    w32(emu)->set_last_error(K32_ERR_MOD_NOT_FOUND);
    return 0;
}

uint64_t Kernel32::GetModuleHandleA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetModuleHandleW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t mod_name_ptr = argv[0];
    if (!mod_name_ptr) {
        auto p = we(emu)->get_current_process();
        if (p) {
            return static_cast<uint64_t>(p->base);
        }
        return 0;
    }
    std::string name = be(emu)->read_mem_string(mod_name_ptr, 2);
    if (name.empty()) return 0;
    name = speakeasy::to_lower(name);
    auto dot = name.rfind(".dll");
    if (dot != std::string::npos) name = name.substr(0, dot);
    auto mods = we(emu)->get_peb_modules();
    for (auto m : mods) {
        auto mod = m;
        std::string mname = speakeasy::to_lower(mod->get_base_name());
        auto mdot = mname.rfind(".dll");
        if (mdot != std::string::npos) mname = mname.substr(0, mdot);
        if (mname == name) {
            return mod->base;
        }
    }
    return 0;
}

uint64_t Kernel32::GetModuleFileNameA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetModuleFileNameW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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
    // buf_sz is in characters (each wide char = 2 bytes)
    if (buf_sz <= filename.size()) {
        w32(emu)->set_last_error(K32_ERR_INSUFFICIENT_BUF);
        filename = filename.substr(0, buf_sz - 1);
    }
    be(emu)->write_mem_string(filename, buf_ptr, 2);  // UTF-16LE
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(filename.size());
}

uint64_t Kernel32::DisableThreadLibraryCalls(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    (void)argv[0];
    return 1;
}

// 
//  PROCESS / THREAD APIs
// 

uint64_t Kernel32::CreateProcessA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t app_ptr = argv[0];
    uint64_t cmd_ptr = argv[1];
    uint64_t proc_attrs = argv[2];
    uint64_t thread_attrs = argv[3];
    uint32_t inherit = static_cast<uint32_t>(argv[4]);
    uint32_t flags = static_cast<uint32_t>(argv[5]);
    uint64_t env_ptr = argv[6];
    uint64_t cd_ptr = argv[7];
    uint64_t si_ptr = argv[8];
    uint64_t pi_ptr = argv[9];
    (void)proc_attrs; (void)thread_attrs; (void)inherit; (void)env_ptr; (void)cd_ptr; (void)si_ptr;
    std::string app_str;
    std::string cmd_str;
    if (app_ptr) app_str = be(emu)->read_mem_string(app_ptr, 1);
    if (cmd_ptr) cmd_str = be(emu)->read_mem_string(cmd_ptr, 1);
    std::shared_ptr<Process> proc = we(emu)->create_process(app_str, cmd_str, nullptr, true);
    if (!proc) {
        w32(emu)->set_last_error(K32_ERR_FILE_NOT_FOUND);
        return 0;
    }
    auto& threads = proc->threads;
    int proc_handle = we(emu)->get_object_handle(proc);
    int thread_handle = 0;
    if (!threads.empty()) {
        thread_handle = we(emu)->get_object_handle(threads[0]);
    }
    if (pi_ptr) {
        std::vector<uint8_t> pi_buf(static_cast<size_t>(ptr_sz(emu) == 8 ? 24 : 16), 0);
        write_le(pi_buf, 0, static_cast<uint64_t>(proc_handle), static_cast<size_t>(ptr_sz(emu)));
        write_le(pi_buf, static_cast<size_t>(ptr_sz(emu)), static_cast<uint64_t>(thread_handle), static_cast<size_t>(ptr_sz(emu)));
        write_le(pi_buf, static_cast<size_t>(ptr_sz(emu) * 2), static_cast<uint64_t>(proc->get_pid()), 4);
        int tid = (!threads.empty()) ? threads[0]->get_id() : 0;
        write_le(pi_buf, static_cast<size_t>(ptr_sz(emu) * 2 + 4), static_cast<uint64_t>(tid), 4);
        mm(emu)->mem_write(pi_ptr, pi_buf);
    }
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::OpenProcess(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::TerminateProcess(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hProcess = argv[0];
    uint32_t exit_code = static_cast<uint32_t>(argv[1]);
    (void)hProcess; (void)exit_code;
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::GetCurrentProcess(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return static_cast<uint64_t>(-1);
}

uint64_t Kernel32::GetCurrentProcessId(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    auto proc = we(emu)->get_current_process();
    if (proc) {
        return static_cast<uint64_t>(proc->get_pid());
    }
    return 0;
}

uint64_t Kernel32::ExitProcess(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t exit_code = static_cast<uint32_t>(argv[0]);
    (void)exit_code;
    we(emu)->stop();
    return 0;
}

uint64_t Kernel32::CreateThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::CreateRemoteThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::OpenThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t access = static_cast<uint32_t>(argv[0]);
    uint32_t inherit = static_cast<uint32_t>(argv[1]);
    uint32_t tid = static_cast<uint32_t>(argv[2]);
    (void)access; (void)inherit; (void)tid;
    w32(emu)->set_last_error(K32_ERR_INVALID_PARAM);
    return 0;
}

uint64_t Kernel32::TerminateThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hThread = argv[0];
    uint32_t exit_code = static_cast<uint32_t>(argv[1]);
    (void)hThread; (void)exit_code;
    return 1;
}

uint64_t Kernel32::GetCurrentThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (thread) {
        int h = we(emu)->get_object_handle(thread);
        if (h) return static_cast<uint64_t>(h);
    }
    return static_cast<uint64_t>(-2);
}

uint64_t Kernel32::GetCurrentThreadId(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    auto thread = we(emu)->get_current_thread();
    if (thread) {
        return static_cast<uint64_t>(thread->get_id());
    }
    return 0;
}

uint64_t Kernel32::ResumeThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hThread = argv[0];
    (void)hThread;
    return 0;
}

uint64_t Kernel32::SuspendThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hThread = argv[0];
    (void)hThread;
    return 0;
}

uint64_t Kernel32::ExitThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t exit_code = static_cast<uint32_t>(argv[0]);
    (void)exit_code;
    we(emu)->stop();
    return 0;
}

uint64_t Kernel32::Sleep(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    if (!argv.empty()) {
        auto ms = std::chrono::milliseconds(argv[0]);
        std::this_thread::sleep_for(ms);
    }
    return 0;
}

uint64_t Kernel32::SleepEx(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t ms = static_cast<uint32_t>(argv[0]);
    uint32_t alertable = static_cast<uint32_t>(argv[1]);
    (void)alertable;
    if (ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
    return 0;
}

uint64_t Kernel32::SwitchToThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    std::this_thread::yield();
    return 0;
}

uint64_t Kernel32::GetExitCodeProcess(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetExitCodeThread(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::QueueUserAPC(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t func = argv[0];
    uint64_t hThread = argv[1];
    uint64_t data = argv[2];
    (void)func; (void)hThread; (void)data;
    return 1;
}

uint64_t Kernel32::WinExec(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetThreadPriority(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hThread = argv[0];
    int32_t priority = static_cast<int32_t>(argv[1]);
    (void)hThread; (void)priority;
    return 1;
}

uint64_t Kernel32::GetThreadPriority(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hThread = argv[0];
    (void)hThread;
    return 0;
}

// 
//  SYNC APIs
// 

uint64_t Kernel32::CreateEventA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::CreateMutexA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t initial_owner = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)attrs; (void)initial_owner;
    std::string name;
    if (name_ptr) name = be(emu)->read_mem_string(name_ptr, 1);

    auto [h, mut] = we(emu)->create_mutant(name);
    if (h == 0) {
        w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
    } else {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    }
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::CreateMutexW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t initial_owner = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)attrs; (void)initial_owner;
    std::string name;
    if (name_ptr) name = be(emu)->read_mem_string(name_ptr, 2);

    auto [h, mut] = we(emu)->create_mutant(name);
    if (h == 0) {
        w32(emu)->set_last_error(K32_ERR_ALREADY_EXISTS);
    } else {
        w32(emu)->set_last_error(K32_ERR_SUCCESS);
    }
    return static_cast<uint64_t>(h);
}

uint64_t Kernel32::OpenMutexA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::ReleaseMutex(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hMutex = argv[0];
    (void)hMutex;
    return 1;
}

uint64_t Kernel32::SetEvent(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hEvent = argv[0];
    (void)hEvent;
    return 1;
}

uint64_t Kernel32::ResetEvent(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hEvent = argv[0];
    (void)hEvent;
    return 1;
}

uint64_t Kernel32::WaitForSingleObject(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hHandle = argv[0];
    uint32_t ms = static_cast<uint32_t>(argv[1]);
    (void)hHandle; (void)ms;
    return 0;
}

uint64_t Kernel32::WaitForMultipleObjects(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t count = static_cast<uint32_t>(argv[0]);
    uint64_t handles_ptr = argv[1];
    uint32_t wait_all = static_cast<uint32_t>(argv[2]);
    uint32_t ms = static_cast<uint32_t>(argv[3]);
    (void)count; (void)handles_ptr; (void)wait_all; (void)ms;
    return 0;
}

uint64_t Kernel32::InitializeCriticalSection(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t cs_ptr = argv[0];
    if (cs_ptr) {
        std::vector<uint8_t> cs_data(24, 0);
        mm(emu)->mem_write(cs_ptr, cs_data);
    }
    return 0;
}

uint64_t Kernel32::DeleteCriticalSection(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::EnterCriticalSection(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::LeaveCriticalSection(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    (void)argv[0];
    return 0;
}

uint64_t Kernel32::CreateWaitableTimerA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t attrs = argv[0];
    uint32_t manual_reset = static_cast<uint32_t>(argv[1]);
    uint64_t name_ptr = argv[2];
    (void)attrs; (void)manual_reset; (void)name_ptr;
    return 1;
}

uint64_t Kernel32::SetWaitableTimer(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hTimer = argv[0];
    uint64_t due_time_ptr = argv[1];
    uint32_t period = static_cast<uint32_t>(argv[2]);
    uint64_t completion_routine = argv[3];
    uint64_t arg = argv[4];
    uint32_t resume = static_cast<uint32_t>(argv[5]);
    (void)hTimer; (void)due_time_ptr; (void)period; (void)completion_routine; (void)arg; (void)resume;
    return 1;
}

uint64_t Kernel32::CancelWaitableTimer(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hTimer = argv[0];
    (void)hTimer;
    return 1;
}

// 
//  SYSTEM APIs
// 

uint64_t Kernel32::GetTickCount(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count() & 0xFFFFFFFF;
}

uint64_t Kernel32::GetSystemInfo(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t lpSystemInfo = argv[0];
    if (!lpSystemInfo) return 0;
    int ps = ptr_sz(emu);
    size_t sz = (ps == 8) ? 48 : 36;
    std::vector<uint8_t> b(sz, 0);
    write_le(b, 0, static_cast<uint16_t>((ps == 8) ? 9 : 0), 2);
    write_le(b, 2, static_cast<uint16_t>(0), 2);
    write_le(b, 4, static_cast<uint32_t>(0x1000), 4);
    if (ps == 8) {
        write_le(b, 8,  static_cast<uint64_t>(0x10000), 8);
        write_le(b, 16, static_cast<uint64_t>(0x7FFFFFFF0000), 8);
        write_le(b, 24, static_cast<uint64_t>(1), 8);
        write_le(b, 32, static_cast<uint32_t>(1), 4);
        write_le(b, 36, static_cast<uint32_t>(0), 4);
        write_le(b, 40, static_cast<uint32_t>(0x10000), 4);
        write_le(b, 44, static_cast<uint16_t>(0), 2);
        write_le(b, 46, static_cast<uint16_t>(0), 2);
    } else {
        write_le(b, 8,  static_cast<uint64_t>(0x10000), 4);
        write_le(b, 12, static_cast<uint64_t>(0x7FFEFFFF), 4);
        write_le(b, 16, static_cast<uint64_t>(1), 4);
        write_le(b, 20, static_cast<uint32_t>(1), 4);
        write_le(b, 24, static_cast<uint32_t>(0), 4);
        write_le(b, 28, static_cast<uint32_t>(0x10000), 4);
        write_le(b, 32, static_cast<uint16_t>(0), 2);
        write_le(b, 34, static_cast<uint16_t>(0), 2);
    }
    mm(emu)->mem_write(lpSystemInfo, b);
    return 0;
}

uint64_t Kernel32::GetVersion(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return (19041 << 16) | (0 << 8) | 10;
}

uint64_t Kernel32::GetVersionExA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t info_ptr = argv[0];
    if (!info_ptr) return 0;
    std::vector<uint8_t> info(156, 0);
    write_le(info, 0, static_cast<uint32_t>(156), 4);
    write_le(info, 4, static_cast<uint32_t>(10), 4);
    write_le(info, 8, static_cast<uint32_t>(0), 4);
    write_le(info, 12, static_cast<uint32_t>(19041), 4);
    write_le(info, 16, static_cast<uint32_t>(10), 4);
    mm(emu)->mem_write(info_ptr, info);
    return 1;
}

uint64_t Kernel32::IsDebuggerPresent(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return 0;
}

uint64_t Kernel32::SetErrorMode(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t mode = static_cast<uint32_t>(argv[0]);
    (void)mode;
    return 0;
}

uint64_t Kernel32::GetSystemTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t st_ptr = argv[0];
    if (!st_ptr) return 0;
    auto now = std::time(nullptr);
    auto* tm = std::gmtime(&now);
    std::vector<uint8_t> st(16, 0);
    write_le(st, 0, static_cast<uint16_t>(tm->tm_year + 1900), 2);
    write_le(st, 2, static_cast<uint16_t>(tm->tm_mon + 1), 2);
    write_le(st, 4, static_cast<uint16_t>(tm->tm_wday), 2);
    write_le(st, 6, static_cast<uint16_t>(tm->tm_mday), 2);
    write_le(st, 8, static_cast<uint16_t>(tm->tm_hour), 2);
    write_le(st, 10, static_cast<uint16_t>(tm->tm_min), 2);
    write_le(st, 12, static_cast<uint16_t>(tm->tm_sec), 2);
    write_le(st, 14, static_cast<uint16_t>(0), 2);
    mm(emu)->mem_write(st_ptr, st);
    return 0;
}

uint64_t Kernel32::GetLocalTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return GetSystemTime(emu, argv, ctx);
}

uint64_t Kernel32::SystemTimeToFileTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::FileTimeToSystemTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t ft_ptr = argv[0];
    uint64_t st_ptr = argv[1];
    (void)ft_ptr;
    if (st_ptr) {
        auto now = std::time(nullptr);
        auto* tm = std::gmtime(&now);
        std::vector<uint8_t> st(16, 0);
        write_le(st, 0, static_cast<uint16_t>(tm->tm_year + 1900), 2);
        write_le(st, 2, static_cast<uint16_t>(tm->tm_mon + 1), 2);
        write_le(st, 4, static_cast<uint16_t>(tm->tm_wday), 2);
        write_le(st, 6, static_cast<uint16_t>(tm->tm_mday), 2);
        write_le(st, 8, static_cast<uint16_t>(tm->tm_hour), 2);
        write_le(st, 10, static_cast<uint16_t>(tm->tm_min), 2);
        write_le(st, 12, static_cast<uint16_t>(tm->tm_sec), 2);
        write_le(st, 14, static_cast<uint16_t>(0), 2);
        mm(emu)->mem_write(st_ptr, st);
    }
    return 1;
}

uint64_t Kernel32::QueryPerformanceCounter(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::QueryPerformanceFrequency(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t ptr = argv[0];
    if (ptr) {
        std::vector<uint8_t> buf(8);
        write_le(buf, 0, 10000000ULL, 8);
        mm(emu)->mem_write(ptr, buf);
    }
    return 1;
}

uint64_t Kernel32::GetComputerNameA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetUserNameA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetUnhandledExceptionFilter(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t filter = argv[0];
    (void)filter;
    return 0;
}

// 
//  ERROR APIs
// 

uint64_t Kernel32::GetLastError(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t err = static_cast<uint32_t>(w32(emu)->get_last_error());
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return static_cast<uint64_t>(err);
}

uint64_t Kernel32::SetLastError(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t err = static_cast<uint32_t>(argv[0]);
    w32(emu)->set_last_error(static_cast<int>(err));
    return 0;
}

uint64_t Kernel32::RaiseException(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t code = static_cast<uint32_t>(argv[0]);
    uint32_t flags = static_cast<uint32_t>(argv[1]);
    uint32_t num_args = static_cast<uint32_t>(argv[2]);
    uint64_t args_ptr = argv[3];
    (void)code; (void)flags; (void)num_args; (void)args_ptr;
    return 0;
}

uint64_t Kernel32::UnhandledExceptionFilter(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t exc_ptr = argv[0];
    (void)exc_ptr;
    return 0;
}

// 
//  STRING APIs
// 

uint64_t Kernel32::lstrlenA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t str_ptr = argv[0];
    if (!str_ptr) return 0;
    std::string s = be(emu)->read_mem_string(str_ptr, 1);
    return static_cast<uint64_t>(s.size());
}

uint64_t Kernel32::lstrcpyA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    if (!dst || !src) return dst;
    std::string s = be(emu)->read_mem_string(src, 1);
    s.push_back('\0');
    be(emu)->write_mem_string(s, dst, 1);
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return dst;
}

uint64_t Kernel32::lstrcatA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::lstrcmpA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t s1_ptr = argv[0];
    uint64_t s2_ptr = argv[1];
    if (!s1_ptr || !s2_ptr) return 1;
    std::string s1 = be(emu)->read_mem_string(s1_ptr, 1);
    std::string s2 = be(emu)->read_mem_string(s2_ptr, 1);
    if (s1 == s2) return 0;
    return (s1 < s2) ? -1 : 1;
}

uint64_t Kernel32::MultiByteToWideChar(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::WideCharToMultiByte(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetCommandLineA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    std::string cmdline = "emulated.exe";
    uint64_t addr = mm(emu)->mem_map(cmdline.size() + 1, 0, 4, "api.cmdline");
    cmdline.push_back('\0');
    be(emu)->write_mem_string(cmdline, addr, 1);
    return addr;
}

uint64_t Kernel32::GetCommandLineW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    std::wstring wcmd = L"emulated.exe";
    size_t bytes = wcmd.size() * 2 + 2;
    uint64_t addr = mm(emu)->mem_map(bytes, 0, 4, "api.cmdlineW");
    std::vector<uint8_t> data(bytes, 0);
    for (size_t i = 0; i < wcmd.size(); i++) {
        write_le(data, i * 2, static_cast<uint16_t>(wcmd[i]), 2);
    }
    mm(emu)->mem_write(addr, data);
    return addr;
}

// 
//  ENVIRONMENT APIs
// 

uint64_t Kernel32::GetEnvironmentVariableA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetEnvironmentVariableA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t name_ptr = argv[0];
    uint64_t val_ptr = argv[1];
    if (!name_ptr) return 0;
    std::string name = be(emu)->read_mem_string(name_ptr, 1);
    std::string val;
    if (val_ptr) val = be(emu)->read_mem_string(val_ptr, 1);
    we(emu)->set_env(name, val);
    return 1;
}

uint64_t Kernel32::GetCurrentDirectoryA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetCurrentDirectoryA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t path_ptr = argv[0];
    if (!path_ptr) return 0;
    std::string path = be(emu)->read_mem_string(path_ptr, 1);
    we(emu)->set_cd(path);
    return 1;
}

uint64_t Kernel32::ExpandEnvironmentStringsA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::CreateToolhelp32Snapshot(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t flags = static_cast<uint32_t>(argv[0]);
    uint32_t pid = static_cast<uint32_t>(argv[1]);
    uint64_t hnd = g_next_snap_handle++;
    std::unordered_map<uint32_t, SnapEntry> entries;
    if (flags & K32_TH32CS_SNAPPROCESS) {
        auto procs = we(emu)->get_processes();
        SnapEntry se;
        se.index = 0;
        //TODO:
        //se.items = (std::vector<void*>)procs;
        se.pid = 0;
        entries[K32_TH32CS_SNAPPROCESS] = se;
    }
    if (flags & K32_TH32CS_SNAPTHREAD) {
        std::shared_ptr<Process> proc_obj = nullptr;
        auto procs = we(emu)->get_processes();
        for (auto proc : procs) {
            //auto proc = we(emu)->find_process(p);
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
            //auto p = we(emu)->find_process(proc_obj);
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
        //TODO:
        //se.items = (std::vector<void*>)mods;
        se.pid = static_cast<int>(pid);
        entries[K32_TH32CS_SNAPMODULE] = se;
    }
    g_snapshots[hnd] = entries;
    return hnd;
}

static uint64_t process32_impl(void* emu, const std::vector<uint64_t>& argv, bool first) {
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
    size_t struct_sz = 4 + 4 + 4 + static_cast<size_t>(ps) + 4 + 4 + 4 + 4 + 4 + 260;
    std::vector<uint8_t> buf(struct_sz, 0);
    write_le(buf, 0, static_cast<uint32_t>(struct_sz), 4);
    auto proc = we(emu)->find_process(entry.items[static_cast<size_t>(idx)]);
    if (!proc) return 0;
    write_le(buf, 8, static_cast<uint32_t>(proc->get_pid()), 4);
    std::string exe = proc->image.empty() ? "emulated.exe" : proc->image;
    size_t exe_off = struct_sz - 260;
    for (size_t i = 0; i < exe.size() && i < 259; i++) {
        buf[exe_off + i] = static_cast<uint8_t>(exe[i]);
    }
    buf[exe_off + exe.size()] = 0;
    mm(emu)->mem_write(pe32, buf);
    return 1;
}

uint64_t Kernel32::Process32FirstA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return process32_impl(emu, argv, true);
}

uint64_t Kernel32::Process32NextA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return process32_impl(emu, argv, false);
}

static uint64_t thread32_impl(void* emu, const std::vector<uint64_t>& argv, bool first) {
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
    size_t struct_sz = 28;
    std::vector<uint8_t> buf(struct_sz, 0);
    write_le(buf, 0, static_cast<uint32_t>(struct_sz), 4);
    auto* thread = static_cast<Thread*>(entry.items[static_cast<size_t>(idx)]);
    write_le(buf, 8, static_cast<uint32_t>(thread->get_id()), 4);
    write_le(buf, 12, static_cast<uint32_t>(entry.pid), 4);
    mm(emu)->mem_write(te32, buf);
    return 1;
}

uint64_t Kernel32::Thread32First(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return thread32_impl(emu, argv, true);
}

uint64_t Kernel32::Thread32Next(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return thread32_impl(emu, argv, false);
}

static uint64_t module32_impl(void* emu, const std::vector<uint64_t>& argv, bool first) {
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
    size_t struct_sz = 4 + 4 + 4 + static_cast<size_t>(ps) * 4 + 4 + 4 + 260 + 260;
    std::vector<uint8_t> buf(struct_sz, 0);
    write_le(buf, 0, static_cast<uint32_t>(struct_sz), 4);
    auto* mod = static_cast<KernelObject*>(entry.items[static_cast<size_t>(idx)]);
    write_le(buf, 8, static_cast<uint32_t>(mod->get_id()), 4);
    write_le(buf, 12, static_cast<uint32_t>(entry.pid), 4);
    size_t base_off = (ps == 8) ? 20 : 16;
    write_le(buf, base_off, reinterpret_cast<uint64_t>(mod), static_cast<size_t>(ps));
    size_t size_off = base_off + static_cast<size_t>(ps);
    write_le(buf, size_off, static_cast<uint64_t>(0x1000), static_cast<size_t>(ps));
    std::string mname = mod->get_obj_name();
    size_t module_off = struct_sz - 520;
    for (size_t i = 0; i < mname.size() && i < 259; i++) {
        buf[module_off + i] = static_cast<uint8_t>(mname[i]);
    }
    buf[module_off + mname.size()] = 0;
    size_t path_off = struct_sz - 260;
    for (size_t i = 0; i < mname.size() && i < 259; i++) {
        buf[path_off + i] = static_cast<uint8_t>(mname[i]);
    }
    buf[path_off + mname.size()] = 0;
    mm(emu)->mem_write(me32, buf);
    return 1;
}

uint64_t Kernel32::Module32FirstA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return module32_impl(emu, argv, true);
}

uint64_t Kernel32::Module32NextA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return module32_impl(emu, argv, false);
}

// 
//  CONSOLE / MISC APIs
// 

uint64_t Kernel32::AllocConsole(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return 1;
}

uint64_t Kernel32::FreeConsole(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return 1;
}

uint64_t Kernel32::GetConsoleMode(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::SetConsoleMode(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t hConsole = argv[0];
    uint32_t mode = static_cast<uint32_t>(argv[1]);
    (void)hConsole; (void)mode;
    return 1;
}

uint64_t Kernel32::OutputDebugStringA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint64_t str_ptr = argv[0];
    if (str_ptr) {
        std::string msg = be(emu)->read_mem_string(str_ptr, 1);
        (void)msg;
    }
    return 0;
}

uint64_t Kernel32::GetACP(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return 936;
}

uint64_t Kernel32::DecodePointer(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return argv[0];
}

uint64_t Kernel32::EncodePointer(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return argv[0];
}

uint64_t Kernel32::IsProcessorFeaturePresent(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t feature = static_cast<uint32_t>(argv[0]);
    switch (feature) {
        case 0: case 1: return 0;
        default: return 1;
    }
}

// ==========================================
//  W function stubs (delegate to A versions or return 1)
STUB(Kernel32, DeleteFileW)
STUB(Kernel32, CreateDirectoryW)
STUB(Kernel32, GetFileAttributesW)
STUB(Kernel32, FindFirstFileW)
STUB(Kernel32, FindNextFileW)
STUB(Kernel32, CreateFileMappingW)
STUB(Kernel32, GetDriveTypeW)
STUB(Kernel32, GetDiskFreeSpaceExW)
STUB(Kernel32, CreateEventW)
STUB(Kernel32, OpenMutexW)
STUB(Kernel32, CreateWaitableTimerW)
STUB(Kernel32, GetVersionExW)
STUB(Kernel32, GetComputerNameW)
STUB(Kernel32, GetUserNameW)
STUB(Kernel32, lstrlenW)
STUB(Kernel32, lstrcpyW)
STUB(Kernel32, lstrcatW)
STUB(Kernel32, lstrcmpW)
STUB(Kernel32, GetEnvironmentVariableW)
STUB(Kernel32, SetEnvironmentVariableW)
STUB(Kernel32, GetCurrentDirectoryW)
STUB(Kernel32, ExpandEnvironmentStringsW)
STUB(Kernel32, Process32FirstW)
STUB(Kernel32, Process32NextW)
STUB(Kernel32, Module32FirstW)
STUB(Kernel32, Module32NextW)
STUB(Kernel32, OutputDebugStringW)
STUB(Kernel32, CreateProcessW)

//  STUBBED AND FULLY IMPLEMENTED NEW APIs
// ==========================================

STUB(Kernel32, AcquireSRWLockExclusive)
STUB(Kernel32, AcquireSRWLockShared)
STUB(Kernel32, AddAtom)
STUB(Kernel32, AddVectoredContinueHandler)
STUB(Kernel32, AddVectoredExceptionHandler)
STUB(Kernel32, AreFileApisANSI)
STUB(Kernel32, CheckRemoteDebuggerPresent)
STUB(Kernel32, CompareFileTime)
STUB(Kernel32, ConnectNamedPipe)
STUB(Kernel32, CreateIoCompletionPort)
STUB(Kernel32, CreateMutexEx)
STUB(Kernel32, CreateNamedPipe)
STUB(Kernel32, CreatePipe)
STUB(Kernel32, CreateProcessInternal)
STUB(Kernel32, CreateSemaphoreW)
STUB(Kernel32, CreateWaitableTimerEx)
STUB(Kernel32, CreateWaitableTimerExW)
STUB(Kernel32, DeleteAtom)
STUB(Kernel32, DisconnectNamedPipe)
STUB(Kernel32, DuplicateHandle)
STUB(Kernel32, EnumProcesses)
STUB(Kernel32, FindAtom)
STUB(Kernel32, FindFirstFileEx)
STUB(Kernel32, FindFirstVolume)
STUB(Kernel32, FindNextVolume)
STUB(Kernel32, FindResource)
STUB(Kernel32, FindResourceEx)
STUB(Kernel32, FindVolumeClose)
STUB(Kernel32, FlsGetValue2)
STUB(Kernel32, FreeEnvironmentStrings)
STUB(Kernel32, FreeLibraryAndExitThread)
STUB(Kernel32, FreeResource)
STUB(Kernel32, GetAtomName)
STUB(Kernel32, GetBinaryType)
STUB(Kernel32, GetCPInfo)
STUB(Kernel32, GetCommProperties)
STUB(Kernel32, GetCommTimeouts)
STUB(Kernel32, GetComputerNameEx)
STUB(Kernel32, GetConsoleTitle)
STUB(Kernel32, GetConsoleWindow)
STUB(Kernel32, GetCurrentPackageId)
STUB(Kernel32, GetDateFormat)
STUB(Kernel32, GetEnvironmentStrings)
STUB(Kernel32, GetErrorMode)
STUB(Kernel32, GetFileAttributesEx)
STUB(Kernel32, GetFileSizeEx)
STUB(Kernel32, GetFullPathName)
STUB(Kernel32, GetHandleInformation)
STUB(Kernel32, GetLocaleInfo)
STUB(Kernel32, GetLogicalDrives)
STUB(Kernel32, GetLongPathName)
STUB(Kernel32, GetMailslotInfo)
STUB(Kernel32, GetModuleFileNameExA)
STUB(Kernel32, GetModuleHandleEx)
STUB(Kernel32, GetNativeSystemInfo)
STUB(Kernel32, GetOEMCP)
STUB(Kernel32, GetPhysicallyInstalledSystemMemory)
STUB(Kernel32, GetProcessAffinityMask)
STUB(Kernel32, GetProcessHandleCount)
STUB(Kernel32, GetProcessVersion)
STUB(Kernel32, GetProfileInt)
STUB(Kernel32, GetShortPathName)
STUB(Kernel32, GetStartupInfo)
STUB(Kernel32, GetStringTypeA)
STUB(Kernel32, GetStringTypeW)
STUB(Kernel32, GetSystemDefaultLCID)
STUB(Kernel32, GetSystemDefaultLangID)
STUB(Kernel32, GetSystemDefaultUILanguage)
STUB(Kernel32, GetSystemDirectory)
STUB(Kernel32, GetSystemFirmwareTable)
STUB(Kernel32, GetSystemTimePreciseAsFileTime)
STUB(Kernel32, GetSystemTimes)
STUB(Kernel32, GetTempFileName)
STUB(Kernel32, GetTempPath)
uint64_t Kernel32::GetThreadContext(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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
    void* saved_ctx = thread->get_context();
    if (!saved_ctx) {
        // No saved context - read current context from emulator
        uint64_t ctx_addr = we(emu)->mem_map(1232, 0, 4, "emu.thread.context.tmp");
        auto ctx_data = we(emu)->mem_read(ctx_addr, 1232);
        we(emu)->mem_write(lpContext, ctx_data);
        return 1;
    }

    // Write the saved context to the output buffer
    uint64_t src_addr = reinterpret_cast<uint64_t>(saved_ctx);
    auto ctx_data = we(emu)->mem_read(src_addr, 1232);
    we(emu)->mem_write(lpContext, ctx_data);
    return 1;
}
STUB(Kernel32, GetThreadId)
STUB(Kernel32, GetThreadLocale)
STUB(Kernel32, GetThreadTimes)
STUB(Kernel32, GetThreadUILanguage)
STUB(Kernel32, GetTickCount64)
STUB(Kernel32, GetTimeFormat)
STUB(Kernel32, GetTimeZoneInformation)
STUB(Kernel32, GetUserDefaultLCID)
STUB(Kernel32, GetUserDefaultLangID)
STUB(Kernel32, GetUserDefaultUILanguage)
STUB(Kernel32, GetVolumeInformation)
STUB(Kernel32, GetVolumePathNamesForVolumeName)
STUB(Kernel32, GetWindowsDirectory)
STUB(Kernel32, GlobalAddAtomA)
STUB(Kernel32, GlobalFlags)
STUB(Kernel32, GlobalHandle)
STUB(Kernel32, GlobalLock)
STUB(Kernel32, GlobalMemoryStatus)
STUB(Kernel32, GlobalMemoryStatusEx)
STUB(Kernel32, GlobalSize)
STUB(Kernel32, GlobalUnlock)
STUB(Kernel32, HeapReAlloc)
STUB(Kernel32, HeapSetInformation)
STUB(Kernel32, HeapSize)
STUB(Kernel32, InitOnceBeginInitialize)
STUB(Kernel32, InitializeConditionVariable)
STUB(Kernel32, InitializeCriticalSectionAndSpinCount)
STUB(Kernel32, InitializeCriticalSectionEx)
STUB(Kernel32, InitializeSListHead)
STUB(Kernel32, InitializeSRWLock)
STUB(Kernel32, IsBadReadPtr)
STUB(Kernel32, IsBadStringPtr)
STUB(Kernel32, IsBadWritePtr)
STUB(Kernel32, IsDBCSLeadByte)
STUB(Kernel32, IsValidCodePage)
STUB(Kernel32, IsValidLocale)
STUB(Kernel32, IsWow64Process)
STUB(Kernel32, LCMapString)
STUB(Kernel32, LCMapStringEx)
STUB(Kernel32, LoadResource)
STUB(Kernel32, LocalLock)
STUB(Kernel32, LocalReAlloc)
STUB(Kernel32, LockResource)
STUB(Kernel32, MoveFile)
STUB(Kernel32, MulDiv)
STUB(Kernel32, OpenEvent)
STUB(Kernel32, OpenWaitableTimer)
STUB(Kernel32, PeekNamedPipe)
STUB(Kernel32, ProcessIdToSessionId)
STUB(Kernel32, ReleaseSRWLockExclusive)
STUB(Kernel32, ReleaseSRWLockShared)
STUB(Kernel32, RemoveVectoredExceptionHandler)
STUB(Kernel32, RtlCaptureContext)
STUB(Kernel32, RtlLookupFunctionEntry)
STUB(Kernel32, RtlUnwind)
STUB(Kernel32, SetConsoleCtrlHandler)
STUB(Kernel32, SetConsoleHistoryInfo)
STUB(Kernel32, SetConsoleTitle)
STUB(Kernel32, SetDefaultDllDirectories)
STUB(Kernel32, SetDllDirectory)
STUB(Kernel32, SetFilePointerEx)
STUB(Kernel32, SetHandleCount)
STUB(Kernel32, SetHandleInformation)
STUB(Kernel32, SetPriorityClass)
STUB(Kernel32, SetProcessPriorityBoost)
STUB(Kernel32, SetThreadContext)
STUB(Kernel32, SetThreadDescription)
STUB(Kernel32, SetThreadErrorMode)
STUB(Kernel32, SetThreadLocale)
STUB(Kernel32, SetThreadStackGuarantee)
STUB(Kernel32, SizeofResource)
STUB(Kernel32, SystemTimeToTzSpecificLocalTime)
STUB(Kernel32, VerSetConditionMask)
STUB(Kernel32, VerifyVersionInfo)
STUB(Kernel32, VirtualAllocExNuma)
STUB(Kernel32, WTSGetActiveConsoleSessionId)
STUB(Kernel32, WaitForSingleObjectEx)
STUB(Kernel32, WakeAllConditionVariable)
STUB(Kernel32, WerGetFlags)
STUB(Kernel32, WerSetFlags)
STUB(Kernel32, Wow64DisableWow64FsRedirection)
STUB(Kernel32, Wow64RevertWow64FsRedirection)
STUB(Kernel32, _lclose)
STUB(Kernel32, _llseek)
STUB(Kernel32, _lopen)

// 
//  TLS APIs
// 

uint64_t Kernel32::TlsAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::TlsFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::TlsGetValue(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::TlsSetValue(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::FlsAlloc(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::FlsFree(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    w32(emu)->set_last_error(K32_ERR_SUCCESS);
    return 1;
}

uint64_t Kernel32::FlsGetValue(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::FlsSetValue(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::GetStdHandle(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    uint32_t nStdHandle = static_cast<uint32_t>(argv[0]);
    auto proc = we(emu)->get_current_process();
    if (proc) {
        return static_cast<uint64_t>(proc->get_std_handle(static_cast<int>(nStdHandle)));
    }
    return 0;
}

uint64_t Kernel32::GetFileType(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    (void)emu; (void)argv;
    return 1; // FILE_TYPE_DISK
}

// 
//  SYSTEM TIME
// 

uint64_t Kernel32::GetSystemTimeAsFileTime(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::InterlockedIncrement(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::InterlockedDecrement(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::InterlockedExchange(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

uint64_t Kernel32::InterlockedCompareExchange(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
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

static uint64_t lstrcmpi_impl(void* emu, const std::vector<uint64_t>& argv, bool is_wide) {
    uint64_t str1_ptr = argv[0];
    uint64_t str2_ptr = argv[1];
    if (!str1_ptr || !str2_ptr) return 1;
    int cw = is_wide ? 2 : 1;
    std::string s1 = be(emu)->read_mem_string(str1_ptr, cw);
    std::string s2 = be(emu)->read_mem_string(str2_ptr, cw);
    std::string s1_lower = s1;
    std::string s2_lower = s2;
    std::transform(s1_lower.begin(), s1_lower.end(), s1_lower.begin(), ::tolower);
    std::transform(s2_lower.begin(), s2_lower.end(), s2_lower.begin(), ::tolower);
    if (s1_lower == s2_lower) {
        return 0;
    }
    return (s1_lower < s2_lower) ? -1 : 1;
}

uint64_t Kernel32::lstrcmpi(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcmpi_impl(emu, argv, false);
}

uint64_t Kernel32::lstrcmpiA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcmpi_impl(emu, argv, false);
}

uint64_t Kernel32::lstrcmpiW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcmpi_impl(emu, argv, true);
}

static uint64_t lstrcpyn_impl(void* emu, const std::vector<uint64_t>& argv, bool is_wide) {
    uint64_t dst = argv[0];
    uint64_t src = argv[1];
    int max_len = static_cast<int>(argv[2]);
    if (!dst || !src || max_len <= 0) return dst;
    int cw = is_wide ? 2 : 1;
    std::string s = be(emu)->read_mem_string(src, cw);
    if (static_cast<int>(s.size()) >= max_len) {
        s = s.substr(0, max_len - 1);
    }
    s.push_back('\0');
    be(emu)->write_mem_string(s, dst, cw);
    return dst;
}

uint64_t Kernel32::lstrcpyn(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcpyn_impl(emu, argv, false);
}

uint64_t Kernel32::lstrcpynA(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcpyn_impl(emu, argv, false);
}

uint64_t Kernel32::lstrcpynW(void* emu, const std::vector<uint64_t>& argv, void* ctx) {
    return lstrcpyn_impl(emu, argv, true);
}

}} // namespaces
