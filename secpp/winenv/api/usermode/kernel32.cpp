// kernel32.cpp — kernel32.dll handler (v2 — ~110 APIs, macro-driven)
#include "kernel32.h"
#include <chrono>
#include <thread>
#include <ctime>

namespace speakeasy { namespace api {

Kernel32::Kernel32() {
    INIT_API_TABLE(Kernel32)
    REG(Kernel32, CreateFileA, 7)    REG(Kernel32, CreateFileW, 7)
    REG(Kernel32, ReadFile, 5)       REG(Kernel32, WriteFile, 5)
    REG(Kernel32, CloseHandle, 1)    REG(Kernel32, DeleteFileA, 1)
    REG(Kernel32, CopyFileA, 3)      REG(Kernel32, CopyFileW, 3)
    REG(Kernel32, CreateDirectoryA, 2) REG(Kernel32, RemoveDirectoryA, 1)
    REG(Kernel32, GetFileAttributesA, 1) REG(Kernel32, SetFilePointer, 4)
    REG(Kernel32, GetFileSize, 2)    REG(Kernel32, FindFirstFileA, 2)
    REG(Kernel32, FindNextFileA, 2)  REG(Kernel32, FindClose, 1)
    REG(Kernel32, CreateFileMappingA, 6) REG(Kernel32, MapViewOfFile, 5)
    REG(Kernel32, UnmapViewOfFile, 1) REG(Kernel32, FlushFileBuffers, 1)
    REG(Kernel32, SetEndOfFile, 1)   REG(Kernel32, GetFileTime, 4)
    REG(Kernel32, SetFileTime, 4)    REG(Kernel32, GetFileInformationByHandle, 2)
    REG(Kernel32, DeviceIoControl, 8) REG(Kernel32, GetDriveTypeA, 1)
    REG(Kernel32, GetDiskFreeSpaceExA, 4)
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
    REG(Kernel32, GetModuleHandleW, 1) REG(Kernel32, GetModuleFileNameA, 3)
    REG(Kernel32, DisableThreadLibraryCalls, 1)
    REG(Kernel32, CreateProcessA, 10) REG(Kernel32, OpenProcess, 3)
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
    REG(Kernel32, CreateEventA, 4)   REG(Kernel32, CreateMutexA, 3)
    REG(Kernel32, OpenMutexA, 3)     REG(Kernel32, ReleaseMutex, 1)
    REG(Kernel32, SetEvent, 1)       REG(Kernel32, ResetEvent, 1)
    REG(Kernel32, WaitForSingleObject, 2) REG(Kernel32, WaitForMultipleObjects, 4)
    REG(Kernel32, InitializeCriticalSection, 1) REG(Kernel32, DeleteCriticalSection, 1)
    REG(Kernel32, EnterCriticalSection, 1) REG(Kernel32, LeaveCriticalSection, 1)
    REG(Kernel32, CreateWaitableTimerA, 3) REG(Kernel32, SetWaitableTimer, 6)
    REG(Kernel32, CancelWaitableTimer, 1)
    REG(Kernel32, GetTickCount, 0)   REG(Kernel32, GetSystemInfo, 1)
    REG(Kernel32, GetVersion, 0)     REG(Kernel32, GetVersionExA, 1)
    REG(Kernel32, IsDebuggerPresent, 0) REG(Kernel32, SetErrorMode, 1)
    REG(Kernel32, GetSystemTime, 1)  REG(Kernel32, GetLocalTime, 1)
    REG(Kernel32, SystemTimeToFileTime, 2) REG(Kernel32, FileTimeToSystemTime, 2)
    REG(Kernel32, QueryPerformanceCounter, 1) REG(Kernel32, QueryPerformanceFrequency, 1)
    REG(Kernel32, GetComputerNameA, 2) REG(Kernel32, GetUserNameA, 2)
    REG(Kernel32, SetUnhandledExceptionFilter, 1)
    REG(Kernel32, GetLastError, 0)   REG(Kernel32, SetLastError, 1)
    REG(Kernel32, RaiseException, 4) REG(Kernel32, UnhandledExceptionFilter, 1)
    REG(Kernel32, lstrlenA, 1)       REG(Kernel32, lstrcpyA, 2)
    REG(Kernel32, lstrcatA, 2)       REG(Kernel32, lstrcmpA, 2)
    REG(Kernel32, MultiByteToWideChar, 6) REG(Kernel32, WideCharToMultiByte, 8)
    REG(Kernel32, GetCommandLineA, 0) REG(Kernel32, GetCommandLineW, 0)
    REG(Kernel32, GetEnvironmentVariableA, 3) REG(Kernel32, SetEnvironmentVariableA, 2)
    REG(Kernel32, GetCurrentDirectoryA, 2) REG(Kernel32, SetCurrentDirectoryA, 1)
    REG(Kernel32, ExpandEnvironmentStringsA, 3)
    REG(Kernel32, CreateToolhelp32Snapshot, 2)
    REG(Kernel32, Process32FirstA, 2) REG(Kernel32, Process32NextA, 2)
    REG(Kernel32, Thread32First, 2)  REG(Kernel32, Thread32Next, 2)
    REG(Kernel32, Module32FirstA, 2) REG(Kernel32, Module32NextA, 2)
    REG(Kernel32, AllocConsole, 0)   REG(Kernel32, FreeConsole, 0)
    REG(Kernel32, GetConsoleMode, 2) REG(Kernel32, SetConsoleMode, 2)
    REG(Kernel32, OutputDebugStringA, 1) REG(Kernel32, GetACP, 0)
    REG(Kernel32, DecodePointer, 1)  REG(Kernel32, EncodePointer, 1)
    REG(Kernel32, IsProcessorFeaturePresent, 1)
    END_API_TABLE
}

// ── Bulk stubs ──────────────────────────────────────────────

#define K32_STUB(n) STUB(Kernel32, n)

K32_STUB(CreateFileA) K32_STUB(CreateFileW) K32_STUB(ReadFile) K32_STUB(WriteFile)
K32_STUB(CloseHandle) K32_STUB(DeleteFileA) K32_STUB(CopyFileA) K32_STUB(CopyFileW)
K32_STUB(CreateDirectoryA) K32_STUB(RemoveDirectoryA) K32_STUB(GetFileAttributesA)
K32_STUB(SetFilePointer) K32_STUB(GetFileSize) K32_STUB(FindFirstFileA)
K32_STUB(FindNextFileA) K32_STUB(FindClose) K32_STUB(CreateFileMappingA)
K32_STUB(MapViewOfFile) K32_STUB(UnmapViewOfFile) K32_STUB(FlushFileBuffers)
K32_STUB(SetEndOfFile) K32_STUB(GetFileTime) K32_STUB(SetFileTime)
K32_STUB(GetFileInformationByHandle) K32_STUB(DeviceIoControl) K32_STUB(GetDriveTypeA)
K32_STUB(GetDiskFreeSpaceExA)

K32_STUB(VirtualAlloc) K32_STUB(VirtualAllocEx) K32_STUB(VirtualFree)
K32_STUB(VirtualProtect) K32_STUB(VirtualProtectEx) K32_STUB(VirtualQuery)
K32_STUB(WriteProcessMemory) K32_STUB(ReadProcessMemory) K32_STUB(HeapAlloc)
K32_STUB(HeapFree) K32_STUB(HeapCreate) K32_STUB(HeapDestroy) K32_STUB(GetProcessHeap)
K32_STUB(GlobalAlloc) K32_STUB(GlobalFree) K32_STUB(LocalAlloc) K32_STUB(LocalFree)
K32_STUB(RtlMoveMemory) K32_STUB(RtlZeroMemory)

K32_STUB(LoadLibraryA) K32_STUB(LoadLibraryW) K32_STUB(LoadLibraryExA)
K32_STUB(FreeLibrary) K32_STUB(GetProcAddress) K32_STUB(GetModuleHandleA)
K32_STUB(GetModuleHandleW) K32_STUB(GetModuleFileNameA) K32_STUB(DisableThreadLibraryCalls)

K32_STUB(CreateProcessA) K32_STUB(OpenProcess) K32_STUB(TerminateProcess)
K32_STUB(GetCurrentProcess) K32_STUB(GetCurrentProcessId) K32_STUB(ExitProcess)
K32_STUB(CreateThread) K32_STUB(CreateRemoteThread) K32_STUB(OpenThread)
K32_STUB(TerminateThread) K32_STUB(GetCurrentThread) K32_STUB(GetCurrentThreadId)
K32_STUB(ResumeThread) K32_STUB(SuspendThread) K32_STUB(ExitThread)
K32_STUB(SleepEx) K32_STUB(SwitchToThread) K32_STUB(GetExitCodeProcess)
K32_STUB(GetExitCodeThread) K32_STUB(QueueUserAPC) K32_STUB(WinExec)
K32_STUB(SetThreadPriority) K32_STUB(GetThreadPriority)

K32_STUB(CreateEventA) K32_STUB(CreateMutexA) K32_STUB(OpenMutexA)
K32_STUB(ReleaseMutex) K32_STUB(SetEvent) K32_STUB(ResetEvent)
K32_STUB(WaitForSingleObject) K32_STUB(WaitForMultipleObjects)
K32_STUB(InitializeCriticalSection) K32_STUB(DeleteCriticalSection)
K32_STUB(EnterCriticalSection) K32_STUB(LeaveCriticalSection)
K32_STUB(CreateWaitableTimerA) K32_STUB(SetWaitableTimer) K32_STUB(CancelWaitableTimer)

K32_STUB(GetVersion) K32_STUB(GetVersionExA) K32_STUB(SetErrorMode)
K32_STUB(GetSystemTime) K32_STUB(GetLocalTime) K32_STUB(SystemTimeToFileTime)
K32_STUB(FileTimeToSystemTime) K32_STUB(QueryPerformanceCounter)
K32_STUB(QueryPerformanceFrequency) K32_STUB(GetComputerNameA) K32_STUB(GetUserNameA)
K32_STUB(SetUnhandledExceptionFilter)

K32_STUB(GetLastError) K32_STUB(SetLastError) K32_STUB(RaiseException)
K32_STUB(UnhandledExceptionFilter)

K32_STUB(lstrlenA) K32_STUB(lstrcpyA) K32_STUB(lstrcatA) K32_STUB(lstrcmpA)
K32_STUB(MultiByteToWideChar) K32_STUB(WideCharToMultiByte)
K32_STUB(GetCommandLineA) K32_STUB(GetCommandLineW)

K32_STUB(GetEnvironmentVariableA) K32_STUB(SetEnvironmentVariableA)
K32_STUB(GetCurrentDirectoryA) K32_STUB(SetCurrentDirectoryA)
K32_STUB(ExpandEnvironmentStringsA)

K32_STUB(CreateToolhelp32Snapshot) K32_STUB(Process32FirstA) K32_STUB(Process32NextA)
K32_STUB(Thread32First) K32_STUB(Thread32Next) K32_STUB(Module32FirstA) K32_STUB(Module32NextA)

K32_STUB(AllocConsole) K32_STUB(FreeConsole) K32_STUB(GetConsoleMode)
K32_STUB(SetConsoleMode) K32_STUB(OutputDebugStringA) K32_STUB(GetACP)
K32_STUB(DecodePointer) K32_STUB(EncodePointer) K32_STUB(IsProcessorFeaturePresent)

// ── Real implementations ────────────────────────────────────

uint64_t Kernel32::Sleep(void*, const std::string&, int, const std::vector<uint64_t>& a) {
    if (!a.empty()) {
        auto ms = std::chrono::milliseconds(a[0]);
        std::this_thread::sleep_for(ms);
    }
    return 0;
}

uint64_t Kernel32::GetTickCount(void*, const std::string&, int, const std::vector<uint64_t>&) {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

uint64_t Kernel32::GetSystemInfo(void*, const std::string&, int, const std::vector<uint64_t>&) {
    return 0;  // TODO: populate SYSTEM_INFO struct
}

uint64_t Kernel32::IsDebuggerPresent(void*, const std::string&, int, const std::vector<uint64_t>&) {
    return 0;  // Speakeasy is NOT a debugger
}

uint64_t Kernel32::GetACP(void*, const std::string&, int, const std::vector<uint64_t>&) {
    return 1252;  // ANSI Latin-1
}

}} // namespaces
