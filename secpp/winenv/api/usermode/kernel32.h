// kernel32.h  kernel32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_KERNEL32_H
#define SPEAKEASY_KERNEL32_H
#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

class Kernel32 : public ApiHandler {
    API_LIST_BEGIN
    // File I/O
    API_ENTRY(CreateFileA, 7)       API_ENTRY(CreateFileW, 7)
    API_ENTRY(ReadFile, 5)          API_ENTRY(WriteFile, 5)
    API_ENTRY(CloseHandle, 1)       API_ENTRY(DeleteFileA, 1)
    API_ENTRY(CopyFileA, 3)         API_ENTRY(CopyFileW, 3)
    API_ENTRY(CreateDirectoryA, 2)  API_ENTRY(RemoveDirectoryA, 1)
    API_ENTRY(GetFileAttributesA, 1) API_ENTRY(SetFilePointer, 4)
    API_ENTRY(GetFileSize, 2)       API_ENTRY(FindFirstFileA, 2)
    API_ENTRY(FindNextFileA, 2)     API_ENTRY(FindClose, 1)
    API_ENTRY(CreateFileMappingA, 6) API_ENTRY(MapViewOfFile, 5)
    API_ENTRY(UnmapViewOfFile, 1)   API_ENTRY(FlushFileBuffers, 1)
    API_ENTRY(SetEndOfFile, 1)      API_ENTRY(GetFileTime, 4)
    API_ENTRY(SetFileTime, 4)       API_ENTRY(GetFileInformationByHandle, 2)
    API_ENTRY(DeviceIoControl, 8)   API_ENTRY(GetDriveTypeA, 1)
    API_ENTRY(GetDiskFreeSpaceExA, 4)
    // Memory
    API_ENTRY(VirtualAlloc, 4)      API_ENTRY(VirtualAllocEx, 5)
    API_ENTRY(VirtualFree, 3)       API_ENTRY(VirtualProtect, 4)
    API_ENTRY(VirtualProtectEx, 5)  API_ENTRY(VirtualQuery, 3)
    API_ENTRY(WriteProcessMemory, 5) API_ENTRY(ReadProcessMemory, 5)
    API_ENTRY(HeapAlloc, 3)         API_ENTRY(HeapFree, 3)
    API_ENTRY(HeapCreate, 3)        API_ENTRY(HeapDestroy, 1)
    API_ENTRY(GetProcessHeap, 0)    API_ENTRY(GlobalAlloc, 2)
    API_ENTRY(GlobalFree, 1)        API_ENTRY(LocalAlloc, 2)
    API_ENTRY(LocalFree, 1)         API_ENTRY(RtlMoveMemory, 3)
    API_ENTRY(RtlZeroMemory, 2)
    // DLL / Module
    API_ENTRY(LoadLibraryA, 1)      API_ENTRY(LoadLibraryW, 1)
    API_ENTRY(LoadLibraryExA, 3)    API_ENTRY(FreeLibrary, 1)
    API_ENTRY(GetProcAddress, 2)    API_ENTRY(GetModuleHandleA, 1)
    API_ENTRY(GetModuleHandleW, 1)  API_ENTRY(GetModuleFileNameA, 3)
    API_ENTRY(DisableThreadLibraryCalls, 1)
    // Process / Thread
    API_ENTRY(CreateProcessA, 10)   API_ENTRY(OpenProcess, 3)
    API_ENTRY(TerminateProcess, 2)  API_ENTRY(GetCurrentProcess, 0)
    API_ENTRY(GetCurrentProcessId, 0) API_ENTRY(ExitProcess, 1)
    API_ENTRY(CreateThread, 6)      API_ENTRY(CreateRemoteThread, 7)
    API_ENTRY(OpenThread, 3)        API_ENTRY(TerminateThread, 2)
    API_ENTRY(GetCurrentThread, 0)  API_ENTRY(GetCurrentThreadId, 0)
    API_ENTRY(ResumeThread, 1)      API_ENTRY(SuspendThread, 1)
    API_ENTRY(ExitThread, 1)        API_ENTRY(Sleep, 1)
    API_ENTRY(SleepEx, 2)           API_ENTRY(SwitchToThread, 0)
    API_ENTRY(GetExitCodeProcess, 2) API_ENTRY(GetExitCodeThread, 2)
    API_ENTRY(QueueUserAPC, 3)      API_ENTRY(WinExec, 2)
    API_ENTRY(SetThreadPriority, 2) API_ENTRY(GetThreadPriority, 1)
    // Sync
    API_ENTRY(CreateEventA, 4)      API_ENTRY(CreateMutexA, 3)
    API_ENTRY(OpenMutexA, 3)        API_ENTRY(ReleaseMutex, 1)
    API_ENTRY(SetEvent, 1)          API_ENTRY(ResetEvent, 1)
    API_ENTRY(WaitForSingleObject, 2) API_ENTRY(WaitForMultipleObjects, 4)
    API_ENTRY(InitializeCriticalSection, 1) API_ENTRY(DeleteCriticalSection, 1)
    API_ENTRY(EnterCriticalSection, 1) API_ENTRY(LeaveCriticalSection, 1)
    API_ENTRY(CreateWaitableTimerA, 3) API_ENTRY(SetWaitableTimer, 6)
    API_ENTRY(CancelWaitableTimer, 1)
    // System
    API_ENTRY(GetTickCount, 0)      API_ENTRY(GetSystemInfo, 1)
    API_ENTRY(GetVersion, 0)        API_ENTRY(GetVersionExA, 1)
    API_ENTRY(IsDebuggerPresent, 0) API_ENTRY(SetErrorMode, 1)
    API_ENTRY(GetSystemTime, 1)     API_ENTRY(GetLocalTime, 1)
    API_ENTRY(SystemTimeToFileTime, 2) API_ENTRY(FileTimeToSystemTime, 2)
    API_ENTRY(QueryPerformanceCounter, 1) API_ENTRY(QueryPerformanceFrequency, 1)
    API_ENTRY(GetComputerNameA, 2)  API_ENTRY(GetUserNameA, 2)
    API_ENTRY(SetUnhandledExceptionFilter, 1)
    // Error
    API_ENTRY(GetLastError, 0)      API_ENTRY(SetLastError, 1)
    API_ENTRY(RaiseException, 4)    API_ENTRY(UnhandledExceptionFilter, 1)
    // String / Encoding
    API_ENTRY(lstrlenA, 1)          API_ENTRY(lstrcpyA, 2)
    API_ENTRY(lstrcatA, 2)          API_ENTRY(lstrcmpA, 2)
    API_ENTRY(MultiByteToWideChar, 6) API_ENTRY(WideCharToMultiByte, 8)
    API_ENTRY(GetCommandLineA, 0)   API_ENTRY(GetCommandLineW, 0)
    // Environment
    API_ENTRY(GetEnvironmentVariableA, 3) API_ENTRY(SetEnvironmentVariableA, 2)
    API_ENTRY(GetCurrentDirectoryA, 2) API_ENTRY(SetCurrentDirectoryA, 1)
    API_ENTRY(ExpandEnvironmentStringsA, 3)
    // Toolhelp / Snapshot
    API_ENTRY(CreateToolhelp32Snapshot, 2)
    API_ENTRY(Process32FirstA, 2)   API_ENTRY(Process32NextA, 2)
    API_ENTRY(Thread32First, 2)     API_ENTRY(Thread32Next, 2)
    API_ENTRY(Module32FirstA, 2)    API_ENTRY(Module32NextA, 2)
    // Misc
    API_ENTRY(AllocConsole, 0)      API_ENTRY(FreeConsole, 0)
    API_ENTRY(GetConsoleMode, 2)    API_ENTRY(SetConsoleMode, 2)
    API_ENTRY(OutputDebugStringA, 1) API_ENTRY(GetACP, 0)
    API_ENTRY(DecodePointer, 1)     API_ENTRY(EncodePointer, 1)
    API_ENTRY(IsProcessorFeaturePresent, 1)
    API_LIST_END

public:
    Kernel32(void* emu);
    std::string get_name() const override { return "kernel32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
