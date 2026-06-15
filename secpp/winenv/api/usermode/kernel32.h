// kernel32.h  kernel32.dll API handler (v2  macro-based registration)
#ifndef SPEAKEASY_KERNEL32_H
#define SPEAKEASY_KERNEL32_H

// Prevent Windows macro pollution
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
#ifdef IsBadStringPtrA
#undef IsBadStringPtrA
#endif
#ifdef IsBadStringPtrW
#undef IsBadStringPtrW
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

#include <string>
#include <vector>
#include "../api.h"

namespace speakeasy { namespace api {

#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif

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
    API_ENTRY(LocalFree, 1)             API_ENTRY(RtlMoveMemory, 3)
        API_ENTRY(RtlZeroMemory, 2)
    // DLL / Module
    API_ENTRY(LoadLibraryA, 1)      API_ENTRY(LoadLibraryW, 1)
    API_ENTRY(LoadLibraryExA, 3)    API_ENTRY(LoadLibraryExW, 3)
    API_ENTRY(FreeLibrary, 1)
    API_ENTRY(GetProcAddress, 2)    API_ENTRY(GetModuleHandleA, 1)
    API_ENTRY(GetModuleHandleW, 1)  API_ENTRY(GetModuleFileNameA, 3)  API_ENTRY(GetModuleFileNameW, 3)
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
    API_ENTRY(CreateEventA, 4)      API_ENTRY(CreateMutexA, 3)      API_ENTRY(CreateMutexW, 3)
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
    API_ENTRY(GetEnvironmentVariableW, 3)  API_ENTRY(SetEnvironmentVariableW, 2)
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
    
    // Statically linked / dynamic-CRT-free missing APIs
    API_ENTRY(FlsAlloc, 1)     API_ENTRY(FlsFree, 1)
    API_ENTRY(FlsGetValue, 1)     API_ENTRY(FlsSetValue, 2)
    API_ENTRY(GetFileType, 1)     API_ENTRY(GetStdHandle, 1)
    API_ENTRY(GetSystemTimeAsFileTime, 1)     
    API_ENTRY(InterlockedCompareExchange, 3)
    API_ENTRY(InterlockedDecrement, 1)     
    API_ENTRY(InterlockedExchange, 2)
    API_ENTRY(InterlockedIncrement, 1)     
    API_ENTRY(InterlockedExchangeAdd, 2)
    API_ENTRY(TlsAlloc, 0)
    API_ENTRY(TlsFree, 1)     API_ENTRY(TlsGetValue, 1)
    API_ENTRY(TlsSetValue, 2)     API_ENTRY(AcquireSRWLockExclusive, 1)
    API_ENTRY(AcquireSRWLockShared, 1)     API_ENTRY(AddAtom, 1)
    API_ENTRY(AddVectoredContinueHandler, 2)     API_ENTRY(AddVectoredExceptionHandler, 2)
    API_ENTRY(AreFileApisANSI, 0)     API_ENTRY(CheckRemoteDebuggerPresent, 2)
    API_ENTRY(CompareFileTime, 2)     API_ENTRY(ConnectNamedPipe, 2)
    API_ENTRY(CreateIoCompletionPort, 4)     API_ENTRY(CreateMutexEx, 4)
    API_ENTRY(CreateNamedPipe, 8)     API_ENTRY(CreatePipe, 4)
    API_ENTRY(CreateProcessInternal, 12)     API_ENTRY(CreateSemaphoreW, 4)
    API_ENTRY(CreateWaitableTimerEx, 4)     API_ENTRY(CreateWaitableTimerExW, 4)
    API_ENTRY(DeleteAtom, 1)     API_ENTRY(DisconnectNamedPipe, 1)
    API_ENTRY(DuplicateHandle, 7)     API_ENTRY(EnumProcesses, 3)
    API_ENTRY(FindAtom, 1)     API_ENTRY(FindFirstFileEx, 6)
    API_ENTRY(FindFirstVolume, 2)     API_ENTRY(FindNextVolume, 3)
    API_ENTRY(FindResource, 3)     API_ENTRY(FindResourceEx, 4)
    API_ENTRY(FindVolumeClose, 1)     API_ENTRY(FlsGetValue2, 1)
    API_ENTRY(FreeEnvironmentStringsA, 1) API_ENTRY(FreeEnvironmentStringsW, 1)     API_ENTRY(FreeLibraryAndExitThread, 2)
    API_ENTRY(FreeResource, 1)     API_ENTRY(GetAtomName, 3)
    API_ENTRY(GetBinaryType, 2)     API_ENTRY(GetCPInfo, 2)
    API_ENTRY(GetCommProperties, 2)     API_ENTRY(GetCommTimeouts, 2)
    API_ENTRY(GetComputerNameEx, 3)     API_ENTRY(GetConsoleTitle, 2)
    API_ENTRY(GetConsoleWindow, 0)     API_ENTRY(GetCurrentPackageId, 2)
    API_ENTRY(GetDateFormat, 6)     API_ENTRY(GetEnvironmentStringsA, 0)  API_ENTRY(GetEnvironmentStringsW, 0)
    API_ENTRY(GetErrorMode, 0)     API_ENTRY(GetFileAttributesEx, 3)
    API_ENTRY(GetFileSizeEx, 2)     API_ENTRY(GetFullPathName, 4)
    API_ENTRY(GetHandleInformation, 2)     API_ENTRY(GetLocaleInfo, 4)
    API_ENTRY(GetLogicalDrives, 0)     API_ENTRY(GetLongPathName, 3)
    API_ENTRY(GetMailslotInfo, 5)     API_ENTRY(GetModuleFileNameExA, 4)
    API_ENTRY(GetModuleHandleEx, 3)     API_ENTRY(GetNativeSystemInfo, 1)
    API_ENTRY(GetOEMCP, 0)     API_ENTRY(GetPhysicallyInstalledSystemMemory, 1)
    API_ENTRY(GetProcessAffinityMask, 3)     API_ENTRY(GetProcessHandleCount, 1)
    API_ENTRY(GetProcessVersion, 1)     API_ENTRY(GetProfileInt, 3)
    API_ENTRY(GetShortPathName, 3)     API_ENTRY(GetStartupInfo, 1)
    API_ENTRY(GetStringTypeA, 5)     API_ENTRY(GetStringTypeW, 4)
    API_ENTRY(GetSystemDefaultLCID, 0)     API_ENTRY(GetSystemDefaultLangID, 0)
    API_ENTRY(GetSystemDefaultUILanguage, 0)     API_ENTRY(GetSystemDirectory, 2)
    API_ENTRY(GetSystemFirmwareTable, 4)     API_ENTRY(GetSystemTimePreciseAsFileTime, 1)
    API_ENTRY(GetSystemTimes, 3)     API_ENTRY(GetTempFileName, 4)
    API_ENTRY(GetTempPath, 2)     API_ENTRY(GetThreadContext, 2)
    API_ENTRY(GetThreadId, 1)     API_ENTRY(GetThreadLocale, 0)
    API_ENTRY(GetThreadTimes, 5)     API_ENTRY(GetThreadUILanguage, 0)
    API_ENTRY(GetTickCount64, 0)     API_ENTRY(GetTimeFormat, 6)
    API_ENTRY(GetTimeZoneInformation, 1)     API_ENTRY(GetUserDefaultLCID, 0)
    API_ENTRY(GetUserDefaultLangID, 0)     API_ENTRY(GetUserDefaultUILanguage, 0)
    API_ENTRY(GetVolumeInformation, 8)     API_ENTRY(GetVolumePathNamesForVolumeName, 4)
    API_ENTRY(GetWindowsDirectory, 2)     API_ENTRY(GlobalAddAtomA, 1)
    API_ENTRY(GlobalFlags, 1)     API_ENTRY(GlobalHandle, 1)
    API_ENTRY(GlobalLock, 1)     API_ENTRY(GlobalMemoryStatus, 1)
    API_ENTRY(GlobalMemoryStatusEx, 1)     API_ENTRY(GlobalSize, 1)
    API_ENTRY(GlobalUnlock, 1)     API_ENTRY(HeapReAlloc, 4)
    API_ENTRY(HeapSetInformation, 4)     API_ENTRY(HeapSize, 3)
    API_ENTRY(InitOnceBeginInitialize, 4)     API_ENTRY(InitializeConditionVariable, 1)
    API_ENTRY(InitializeCriticalSectionAndSpinCount, 2)     API_ENTRY(InitializeCriticalSectionEx, 3)
    API_ENTRY(InitializeSListHead, 1)     API_ENTRY(InitializeSRWLock, 1)
    API_ENTRY(IsBadReadPtr, 2)     API_ENTRY(IsBadStringPtrA, 2)    API_ENTRY(IsBadStringPtrW, 2)
    API_ENTRY(IsBadWritePtr, 2)     API_ENTRY(IsDBCSLeadByte, 1)
    API_ENTRY(IsValidCodePage, 1)     API_ENTRY(IsValidLocale, 2)
    API_ENTRY(IsWow64Process, 2)     API_ENTRY(LCMapString, 6)
    API_ENTRY(LCMapStringEx, 9)     API_ENTRY(LoadResource, 2)
    API_ENTRY(LocalLock, 1)     API_ENTRY(LocalReAlloc, 3)
    API_ENTRY(LockResource, 1)     API_ENTRY(MoveFile, 2)
    API_ENTRY(MulDiv, 3)     API_ENTRY(OpenEvent, 3)
    API_ENTRY(OpenWaitableTimer, 3)     API_ENTRY(PeekNamedPipe, 6)
    API_ENTRY(ProcessIdToSessionId, 2)     API_ENTRY(ReleaseSRWLockExclusive, 1)
    API_ENTRY(ReleaseSRWLockShared, 1)     API_ENTRY(RemoveVectoredExceptionHandler, 1)
    API_ENTRY(RtlCaptureContext, 1)     API_ENTRY(RtlLookupFunctionEntry, 3)
    API_ENTRY(RtlUnwind, 4)     API_ENTRY(SetConsoleCtrlHandler, 2)
    API_ENTRY(SetConsoleHistoryInfo, 1)     API_ENTRY(SetConsoleTitle, 1)
    API_ENTRY(SetDefaultDllDirectories, 1)     API_ENTRY(SetDllDirectory, 1)
    API_ENTRY(SetFilePointerEx, 4)     API_ENTRY(SetHandleCount, 1)
    API_ENTRY(SetHandleInformation, 3)     API_ENTRY(SetPriorityClass, 2)
    API_ENTRY(SetProcessPriorityBoost, 2)     API_ENTRY(SetThreadContext, 2)
    API_ENTRY(SetThreadDescription, 2)     API_ENTRY(SetThreadErrorMode, 2)
    API_ENTRY(SetThreadLocale, 1)     API_ENTRY(SetThreadStackGuarantee, 1)
    API_ENTRY(SizeofResource, 2)     API_ENTRY(SystemTimeToTzSpecificLocalTime, 3)
    API_ENTRY(VerSetConditionMask, 3)     API_ENTRY(VerifyVersionInfo, 3)
    API_ENTRY(VirtualAllocExNuma, 6)     API_ENTRY(WTSGetActiveConsoleSessionId, 0)
    API_ENTRY(WaitForSingleObjectEx, 3)     API_ENTRY(WakeAllConditionVariable, 1)
    API_ENTRY(WerGetFlags, 2)     API_ENTRY(WerSetFlags, 1)
    API_ENTRY(Wow64DisableWow64FsRedirection, 1)     API_ENTRY(Wow64RevertWow64FsRedirection, 1)
    API_ENTRY(_lclose, 1)     API_ENTRY(_llseek, 3)
    API_ENTRY(_lopen, 2)     API_ENTRY(lstrcmpi, 2)
    API_ENTRY(lstrcmpiA, 2)     API_ENTRY(lstrcmpiW, 2)
    API_ENTRY(lstrcpyn, 3)
    API_ENTRY(lstrcpynA, 3)     API_ENTRY(lstrcpynW, 3)
    //  W function stubs (delegate to A versions or return 1)
    API_ENTRY(DeleteFileW, 1)    API_ENTRY(CreateDirectoryW, 2)
    API_ENTRY(GetFileAttributesW, 1)  API_ENTRY(FindFirstFileW, 2)
    API_ENTRY(FindNextFileW, 2)  API_ENTRY(CreateFileMappingW, 6)
    API_ENTRY(GetDriveTypeW, 1)  API_ENTRY(GetDiskFreeSpaceExW, 4)
    API_ENTRY(CreateEventW, 4)   API_ENTRY(OpenMutexW, 3)
    API_ENTRY(CreateWaitableTimerW, 3)  API_ENTRY(GetVersionExW, 1)
    API_ENTRY(GetComputerNameW, 2)  API_ENTRY(GetUserNameW, 2)
    API_ENTRY(lstrlenW, 1)       API_ENTRY(lstrcpyW, 2)
    API_ENTRY(lstrcatW, 2)       API_ENTRY(lstrcmpW, 2)
    API_ENTRY(GetCurrentDirectoryW, 2)  API_ENTRY(ExpandEnvironmentStringsW, 3)
    API_ENTRY(Process32FirstW, 2)  API_ENTRY(Process32NextW, 2)
    API_ENTRY(Module32FirstW, 2)  API_ENTRY(Module32NextW, 2)
    API_ENTRY(OutputDebugStringW, 1)  API_ENTRY(CreateProcessW, 10)
    API_LIST_END

public:
    Kernel32(void* emu);
    std::string get_name() const override { return "kernel32"; }
    const std::vector<ApiEntry>& get_apis() const override { return apis_; }
};

}} // namespaces
#endif
