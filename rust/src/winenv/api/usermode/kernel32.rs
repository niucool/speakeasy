use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Kernel32Handler {
    last_error: u32,
    heaps: Vec<u64>,
    curr_handle: u32,
    tick_counter: u32,
    local_atom_table: std::collections::HashMap<u32, (String, u32)>,
    curr_local_atom: u32,
}

impl Kernel32Handler {
    pub fn new() -> Self {
        Self {
            last_error: 0,
            heaps: Vec::new(),
            curr_handle: 0x1800,
            tick_counter: 0,
            local_atom_table: std::collections::HashMap::new(),
            curr_local_atom: 0xC000,
        }
    }

    fn get_handle(&mut self) -> u32 {
        self.curr_handle += 4;
        self.curr_handle
    }

    fn add_local_atom(&mut self, s: &str) -> u32 {
        for (atom, (value, _cnt)) in &self.local_atom_table {
            if value.to_lowercase() == s.to_lowercase() {
                return *atom;
            }
        }
        self.curr_local_atom += 1;
        let atom = self.curr_local_atom - 1;
        self.local_atom_table.insert(atom, (s.to_string(), 1));
        atom
    }

    fn get_local_atom_name(&self, atom: u32) -> Option<String> {
        self.local_atom_table.get(&atom).map(|(s, _)| s.clone())
    }
}

impl Default for Kernel32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Kernel32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "GetThreadLocale" => Ok(0xC000),
            "SetThreadLocale" => Ok(args[0]),
            "IsValidLocale" => Ok(1),
            "GetThreadTimes" => {
                let lp_creation_time = args[1];
                if lp_creation_time != 0 {
                    emu.mem_write(lp_creation_time, &[0x20, 0x20, 0, 0])?;
                }
                Ok(1)
            },
            "GetProcessHeap" => {
                if self.heaps.is_empty() {
                    self.heaps.push(0x1000);
                }
                Ok(self.heaps[0])
            },
            "GetProcessVersion" => {
                Ok(0x00060001)
            },
            "DisableThreadLibraryCalls" => Ok(1),
            "CreateMutex" | "CreateMutexA" | "CreateMutexW" => {
                Ok(self.get_handle() as u64)
            },
            "LoadLibraryA" | "LoadLibraryW" | "LoadLibraryExA" | "LoadLibraryExW" => {
                Ok(0x70000000)
            },
            "CreateToolhelp32Snapshot" => {
                Ok(self.get_handle() as u64)
            },
            "Process32First" | "Process32Next" => Ok(0),
            "Module32First" | "Module32Next" => Ok(0),
            "Thread32First" | "Thread32Next" => Ok(0),
            "OpenProcess" => Ok(self.get_handle() as u64),
            "OpenMutexA" | "OpenMutexW" => Ok(self.get_handle() as u64),
            "TerminateProcess" => Ok(1),
            "FreeLibraryAndExitThread" => Ok(0),
            "ExitThread" => Ok(0),
            "WinExec" => Ok(32),
            "VirtualAlloc" | "VirtualAllocEx" => {
                let addr = if name == "VirtualAllocEx" { args[1] } else { args[0] };
                let base = if addr == 0 { 0x2000000 } else { addr };
                Ok(base)
            },
            "WriteProcessMemory" => Ok(1),
            "ReadProcessMemory" => Ok(1),
            "CreateRemoteThread" => Ok(self.get_handle() as u64),
            "CreateThread" => Ok(self.get_handle() as u64),
            "ResumeThread" => Ok(0),
            "SuspendThread" => Ok(0),
            "TerminateThread" => Ok(1),
            "GetThreadId" => Ok(0x1000),
            "VirtualQuery" => Ok(0x30),
            "VirtualProtect" | "VirtualProtectEx" => Ok(1),
            "VirtualFree" => Ok(1),
            "GetCurrentProcess" => Ok(0xFFFFFFFF),
            "GetCurrentProcessId" => Ok(4),
            "GetCurrentThreadId" => Ok(8),
            "GetCurrentThread" => Ok(0xFFFFFFFE),
            "GetVersion" => Ok(0x80020004),
            "GetLastError" => Ok(self.last_error as u64),
            "SetLastError" => {
                self.last_error = args[0] as u32;
                Ok(0)
            },
            "SetHandleInformation" => Ok(1),
            "GetHandleInformation" => Ok(1),
            "ExitProcess" => {
                Ok(0)
            },
            "GetSystemTimeAsFileTime" => {
                let lp_time = args[0];
                if lp_time != 0 {
                    emu.mem_write(lp_time, &[0, 0, 0, 0, 0, 0, 0, 0])?;
                }
                Ok(0)
            },
            "GetLocalTime" | "GetSystemTime" => {
                let lp_time = args[0];
                let mut time = Vec::new();
                time.extend_from_slice(&(2026u16).to_le_bytes());
                time.extend_from_slice(&(4u16).to_le_bytes());
                time.extend_from_slice(&(2u16).to_le_bytes());
                time.extend_from_slice(&(2u16).to_le_bytes());
                time.extend_from_slice(&(12u16).to_le_bytes());
                time.extend_from_slice(&(0u16).to_le_bytes());
                time.extend_from_slice(&(0u16).to_le_bytes());
                time.extend_from_slice(&(0u16).to_le_bytes());
                emu.mem_write(lp_time, &time)?;
                Ok(0)
            },
            "GetTimeZoneInformation" => Ok(1),
            "IsProcessorFeaturePresent" => Ok(1),
            "lstrcmpA" | "lstrcmpW" | "lstrcmpiA" | "lstrcmpiW" => Ok(0),
            "lstrlenA" | "lstrlenW" => {
                let addr = args[0];
                if addr == 0 {
                    Ok(0)
                } else {
                    let data = emu.mem_read(addr, 256)?;
                    let len = data.iter().position(|&b| b == 0).unwrap_or(256);
                    Ok(len as u64)
                }
            },
            "lstrcpyA" | "lstrcpyW" | "lstrcatA" | "lstrcatW" => Ok(args[0]),
            "lstrcpynA" | "lstrcpynW" => Ok(args[0]),
            "QueryPerformanceCounter" => {
                Ok(0x5FD27D571F)
            },
            "GetTickCount" => {
                self.tick_counter = self.tick_counter.wrapping_add(100);
                Ok(self.tick_counter as u64)
            },
            "GetTickCount64" => Ok(0xDBF0u64),
            "GetModuleHandleA" | "GetModuleHandleW" | "GetModuleHandleExA" | "GetModuleHandleExW" => {
                let lp_name = args[0];
                if lp_name == 0 {
                    Ok(0x400000)
                } else {
                    Ok(0x70000000)
                }
            },
            "GetProcAddress" => Ok(0x7FFFFFFF),
            "AllocConsole" => Ok(1),
            "GetConsoleWindow" => Ok(0),
            "Sleep" | "SleepEx" => Ok(0),
            "GlobalAlloc" => Ok(0x2000),
            "GlobalSize" => Ok(8),
            "GlobalFlags" => Ok(0),
            "LocalAlloc" => Ok(0x2000),
            "HeapAlloc" => {
                let _heap = args[0];
                let _flags = args[1];
                let _size = args[2];
                Ok(0x200000)
            },
            "HeapSize" => Ok(0x1000),
            "IsBadReadPtr" => Ok(0),
            "HeapReAlloc" => Ok(0x200000),
            "LocalReAlloc" => Ok(0x2000),
            "HeapCreate" => Ok(0x1000),
            "TlsAlloc" => Ok(0x10),
            "TlsSetValue" => Ok(1),
            "TlsGetValue" => Ok(0),
            "FlsAlloc" => Ok(0x10),
            "FlsSetValue" => Ok(1),
            "FlsGetValue" => Ok(0),
            "EncodePointer" | "DecodePointer" => Ok(args[0]),
            "InitializeCriticalSectionAndSpinCount" => Ok(1),
            "EnterCriticalSection" => Ok(0),
            "LeaveCriticalSection" => Ok(0),
            "InitializeSListHead" => Ok(0),
            "CreateFileA" | "CreateFileW" | "CreateFileExA" | "CreateFileExW" => {
                Ok(self.get_handle() as u64)
            },
            "ReadFile" | "ReadFileEx" => {
                let _h_file = args[0];
                let lp_buf = args[1];
                let num_to_read = args[2] as usize;
                let lp_num_read = args[3];
                
                let data = vec![0u8; num_to_read];
                emu.mem_write(lp_buf, &data)?;
                if lp_num_read != 0 {
                    emu.mem_write(lp_num_read, &(num_to_read as u32).to_le_bytes())?;
                }
                Ok(1)
            },
            "WriteFile" | "WriteFileEx" => {
                let _h_file = args[0];
                let lp_buf = args[1];
                let num_to_write = args[2] as usize;
                let lp_num_written = args[3];
                
                let _data = emu.mem_read(lp_buf, num_to_write)?;
                if lp_num_written != 0 {
                    emu.mem_write(lp_num_written, &(num_to_write as u32).to_le_bytes())?;
                }
                Ok(1)
            },
            "CloseHandle" => Ok(1),
            "FlushFileBuffers" => Ok(1),
            "SetFilePointer" => Ok(0),
            "SetFilePointerEx" => Ok(1),
            "GetFileSize" => Ok(0x1000),
            "GetFileSizeEx" => Ok(1),
            "GetFileAttributesA" | "GetFileAttributesW" => {
                let _lp_file_name = args[0];
                Ok(0x80)
            },
            "SetFileAttributesA" | "SetFileAttributesW" => Ok(1),
            "GetFileTime" => Ok(1),
            "SetFileTime" => Ok(1),
            "DeleteFileA" | "DeleteFileW" => Ok(1),
            "MoveFileA" | "MoveFileW" | "MoveFileExA" | "MoveFileExW" => Ok(1),
            "CopyFileA" | "CopyFileW" | "CopyFileExA" | "CopyFileExW" => Ok(1),
            "CreateDirectoryA" | "CreateDirectoryW" => Ok(1),
            "RemoveDirectoryA" | "RemoveDirectoryW" => Ok(1),
            "GetCurrentDirectoryA" | "GetCurrentDirectoryW" => {
                let n_buffer_length = args[0];
                if n_buffer_length > 0 {
                    let path = b"C:\\\0";
                    emu.mem_write(args[1], path)?;
                }
                Ok(3)
            },
            "SetCurrentDirectoryA" | "SetCurrentDirectoryW" => Ok(1),
            "GetTempPathA" | "GetTempPathW" => {
                let _n_buffer_length = args[0];
                let _lp_buffer = args[1];
                Ok(4)
            },
            "GetTempFileNameA" | "GetTempFileNameW" => Ok(1),
            "GetFullPathNameA" | "GetFullPathNameW" => Ok(1),
            "GetLongPathNameA" | "GetLongPathNameW" => Ok(1),
            "GetShortPathNameA" | "GetShortPathNameW" => Ok(1),
            "FindFirstFileA" | "FindFirstFileW" => {
                Ok(self.get_handle() as u64)
            },
            "FindNextFileA" | "FindNextFileW" => Ok(0),
            "FindClose" => Ok(1),
            "GetLastWriteTime" => Ok(1),
            "GetFileType" => Ok(1),
            "GetStdHandle" => Ok(0xFFFFFFF6),
            "SetStdHandle" => Ok(1),
            "CreatePipe" => Ok(1),
            "ConnectNamedPipe" => Ok(0),
            "DisconnectNamedPipe" => Ok(1),
            "SetNamedPipeHandleState" => Ok(1),
            "PeekNamedPipe" => Ok(1),
            "TransactNamedPipe" => Ok(0),
            "WaitNamedPipeA" | "WaitNamedPipeW" => Ok(1),
            "CallNamedPipeA" | "CallNamedPipeW" => Ok(1),
            "AddLocalAtomA" | "AddLocalAtomW" => {
                let lp_string = args[0];
                if lp_string != 0 {
                    let data = emu.mem_read(lp_string, 256)?;
                    let s = String::from_utf8_lossy(&data);
                    if let Some(pos) = s.find('\0') {
                        let atom = self.add_local_atom(&s[..pos]);
                        return Ok(atom as u64);
                    }
                }
                Ok(0)
            },
            "FindLocalAtomA" | "FindLocalAtomW" => Ok(0),
            "DeleteLocalAtom" => Ok(1),
            "GlobalAddAtomA" | "GlobalAddAtomW" => {
                Ok(self.add_local_atom("test") as u64)
            },
            "GlobalFindAtomA" | "GlobalFindAtomW" => Ok(0),
            "GlobalDeleteAtom" => Ok(0),
            "GetCommandLineA" | "GetCommandLineW" => Ok(0x1000),
            "GetEnvironmentVariableA" | "GetEnvironmentVariableW" => Ok(0),
            "SetEnvironmentVariableA" | "SetEnvironmentVariableW" => Ok(1),
            "ExpandEnvironmentStringsA" | "ExpandEnvironmentStringsW" => Ok(0),
            "SetEnvironmentStringsA" | "SetEnvironmentStringsW" => Ok(1),
            "FormatMessageA" | "FormatMessageW" => Ok(0),
            "CreateMailslotA" | "CreateMailslotW" => Ok(self.get_handle() as u64),
            "GetMailslotInfo" => Ok(1),
            "SetMailslotInfo" => Ok(1),
            "LocalCreate" => Ok(0x2000),
            "LocalSize" => Ok(0x100),
            "LocalHandle" => Ok(0x2000),
            "LocalFree" => Ok(0),
            "GlobalHandle" => Ok(0x2000),
            "GlobalLock" => Ok(1),
            "GlobalUnlock" => Ok(1),
            "GlobalFree" => Ok(0),
            "MulDiv" => Ok(10),
            "GetModuleFileNameA" | "GetModuleFileNameW" => {
                let _h_module = args[0];
                let lp_filename = args[1];
                let n_size = args[2] as usize;
                let name = b"C:\\\\test.exe\0";
                let write_len = name.len().min(n_size);
                emu.mem_write(lp_filename, &name[..write_len])?;
                Ok(write_len as u64)
            },
            "GetStartupInfoA" | "GetStartupInfoW" => Ok(0),
            "GetProcessWindowStation" => Ok(0x1000),
            "GetThreadDesktop" => Ok(0x1000),
            "GetDesktopWindow" => Ok(0x10000),
            "GetShellWindow" => Ok(0x10000),
            "GetWindowThreadProcessId" => Ok(4),
            "IsWindow" => Ok(0),
            "IsChild" => Ok(0),
            "GetParent" => Ok(0),
            "SetParent" => Ok(0),
            "SetWindowPos" => Ok(1),
            "MoveWindow" => Ok(1),
            "SetWindowTextA" | "SetWindowTextW" => Ok(1),
            "GetWindowTextA" | "GetWindowTextW" => Ok(0),
            "GetWindowTextLengthA" | "GetWindowTextLengthW" => Ok(0),
            "MessageBoxA" | "MessageBoxW" => Ok(2),
            "MessageBoxExA" | "MessageBoxExW" => Ok(2),
            "MessageBoxIndirectA" | "MessageBoxIndirectW" => Ok(2),
            "FindResourceA" | "FindResourceW" => Ok(0),
            "FindResourceExA" | "FindResourceExW" => Ok(0),
            "LoadResource" => Ok(0),
            "LockResource" => Ok(0),
            "FreeResource" => Ok(0),
            "SizeofResource" => Ok(0x1000),
            "BeginUpdateResourceA" | "BeginUpdateResourceW" => {
                Ok(self.get_handle() as u64)
            },
            "UpdateResourceA" | "UpdateResourceW" => Ok(1),
            "EndUpdateResourceA" | "EndUpdateResourceW" => Ok(1),
            "GetPrivateProfileIntA" | "GetPrivateProfileIntW" => Ok(0),
            "WritePrivateProfileStringA" | "WritePrivateProfileStringW" => Ok(1),
            "GetPrivateProfileStringA" | "GetPrivateProfileStringW" => Ok(0),
            "WriteProfileStringA" | "WriteProfileStringW" => Ok(1),
            "GetProfileStringA" | "GetProfileStringW" => Ok(0),
            "GetProfileIntA" | "GetProfileIntW" => Ok(0),
            "GetACP" => Ok(1252),
            "GetOEMCP" => Ok(437),
            "GetCPInfo" => Ok(1),
            "IsValidCodePage" => Ok(1),
            "GetSystemDefaultLCID" => Ok(0x409),
            "GetUserDefaultLCID" => Ok(0x409),
            "GetLocaleInfoA" | "GetLocaleInfoW" => Ok(0),
            "SetLocaleInfoA" | "SetLocaleInfoW" => Ok(1),
            "GetStringTypeA" | "GetStringTypeW" => Ok(1),
            "GetStringTypeExA" | "GetStringTypeExW" => Ok(1),
            "LCMapStringA" | "LCMapStringW" => Ok(0),
            "FoldStringA" | "FoldStringW" => Ok(0),
            "FindNLSString" => Ok(-1),
            "CompareStringA" | "CompareStringW" => Ok(2),
            "GetUserDefaultUILanguage" => Ok(0x409),
            "GetSystemDefaultUILanguage" => Ok(0x409),
            "GetFileMUIInfo" => Ok(0),
            "GetSystemPreferredUILanguages" => Ok(1),
            "GetThreadPreferredUILanguages" => Ok(1),
            "GetUserPreferredUILanguages" => Ok(1),
            "GetProcessPreferredUILanguages" => Ok(1),
            "SetThreadPreferredUILanguages" => Ok(1),
            "SetProcessPreferredUILanguages" => Ok(1),
            "GetNLSVersion" => Ok(1),
            "IsNLSDefinedString" => Ok(1),
            "CompareStringOrdinal" => Ok(2),
            "NormalizeString" => Ok(0),
            "IsNormalizedString" => Ok(1),
            "GetLongPathNameEx" => Ok(0),
            "GetFinalPathNameByHandleA" | "GetFinalPathNameByHandleW" => Ok(0),
            "SetFileCompletionNotificationModes" => Ok(1),
            "SetFileInformationByHandle" => Ok(1),
            "GetVolumeInformationA" | "GetVolumeInformationW" => Ok(1),
            "GetVolumeInformationByHandleA" | "GetVolumeInformationByHandleW" => Ok(1),
            "SetVolumeLabelA" | "SetVolumeLabelW" => Ok(1),
            "SetVolumeMountPointA" | "SetVolumeMountPointW" => Ok(1),
            "DeleteVolumeMountPointA" | "DeleteVolumeMountPointW" => Ok(1),
            "GetDriveTypeA" | "GetDriveTypeW" => Ok(3),
            "GetDriveTypeExA" | "GetDriveTypeExW" => Ok(3),
            "GetLogicalDrives" => Ok(0xFF),
            "GetLogicalDriveStringsA" | "GetLogicalDriveStringsW" => Ok(0),
            "GetDiskFreeSpaceA" | "GetDiskFreeSpaceW" => Ok(1),
            "GetDiskFreeSpaceExA" | "GetDiskFreeSpaceExW" => Ok(1),
            "GetDriveBusType" => Ok(0),
            "GetFileAttributesExA" | "GetFileAttributesExW" => Ok(1),
            "GetNamedSecurityInfoA" | "GetNamedSecurityInfoW" => Ok(0),
            "SetNamedSecurityInfoA" | "SetNamedSecurityInfoW" => Ok(0),
            "GetSecurityInfo" => Ok(0),
            "SetSecurityInfo" => Ok(0),
            "GetSecurityDescriptorLength" => Ok(0x100),
            "BuildSecurityDescriptor" => Ok(0),
            "MakeAbsoluteSD" => Ok(0),
            "GetFileSecurityA" | "GetFileSecurityW" => Ok(0),
            "SetFileSecurityA" | "SetFileSecurityW" => Ok(0),
            "OpenProcessToken" => Ok(1),
            "GetTokenInformation" => Ok(1),
            "SetTokenInformation" => Ok(1),
            "DuplicateToken" => Ok(1),
            "DuplicateTokenEx" => Ok(1),
            "CreateRestrictedToken" => Ok(1),
            "GetTokenPrimaryGroup" => Ok(1),
            "SetTokenPrimaryGroup" => Ok(1),
            "GetTokenDefaultDacl" => Ok(1),
            "SetTokenDefaultDacl" => Ok(1),
            "GetTokenUser" => Ok(1),
            "SetTokenUser" => Ok(1),
            "GetTokenGroups" => Ok(1),
            "SetTokenGroups" => Ok(1),
            "GetTokenPrivileges" => Ok(1),
            "SetTokenPrivileges" => Ok(1),
            "GetTokenStatistics" => Ok(1),
            "GetTokenAuditPolicy" => Ok(1),
            "SetTokenAuditPolicy" => Ok(1),
            "CreateProcessAsUserA" | "CreateProcessAsUserW" => Ok(1),
            "CreateProcessAsUserW" => Ok(1),
            "ImpersonateLoggedOnUser" => Ok(1),
            "RevertToSelf" => Ok(1),
            "ImpersonateSelf" => Ok(1),
            "CheckTokenMembership" => Ok(1),
            "CreateWellKnownSid" => Ok(1),
            "IsWellKnownSid" => Ok(1),
            "LookupAccountNameA" | "LookupAccountNameW" => Ok(1),
            "LookupAccountSidA" | "LookupAccountSidW" => Ok(1),
            "LookupPrivilegeValueA" | "LookupPrivilegeValueW" => Ok(1),
            "LookupPrivilegeNameA" | "LookupPrivilegeNameW" => Ok(1),
            "LookupPrivilegeDisplayNameA" | "LookupPrivilegeDisplayNameW" => Ok(1),
            "CreatePrivateObjectSecurity" => Ok(1),
            "DestroyPrivateObjectSecurity" => Ok(0),
            "GetPrivateObjectSecurity" => Ok(1),
            "SetPrivateObjectSecurity" => Ok(1),
            "SetKernelObjectSecurity" => Ok(1),
            "GetKernelObjectSecurity" => Ok(1),
            "CreateFileMappingA" | "CreateFileMappingW" | "CreateFileMappingExA" | "CreateFileMappingExW" => {
                Ok(self.get_handle() as u64)
            },
            "OpenFileMappingA" | "OpenFileMappingW" => Ok(self.get_handle() as u64),
            "MapViewOfFile" => Ok(0x10000),
            "MapViewOfFileEx" => Ok(0x10000),
            "UnmapViewOfFile" => Ok(1),
            "FlushViewOfFile" => Ok(1),
            "VirtualLock" => Ok(1),
            "VirtualUnlock" => Ok(1),
            "AllocateUserPhysicalPages" => Ok(0),
            "AllocateUserPhysicalPagesNuma" => Ok(0),
            "GetPhysicalPages" => Ok(0),
            "GetLargePageMinimum" => Ok(0x200000),
            "GetProcessAffinityMask" => Ok(1),
            "SetProcessAffinityMask" => Ok(1),
            "GetProcessAffinityMask" => Ok(1),
            "SetThreadAffinityMask" => Ok(1),
            "GetThreadAffinityMask" => Ok(1),
            "SetProcessPriorityBoost" => Ok(1),
            "GetProcessPriorityBoost" => Ok(0),
            "SetThreadPriorityBoost" => Ok(1),
            "GetThreadPriorityBoost" => Ok(0),
            "GetThreadPriority" => Ok(0),
            "SetThreadPriority" => Ok(1),
            "GetProcessPriority" => Ok(8),
            "SetProcessPriority" => Ok(1),
            "GetThreadContext" => Ok(1),
            "SetThreadContext" => Ok(1),
            "SwitchToThread" => Ok(0),
            "FlushInstructionCache" => Ok(1),
            "FlushProcessWriteBuffers" => Ok(0),
            "GetProcessorSystemCycleTime" => Ok(0),
            "GetThreadCycleTime" => Ok(0),
            "GetProcessCycleTime" => Ok(0),
            "QueryProcessCycleTime" => Ok(0),
            "QueryThreadCycleTime" => Ok(0),
            "GetTimeZoneInformation" => Ok(1),
            "SetTimeZoneInformation" => Ok(1),
            "SystemTimeToTzSpecificLocalTime" => Ok(1),
            "TzSpecificLocalTimeToSystemTime" => Ok(1),
            "FileTimeToSystemTime" => Ok(1),
            "SystemTimeToFileTime" => Ok(1),
            "FileTimeToLocalFileTime" => Ok(1),
            "LocalFileTimeToFileTime" => Ok(1),
            "CompareFileTime" => Ok(0),
            "SetThreadErrorMode" => Ok(1),
            "GetThreadErrorMode" => Ok(0),
            "SetDefaultDllDirectories" => Ok(1),
            "AddDllDirectory" => Ok(0),
            "RemoveDllDirectory" => Ok(1),
            "SetDllDirectoryA" | "SetDllDirectoryW" => Ok(1),
            "GetDllDirectory" => Ok(0),
            "GetSystemWow64DirectoryA" | "GetSystemWow64DirectoryW" => Ok(0),
            "IsWow64Process" => Ok(0),
            "IsWow64Process2" => Ok(1),
            "GetNativeSystemInfo" => Ok(0),
            "GetSystemInfo" => Ok(0),
            "GetSystemInfoExA" | "GetSystemInfoExW" => Ok(0),
            "GetProductInfo" => Ok(1),
            "GetOsDeploymentState" => Ok(1),
            "VerifyVersionInfoA" | "VerifyVersionInfoW" => Ok(1),
            "VerSetConditionMask" => Ok(1),
            "GetComputerNameA" | "GetComputerNameW" => Ok(1),
            "SetComputerNameA" | "SetComputerNameW" => Ok(1),
            "GetComputerNameExA" | "GetComputerNameExW" => Ok(1),
            "SetComputerNameExA" | "SetComputerNameExW" => Ok(1),
            "GetUserNameA" | "GetUserNameW" => Ok(1),
            "GetEnvironmentVariableA" | "GetEnvironmentVariableW" => Ok(0),
            "SetEnvironmentVariableA" | "SetEnvironmentVariableW" => Ok(1),
            "ExpandEnvironmentStringsA" | "ExpandEnvironmentStringsW" => Ok(0),
            "SetEnvironmentStringsA" | "SetEnvironmentStringsW" => Ok(1),
            "GetFirmwareEnvironmentVariableA" | "GetFirmwareEnvironmentVariableW" => Ok(0),
            "SetFirmwareEnvironmentVariableA" | "SetFirmwareEnvironmentVariableW" => Ok(0),
            "GetFirmwareType" => Ok(1),
            "GetSystemFirmwareTable" => Ok(0),
            "SetSystemFirmwareTable" => Ok(0),
            "GetErrorMode" => Ok(0),
            "SetErrorMode" => Ok(0),
            "AddVectoredExceptionHandler" => Ok(0),
            "RemoveVectoredExceptionHandler" => Ok(0),
            "RtlAddVectoredExceptionHandler" => Ok(0),
            "RtlRemoveVectoredExceptionHandler" => Ok(0),
            "CreateWaitableTimerA" | "CreateWaitableTimerW" => {
                Ok(self.get_handle() as u64)
            },
            "CreateWaitableTimerExA" | "CreateWaitableTimerExW" => Ok(self.get_handle() as u64),
            "OpenWaitableTimerA" | "OpenWaitableTimerW" => Ok(self.get_handle() as u64),
            "SetWaitableTimer" => Ok(1),
            "CancelWaitableTimer" => Ok(1),
            "CreateIoCompletionPort" | "CreateIoCompletionPort" => Ok(0x1000),
            "GetQueuedCompletionStatus" => Ok(0),
            "PostQueuedCompletionStatus" => Ok(1),
            "BindIoCompletionCallback" => Ok(1),
            "CreateMemoryResourceNotification" => Ok(0),
            "QueryMemoryResourceNotification" => Ok(0),
            "IsProcessInJob" => Ok(0),
            "CreateJobObjectA" | "CreateJobObjectW" => Ok(self.get_handle() as u64),
            "OpenJobObjectA" | "OpenJobObjectW" => Ok(self.get_handle() as u64),
            "AssignProcessToJobObject" => Ok(1),
            "TerminateJobObject" => Ok(1),
            "QueryInformationJobObject" => Ok(1),
            "SetInformationJobObject" => Ok(1),
            "CreateTimerQueue" => Ok(0x1000),
            "CreateTimerQueueTimer" => Ok(1),
            "ChangeTimerQueueTimer" => Ok(1),
            "DeleteTimerQueueTimer" => Ok(1),
            "DeleteTimerQueue" => Ok(1),
            "WaitForSingleObject" => Ok(0),
            "WaitForMultipleObjects" => Ok(0),
            "WaitForMultipleObjectsEx" => Ok(0),
            "WaitForSingleObjectEx" => Ok(0),
            "RegisterWaitForSingleObject" => Ok(1),
            "UnregisterWaitEx" => Ok(1),
            "QueueUserWorkItem" => Ok(1),
            "CreateThreadpoolWork" => Ok(0x1000),
            "SubmitThreadpoolWork" => Ok(()),
            "WaitForThreadpoolWorkCallbacks" => Ok(()),
            "CloseThreadpoolWork" => Ok(()),
            "CreateThreadpool" => Ok(0x1000),
            "SetThreadpoolThreadMaximum" => Ok(()),
            "SetThreadpoolThreadMinimum" => Ok(1),
            "SetThreadpoolPoolMinimumThreads" => Ok(1),
            "SetThreadpoolPoolMaximumThreads" => Ok(1),
            "WaitForThreadpoolPoolCallbacks" => Ok(()),
            "CloseThreadpool" => Ok(()),
            "CallbackMayRunLong" => Ok(0),
            "TrySubmitThreadpoolCallback" => Ok(0),
            "DisassociateCurrentThreadFromCallback" => Ok(()),
            "IsThreadpoolTimerSet" => Ok(0),
            "CreateThreadpoolTimer" => Ok(0x1000),
            "SetThreadpoolTimer" => Ok(()),
            "WaitForThreadpoolTimerCallbacks" => Ok(()),
            "CloseThreadpoolTimer" => Ok(()),
            "CreateThreadpoolWait" => Ok(0x1000),
            "SetThreadpoolWait" => Ok(()),
            "WaitForThreadpoolWaitCallbacks" => Ok(()),
            "CloseThreadpoolWait" => Ok(()),
            "CreateThreadpoolCleanupGroup" => Ok(0x1000),
            "CloseThreadpoolCleanupGroup" => Ok(()),
            "SetThreadpoolCallbackCleanupGroup" => Ok(()),
            "LeaveCriticalSectionWhenCallbackReturns" => Ok(()),
            "DeleteCriticalSectionWhenCallbackReturns" => Ok(()),
            "LeaveCriticalSectionWhenCallbackReturns" => Ok(()),
            "ActivateActCtx" => Ok(1),
            "DeactivateActCtx" => Ok(1),
            "GetCurrentActCtx" => Ok(0x1000),
            "AddRefActCtx" => Ok(()),
            "ReleaseActCtx" => Ok(()),
            "CreateActCtxA" | "CreateActCtxW" => Ok(0x1000),
            "ActivateActCtx" => Ok(1),
            "DeactivateActCtx" => Ok(1),
            "GetCurrentProcessTransaction" => Ok(0),
            "CreateTransaction" => Ok(self.get_handle() as u64),
            "OpenTransaction" => Ok(self.get_handle() as u64),
            "CommitTransaction" => Ok(1),
            "RollbackTransaction" => Ok(1),
            "GetTransactionId" => Ok(0),
            "CloneFileA" | "CloneFileW" => Ok(0),
            "SfcGetNextProtectedFile" => Ok(0),
            "SfcIsFileProtected" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Kernel32"
    }
}
