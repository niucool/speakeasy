// Ntoskrnl API implementations - Windows Kernel

use crate::binemu::BinaryEmulator;
use crate::winenv::api::ApiHandler;
use crate::errors::Result;

pub struct NtoskrnlHandler {
    next_handle: u32,
    current_irql: u8,
}

impl NtoskrnlHandler {
    pub fn new() -> Self {
        Self {
            next_handle: 0x4000,
            current_irql: 0, // PASSIVE_LEVEL
        }
    }

    pub fn get_current_irql(&self) -> u8 {
        self.current_irql
    }

    pub fn set_current_irql(&mut self, irql: u8) {
        self.current_irql = irql;
    }

    pub fn get_handle(&mut self) -> u32 {
        self.next_handle += 4;
        self.next_handle
    }

    fn win_perms_to_emu_perms(&self, win_perms: u32) -> u32 {
        let mut new = 0;
        if win_perms & 0x40 != 0 != 0 { // PAGE_EXECUTE_READWRITE
            new |= 7; // PERM_MEM_RWX
        } else if win_perms & 0x01 != 0 { // PAGE_NOACCESS
            new |= 0; // PERM_MEM_NONE
        } else {
            if win_perms & 0x20 != 0 || win_perms & 0x10 != 0 { // PAGE_EXECUTE or PAGE_EXECUTE_READ
                new |= 1; // PERM_MEM_EXEC
            }
            if win_perms & 0x10 != 0 || win_perms & 0x02 != 0 || win_perms & 0x04 != 0 {
                new |= 2; // PERM_MEM_READ
            }
            if win_perms & 0x04 != 0 {
                new |= 4; // PERM_MEM_WRITE
            }
        }
        new
    }

    fn read_string(&self, emu: &mut dyn BinaryEmulator, addr: u64) -> String {
        if let Ok(data) = emu.mem_read(addr, 256) {
            String::from_utf8_lossy(&data).trim_end_matches('\0').to_string()
        } else {
            String::new()
        }
    }

    fn read_wide_string(&self, emu: &mut dyn BinaryEmulator, addr: u64) -> String {
        if let Ok(data) = emu.mem_read(addr, 512) {
            let mut result = String::new();
            for chunk in data.chunks(2) {
                if chunk.len() == 2 {
                    let c = u16::from_le_bytes([chunk[0], chunk[1]]);
                    if c == 0 {
                        break;
                    }
                    if let Some(ch) = char::from_u32(c as u32) {
                        result.push(ch);
                    }
                }
            }
            result
        } else {
            String::new()
        }
    }

    fn read_ansi_string(&self, emu: &mut dyn BinaryEmulator, addr: u64) -> String {
        self.read_string(emu, addr)
    }

    fn read_unicode_string(&self, emu: &mut dyn BinaryEmulator, addr: u64) -> String {
        self.read_wide_string(emu, addr)
    }
}

impl Default for NtoskrnlHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NtoskrnlHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            // Pool allocation
            "ExAllocatePoolWithTag" | "ExAllocatePool" => {
                let _pool_type = args[0] as u32;
                let size = args[1] as usize;
                let _tag = if name == "ExAllocatePoolWithTag" { args[2] as u32 } else { 0 };
                Ok(0xBAADF00D)
            },
            "ExFreePoolWithTag" | "ExFreePool" => {
                Ok(0)
            },

            // Memory management
            "MmIsAddressValid" => {
                let addr = args[0];
                Ok(1) // Assume valid
            },
            "MmProbeAndLockPages" => Ok(0),
            "MmUnlockPages" => Ok(0),
            "MmMapLockedPagesSpecifyCache" => Ok(0x200000),
            "MmGetSystemRoutineAddress" => Ok(0),
            "MmIsDriverVerifying" => Ok(0),

            // I/O
            "IoCreateDevice" => {
                let out_ptr = args[6];
                emu.mem_write(out_ptr, &(0xDEADC0DEu64).to_le_bytes())?;
                Ok(0) // STATUS_SUCCESS
            },
            "IoCreateDeviceSecure" => Ok(0),
            "IoDeleteDevice" => Ok(0),
            "IoCreateSymbolicLink" => Ok(0),
            "IoDeleteSymbolicLink" => Ok(0),
            "IoAllocateIrp" => Ok(0x15000),
            "IoFreeIrp" => Ok(0),
            "IoReuseIrp" => Ok(0),
            "IoAllocateMdl" => Ok(0x16000),
            "IoFreeMdl" => Ok(0),
            "IoDeleteDriver" => Ok(0),
            "IofCompleteRequest" => Ok(0),
            "IofCallDriver" => Ok(0),
            "IoSetCompletionRoutineEx" => Ok(0),
            "IoWMIRegistrationControl" => Ok(0),
            "IoRegisterShutdownNotification" => Ok(0),
            "IoUnregisterShutdownNotification" => Ok(0),
            "IoGetCurrentProcess" => Ok(0x50000),
            "IoGetDeviceObjectPointer" => Ok(0),
            "IoCreateSynchronizationEvent" => {
                let handle = self.get_handle();
                Ok(handle as u64)
            },

            // Events
            "KeInitializeEvent" => Ok(0),
            "KeResetEvent" => Ok(0),
            "KeClearEvent" => Ok(0),
            "KeSetEvent" => Ok(0),
            "KeInitializeTimer" => Ok(0),
            "KeSetTimer" => Ok(1),
            "KeCancelTimer" => Ok(1),

            // IRQL
            "KeQuerySystemTime" => {
                let time_ptr = args[0];
                let time = 0x100000u64;
                emu.mem_write(time_ptr, &time.to_le_bytes())?;
                Ok(0)
            },
            "KeDelayExecutionThread" => Ok(0),
            "KeWaitForSingleObject" => Ok(0),
            "KeEnterCriticalRegion" => Ok(0),
            "KeAcquireSpinLockRaiseToDpc" => {
                let irql = self.get_current_irql();
                self.set_current_irql(2); // DISPATCH_LEVEL
                Ok(irql as u64)
            },

            // DPC
            "KeInitializeDpc" => Ok(0),
            "KeInitializeApc" => Ok(0),
            "KeInsertQueueApc" => Ok(1),

            // Threads/Processes
            "PsCreateSystemThread" => {
                let thread_handle = args[0];
                let handle = self.get_handle();
                if thread_handle != 0 {
                    emu.mem_write(thread_handle, &handle.to_le_bytes())?;
                }
                Ok(0)
            },
            "PsGetCurrentProcess" => Ok(0x50000),
            "PsGetCurrentThread" => Ok(0x60000),
            "PsGetProcessPeb" => Ok(0x7FFD0000),
            "PsLookupProcessByProcessId" => {
                let proc_id = args[0];
                let out_ptr = args[1];
                if proc_id == 4 {
                    emu.mem_write(out_ptr, &0x50000u64.to_le_bytes())?;
                    Ok(0) // STATUS_SUCCESS
                } else {
                    Ok(0xC000000Du64) // STATUS_INVALID_CID
                }
            },
            "PsLookupThreadByThreadId" => Ok(0),
            "PsTerminateSystemThread" => Ok(0),
            "KeStackAttachProcess" => Ok(0),
            "KeUnstackDetachProcess" => Ok(0),
            "ZwGetContextThread" => Ok(1),
            "ZwSetContextThread" => Ok(1),
            "NtSetInformationThread" => Ok(0),

            // Object management
            "ObOpenObjectByPointer" => Ok(0),
            "ObReferenceObjectByName" => Ok(0),
            "ObReferenceObject" => Ok(0),
            "ObfReferenceObject" => Ok(0),
            "ObfDereferenceObject" => Ok(0),
            "ObMakeTemporaryObject" => Ok(0),
            "ObSetSecurityObjectByPointer" => Ok(0),
            "ObGetFilterVersion" => Ok(256),
            "ObRegisterCallbacks" => Ok(0),
            "ObOpenObjectByHandle" => {
                let handle = args[0];
                let out_ptr = args[4];
                if handle != 0 {
                    emu.mem_write(out_ptr, &0x80000u64.to_le_bytes())?;
                    Ok(0)
                } else {
                    Ok(0xC0000008u64) // STATUS_INVALID_HANDLE
                }
            },

            // ZwClose
            "ZwClose" => Ok(0),
            "NtClose" => Ok(0),

            // Debug
            "DbgPrint" => Ok(0),
            "DbgPrintEx" => Ok(0),
            "KdDisableDebugger" => Ok(0xC0000346u64), // STATUS_DEBUGGER_INACTIVE
            "KdChangeOption" => Ok(0xC0000346u64),

            // String functions
            "RtlInitAnsiString" => Ok(0),
            "RtlInitUnicodeString" => Ok(0),
            "RtlFreeUnicodeString" => Ok(0),
            "RtlAnsiStringToUnicodeString" => Ok(0),
            "RtlCopyUnicodeString" => Ok(0),
            "RtlEqualUnicodeString" => {
                let str1 = args[0];
                let str2 = args[1];
                let case_insensitive = args[2];
                
                let s1 = self.read_unicode_string(emu, str1);
                let s2 = self.read_unicode_string(emu, str2);
                
                let equal = if case_insensitive != 0 {
                    s1.to_lowercase() == s2.to_lowercase()
                } else {
                    s1 == s2
                };
                Ok(if equal { 1 } else { 0 })
            },
            "wcslen" => {
                let string = args[0];
                let ws = self.read_wide_string(emu, string);
                Ok(ws.len() as u64)
            },
            "wcscpy" => Ok(args[0]),
            "wcsncpy" => Ok(args[0]),
            "wcscat" => Ok(args[0]),
            "wcschr" => Ok(args[0]),
            "wcsnlen" => {
                let src = args[0];
                let _num = args[1];
                let ws = self.read_wide_string(emu, src);
                Ok(ws.len() as u64)
            },
            "wcscmp" | "_wcsicmp" => {
                let s1 = self.read_wide_string(emu, args[0]);
                let s2 = self.read_wide_string(emu, args[1]);
                Ok(if s1 == s2 { 0 } else { 1 })
            },
            "wcsicmp" => {
                let s1 = self.read_wide_string(emu, args[0]);
                let s2 = self.read_wide_string(emu, args[1]);
                Ok(if s1.to_lowercase() == s2.to_lowercase() { 0 } else { 1 })
            },
            "_wcsnicmp" => {
                let s1 = self.read_wide_string(emu, args[0]);
                let s2 = self.read_wide_string(emu, args[1]);
                let count = args[2] as usize;
                let (s1_part, s2_part) = if s1.len() > count {
                    (&s1[..count], &s2[..count])
                } else {
                    (s1.as_str(), s2.as_str())
                };
                Ok(if s1_part.to_lowercase() == s2_part.to_lowercase() { 0 } else { 1 })
            },
            "strchr" => Ok(args[0]),
            "strrchr" => Ok(args[0]),
            "_stricmp" | "strcmp" => {
                let s1 = self.read_string(emu, args[0]);
                let s2 = self.read_string(emu, args[1]);
                Ok(if s1.to_lowercase() == s2.to_lowercase() { 0 } else { 1 })
            },
            "_snprintf" | "sprintf" | "vsprintf_s" => Ok(0),
            "_vsnprintf" => Ok(0),
            "_snwprintf" => Ok(0),

            // Memory functions
            "memcpy" | "RtlMoveMemory" | "memmove" => {
                let dest = args[0];
                let src = args[1];
                let count = args[2] as usize;
                if let Ok(data) = emu.mem_read(src, count) {
                    let _ = emu.mem_write(dest, &data);
                }
                Ok(dest)
            },
            "memset" => {
                let dest = args[0];
                let _c = args[1];
                let count = args[2] as usize;
                if count > 0 {
                    let _ = emu.mem_write(dest, &vec![0; count]);
                }
                Ok(dest)
            },
            "RtlCompareMemory" => {
                let s1 = args[0];
                let s2 = args[1];
                let length = args[2] as usize;
                let mut i = 0;
                if let (Ok(data1), Ok(data2)) = (emu.mem_read(s1, length), emu.mem_read(s2, length)) {
                    while i < length && i < data1.len() && i < data2.len() {
                        if data1[i] != data2[i] {
                            break;
                        }
                        i += 1;
                    }
                }
                Ok(i as u64)
            },

            // Heap functions
            "RtlAllocateHeap" => Ok(0x180000),
            "RtlFreeHeap" => Ok(1),

            // Registry
            "ZwOpenKey" => Ok(0),
            "ZwCreateKey" => Ok(0),
            "ZwDeleteKey" => Ok(0),
            "ZwQueryValueKey" => Ok(0),
            "ZwSetValueKey" => Ok(0),
            "RtlQueryRegistryValuesEx" => Ok(0),

            // File I/O
            "ZwCreateFile" => {
                let handle = args[0];
                let h = self.get_handle() as u64;
                if handle != 0 {
                    emu.mem_write(handle, &h.to_le_bytes())?;
                }
                Ok(0)
            },
            "ZwOpenFile" => {
                let handle = args[0];
                let h = self.get_handle() as u64;
                if handle != 0 {
                    emu.mem_write(handle, &h.to_le_bytes())?;
                }
                Ok(0)
            },
            "ZwReadFile" => Ok(0),
            "ZwWriteFile" => Ok(0),
            "ZwQueryInformationFile" => Ok(0),
            "ZwDeviceIoControlFile" => Ok(0),

            // Virtual memory
            "ZwAllocateVirtualMemory" => {
                let base_addr = args[1];
                let size = if args[3] != 0 {
                    if let Ok(data) = emu.mem_read(args[3], 8) {
                        u64::from_le_bytes(data.try_into().unwrap_or(0))
                    } else { 0 }
                } else { 0 };
                let addr = 0x200000;
                if base_addr != 0 {
                    let _ = emu.mem_write(base_addr, &addr.to_le_bytes());
                }
                Ok(0)
            },
            "ZwProtectVirtualMemory" => Ok(0),
            "ZwWriteVirtualMemory" => Ok(0),

            // Sections
            "ZwCreateSection" => {
                let handle = args[0];
                let h = self.get_handle() as u64;
                if handle != 0 {
                    emu.mem_write(handle, &h.to_le_bytes())?;
                }
                Ok(0)
            },
            "ZwMapViewOfSection" => Ok(0),
            "ZwUnmapViewOfSection" => Ok(0),

            // System info
            "ZwQuerySystemInformation" => Ok(0),
            "RtlGetVersion" => Ok(0),
            "PsGetVersion" => Ok(0),

            // Compression
            "RtlGetCompressionWorkSpaceSize" => {
                if args[1] != 0 {
                    let _ = emu.mem_write(args[1], &0x1000u32.to_le_bytes());
                }
                if args[2] != 0 {
                    let _ = emu.mem_write(args[2], &0x1000u32.to_le_bytes());
                }
                Ok(0)
            },
            "RtlDecompressBuffer" => Ok(0),

            // Security
            "RtlLengthRequiredSid" => {
                let count = args[0] as u32;
                Ok((count * 16) as u64)
            },
            "RtlInitializeSid" => Ok(0),
            "RtlSubAuthoritySid" => Ok(args[0]),
            "RtlCreateAcl" => Ok(0),
            "RtlSetDaclSecurityDescriptor" => Ok(0),
            "RtlCreateSecurityDescriptor" => Ok(0),
            "RtlAddAccessAllowedAce" => Ok(0),

            // Resources
            "ExInitializeResourceLite" => Ok(0),
            "ExAcquireResourceExclusiveLite" => Ok(1),
            "ExAcquireResourceSharedLite" => Ok(1),
            "ExReleaseResourceLite" => Ok(0),
            "ExAcquireFastMutex" => Ok(0),
            "ExReleaseFastMutex" => Ok(0),

            // Process/Thread notify
            "PsSetCreateProcessNotifyRoutineEx" => Ok(0),
            "PsSetLoadImageNotifyRoutine" => Ok(0),
            "PsRemoveLoadImageNotifyRoutine" => Ok(0),
            "PsSetCreateThreadNotifyRoutine" => Ok(0),
            "PsRemoveCreateThreadNotifyRoutine" => Ok(0),

            // Work items
            "ExQueueWorkItem" => Ok(0),

            // ETW
            "EtwRegister" => Ok(0),
            "CmRegisterCallback" => Ok(0),
            "CmRegisterCallbackEx" => Ok(0),
            "CmUnRegisterCallback" => Ok(0),

            // Power
            "PoDeletePowerRequest" => Ok(0),

            // Other
            "_allshl" => {
                let a = args[0];
                let b = args[1] as u32;
                Ok(0xFFFFFFFFFFFFFFFF & a << b)
            },
            "RtlTimeToTimeFields" => Ok(0),
            "ExSystemTimeToLocalTime" => {
                let sys_time = args[0];
                let local_time = args[1];
                if let Ok(data) = emu.mem_read(sys_time, 8) {
                    let _ = emu.mem_write(local_time, &data);
                }
                Ok(0)
            },
            "FsRtlAllocatePool" => Ok(0x180000),
            "IoRegisterBootDriverReinitialization" => Ok(0),
            "RtlImageDirectoryEntryToData" => Ok(0),

            // Events (Zw*)
            "ZwOpenEvent" => Ok(0),
            "ZwCreateEvent" => {
                let handle = args[0];
                let h = self.get_handle() as u64;
                if handle != 0 {
                    emu.mem_write(handle, &h.to_le_bytes())?;
                }
                Ok(0)
            },
            "ZwQueryInformationProcess" => Ok(0xC0000003u64), // STATUS_OBJECT_TYPE_MISMATCH
            "mbstowcs" => {
                let wcstr = args[0];
                let mbstr = args[1];
                let mb = self.read_string(emu, mbstr);
                let wide = mb.encode("utf-16le");
                if wcstr != 0 {
                    let _ = emu.mem_write(wcstr, &wide);
                }
                Ok(mb.len() as u64)
            },
            
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Ntoskrnl"
    }
}
