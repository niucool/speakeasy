// Ntdll API implementations

use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct NtdllHandler;

impl NtdllHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NtdllHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NtdllHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "RtlGetLastWin32Error" => Ok(0),
            "RtlNtStatusToDosError" => Ok(0),
            "RtlFlushSecureMemoryCache" => Ok(0),
            "RtlAddVectoredExceptionHandler" => Ok(0x1000),
            "NtYieldExecution" => Ok(0),
            "RtlRemoveVectoredExceptionHandler" => Ok(0),
            "LdrLoadDll" => {
                let _path_ptr = args[0];
                let _flags_ptr = args[1];
                let _dll_name_ptr = args[2];
                let base_addr_ptr = args[3];
                emu.mem_write(base_addr_ptr, &(0x70000000u64).to_le_bytes())?;
                Ok(0)
            },
            "LdrGetProcedureAddress" => Ok(0),
            "RtlZeroMemory" => {
                let dest = args[0];
                let len = args[1] as usize;
                let buf = vec![0u8; len];
                emu.mem_write(dest, &buf)?;
                Ok(0)
            },
            "RtlMoveMemory" => {
                let dest = args[0];
                let src = args[1];
                let len = args[2] as usize;
                let buf = emu.mem_read(src, len)?;
                emu.mem_write(dest, &buf)?;
                Ok(0)
            },
            "NtSetInformationProcess" => Ok(0),
            "RtlEncodePointer" => Ok(args[0]),
            "RtlDecodePointer" => Ok(args[0]),
            "NtWaitForSingleObject" => Ok(0),
            "RtlComputeCrc32" => Ok(0),
            "LdrFindResource_U" => Ok(0),
            "NtUnmapViewOfSection" => Ok(0),
            "LdrAccessResource" => Ok(0),
            "RtlGetNtVersionNumbers" => {
                let major = args[0];
                let minor = args[1];
                let build = args[2];
                if major != 0 {
                    emu.mem_write(major, &10u32.to_le_bytes())?;
                }
                if minor != 0 {
                    emu.mem_write(minor, &0u32.to_le_bytes())?;
                }
                if build != 0 {
                    emu.mem_write(build, &19041u32.to_le_bytes())?;
                }
                Ok(())
            },
            "RtlGetCurrentPeb" => Ok(0x7FFDE000),
            "RtlGetVersion" => {
                let addr = args[0];
                let mut info = Vec::new();
                info.extend_from_slice(&(276u32).to_le_bytes());
                info.extend_from_slice(&(10u32).to_le_bytes());
                info.extend_from_slice(&(0u32).to_le_bytes());
                info.extend_from_slice(&(19041u32).to_le_bytes());
                info.extend_from_slice(&(2u32).to_le_bytes());
                info.resize(276, 0);
                emu.mem_write(addr, &info)?;
                Ok(0)
            },
            "NtAllocateVirtualMemory" => {
                let _proc_handle = args[0];
                let base_addr_ptr = args[1];
                let _zero_bits = args[2];
                let region_size_ptr = args[3];
                let _alloc_type = args[4];
                let _protect = args[5];

                let mut base_addr = u64::from_le_bytes(emu.mem_read(base_addr_ptr, 8)?.try_into().unwrap());
                let region_size = u64::from_le_bytes(emu.mem_read(region_size_ptr, 8)?.try_into().unwrap());

                if base_addr == 0 {
                    base_addr = 0x2000000;
                }

                emu.mem_write(base_addr_ptr, &base_addr.to_le_bytes())?;
                emu.mem_write(region_size_ptr, &region_size.to_le_bytes())?;

                Ok(0)
            },
            "NtWriteVirtualMemory" => {
                let _proc_handle = args[0];
                let base_addr = args[1];
                let buffer = args[2];
                let buffer_size = args[3] as usize;
                let num_bytes_written_ptr = args[4];

                let data = emu.mem_read(buffer, buffer_size)?;
                emu.mem_write(base_addr, &data)?;

                if num_bytes_written_ptr != 0 {
                    emu.mem_write(num_bytes_written_ptr, &(buffer_size as u64).to_le_bytes())?;
                }

                Ok(0)
            },
            "NtCreateFile" | "NtOpenFile" | "NtCreateSection" => {
                let handle_ptr = args[0];
                emu.mem_write(handle_ptr, &(0x100u64).to_le_bytes())?;
                Ok(0)
            },
            "NtClose" => Ok(0),
            "NtQueryInformationFile" => Ok(0),
            "NtSetInformationFile" => Ok(0),
            "NtQueryVolumeInformationFile" => Ok(0),
            "NtSetVolumeInformationFile" => Ok(0),
            "NtCreateProcess" => Ok(0),
            "NtCreateProcessEx" => Ok(0),
            "NtOpenProcess" => Ok(0),
            "NtTerminateProcess" => Ok(0),
            "NtQueryInformationProcess" => Ok(0),
            "NtSetInformationProcess" => Ok(0),
            "NtCreateThread" => Ok(0),
            "NtOpenThread" => Ok(0),
            "NtTerminateThread" => Ok(0),
            "NtGetContextThread" => Ok(0),
            "NtSetContextThread" => Ok(0),
            "NtSuspendThread" => Ok(0),
            "NtResumeThread" => Ok(0),
            "NtQuerySystemInformation" => Ok(0),
            "NtSetSystemInformation" => Ok(0),
            "NtQueryObject" => Ok(0),
            "NtSetObjectSecurity" => Ok(0),
            "NtCreateObjectAttributes" => Ok(0),
            "NtOpenDirectoryObject" => Ok(0),
            "NtCreateDirectoryObject" => Ok(0),
            "NtOpenSymbolicLinkObject" => Ok(0),
            "NtCreateSymbolicLinkObject" => Ok(0),
            "NtQuerySymbolicLinkObject" => Ok(0),
            "NtCreateKey" => Ok(0),
            "NtOpenKey" => Ok(0),
            "NtDeleteKey" => Ok(0),
            "NtSetValueKey" => Ok(0),
            "NtQueryValueKey" => Ok(0),
            "NtDeleteValueKey" => Ok(0),
            "NtEnumerateKey" => Ok(0),
            "NtEnumerateValueKey" => Ok(0),
            "NtFlushKey" => Ok(0),
            "NtLoadDriver" => Ok(0),
            "NtUnloadDriver" => Ok(0),
            "NtCreateEvent" => Ok(0),
            "NtOpenEvent" => Ok(0),
            "NtSetEvent" => Ok(0),
            "NtResetEvent" => Ok(0),
            "NtClearEvent" => Ok(0),
            "NtCreateMutant" => Ok(0),
            "NtOpenMutant" => Ok(0),
            "NtReleaseMutant" => Ok(0),
            "NtCreateSemaphore" => Ok(0),
            "NtOpenSemaphore" => Ok(0),
            "NtReleaseSemaphore" => Ok(0),
            "NtCreateTimer" => Ok(0),
            "NtOpenTimer" => Ok(0),
            "NtSetTimer" => Ok(0),
            "NtCancelTimer" => Ok(0),
            "NtQueryTimer" => Ok(0),
            "NtCreateIoCompletion" => Ok(0),
            "NtOpenIoCompletion" => Ok(0),
            "NtSetIoCompletion" => Ok(0),
            "NtRemoveIoCompletion" => Ok(0),
            "NtQueryInformationThread" => Ok(0),
            "NtSetInformationThread" => Ok(0),
            "NtQueryInformationJobObject" => Ok(0),
            "NtSetInformationJobObject" => Ok(0),
            "NtCreateJobObject" => Ok(0),
            "NtOpenJobObject" => Ok(0),
            "NtAssignProcessToJobObject" => Ok(0),
            "NtTerminateJobObject" => Ok(0),
            "NtQueryPerformanceCounter" => Ok(0),
            "NtQuerySystemTime" => Ok(0),
            "NtSetSystemTime" => Ok(0),
            "NtQueryInterruptTime" => Ok(0),
            "NtQueryInterruptTimePrecise" => Ok(0),
            "NtQueryTimerResolution" => Ok(0),
            "NtSetTimerResolution" => Ok(0),
            "NtCreateSection" => Ok(0),
            "NtOpenSection" => Ok(0),
            "NtMapViewOfSection" => Ok(0),
            "NtUnmapViewOfSection" => Ok(0),
            "NtExtendSection" => Ok(0),
            "NtQuerySection" => Ok(0),
            "NtProtectVirtualMemory" => Ok(0),
            "NtReadVirtualMemory" => Ok(0),
            "NtWriteVirtualMemory" => Ok(0),
            "NtFlushVirtualMemory" => Ok(0),
            "NtLockVirtualMemory" => Ok(0),
            "NtUnlockVirtualMemory" => Ok(0),
            "NtAllocateVirtualMemory" => Ok(0),
            "NtFreeVirtualMemory" => Ok(0),
            "NtQueryVirtualMemory" => Ok(0),
            "NtSetLdtEntries" => Ok(0),
            "NtQuerySystemInformationEx" => Ok(0),
            "RtlCopyUnicodeString" => Ok(0),
            "RtlCompareUnicodeString" => Ok(0),
            "RtlAppendUnicodeStringToString" => Ok(0),
            "RtlAppendUnicodeToString" => Ok(0),
            "RtlInitUnicodeString" => Ok(0),
            "RtlFreeUnicodeString" => Ok(0),
            "RtlAnsiStringToUnicodeString" => Ok(0),
            "RtlUnicodeStringToAnsiString" => Ok(0),
            "RtlDowncaseUnicodeString" => Ok(0),
            "RtlUpcaseUnicodeString" => Ok(0),
            "RtlEqualUnicodeString" => Ok(0),
            "RtlHashUnicodeString" => Ok(0),
            "RtlAllocateHeap" => Ok(0x200000),
            "RtlReAllocateHeap" => Ok(0x200000),
            "RtlFreeHeap" => Ok(0),
            "RtlSizeHeap" => Ok(0x1000),
            "RtlAllocateLocallyUniqueId" => Ok(0),
            "RtlAssert" => Ok(0),
            "RtlCaptureStackBackTrace" => Ok(0),
            "RtlCompareMemory" => Ok(0),
            "RtlCompareMemoryLong" => Ok(0),
            "RtlCopyMemory" => Ok(0),
            "RtlFillMemory" => Ok(0),
            "RtlFillMemoryLong" => Ok(0),
            "RtlGetCallersAddress" => Ok(0),
            "RtlGetCurrentThread" => Ok(0),
            "RtlInitializeCriticalSection" => Ok(0),
            "RtlInitializeCriticalSectionAndSpinCount" => Ok(0),
            "RtlDeleteCriticalSection" => Ok(0),
            "RtlEnterCriticalSection" => Ok(0),
            "RtlLeaveCriticalSection" => Ok(0),
            "RtlTryEnterCriticalSection" => Ok(1),
            "RtlInitString" => Ok(0),
            "RtlFreeAnsiString" => Ok(0),
            "RtlTimeToTimeFields" => Ok(0),
            "RtlTimeFieldsToTime" => Ok(0),
            "RtlValidSecurityDescriptor" => Ok(1),
            "RtlCreateSecurityDescriptor" => Ok(0),
            "RtlSetDaclSecurityDescriptor" => Ok(0),
            "RtlSetSaclSecurityDescriptor" => Ok(0),
            "RtlSetOwnerSecurityDescriptor" => Ok(0),
            "RtlGetDaclSecurityDescriptor" => Ok(0),
            "RtlGetSaclSecurityDescriptor" => Ok(0),
            "RtlGetOwnerSecurityDescriptor" => Ok(0),
            "RtlGetGroupSecurityDescriptor" => Ok(0),
            "RtlMakeSelfRelativeSD" => Ok(0),
            "RtlAbsoluteToSelfRelativeSD" => Ok(0),
            "RtlSelfRelativeToAbsoluteSD" => Ok(0),
            "RtlValidateSecurityDescriptor" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Ntdll"
    }
}
