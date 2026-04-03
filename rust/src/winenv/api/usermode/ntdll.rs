// Ntdll API implementations

use crate::winenv::api::{ApiHandler, ApiContext};
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct NtdllHandler;

impl ApiHandler for NtdllHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "RtlGetLastWin32Error" => Ok(0),
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
            "RtlGetVersion" => {
                let addr = args[0];
                let mut info = Vec::new();
                info.extend_from_slice(&(276u32).to_le_bytes()); // dwOSVersionInfoSize
                info.extend_from_slice(&(10u32).to_le_bytes());  // dwMajorVersion
                info.extend_from_slice(&(0u32).to_le_bytes());   // dwMinorVersion
                info.extend_from_slice(&(19041u32).to_le_bytes()); // dwBuildNumber
                info.extend_from_slice(&(2u32).to_le_bytes());   // dwPlatformId
                info.resize(276, 0);
                emu.mem_write(addr, &info)?;
                Ok(0) // STATUS_SUCCESS
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
                    base_addr = 0x2000000; // Placeholder allocation
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
            "LdrLoadDll" => {
                let _path_ptr = args[0];
                let _flags_ptr = args[1];
                let _dll_name_ptr = args[2];
                let base_addr_ptr = args[3];

                emu.mem_write(base_addr_ptr, &(0x70000000u64).to_le_bytes())?;
                Ok(0)
            },
            "NtCreateFile" | "NtOpenFile" => {
                let handle_ptr = args[0];
                emu.mem_write(handle_ptr, &(0x100u64).to_le_bytes())?;
                Ok(0)
            },
            "NtClose" => Ok(0),
            _ => Ok(0),
        }
    }
}
