// Kernel32 API implementations

use crate::winenv::api::{ApiHandler, ApiContext};
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Kernel32Handler {
    pub last_error: u32,
}

impl Kernel32Handler {
    pub fn new() -> Self {
        Self { last_error: 0 }
    }
}

impl ApiHandler for Kernel32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "GetLastError" => Ok(self.last_error as u64),
            "SetLastError" => {
                self.last_error = args[0] as u32;
                Ok(0)
            },
            "GetProcessHeap" => Ok(0x1000),
            "VirtualAlloc" | "VirtualAllocEx" => {
                let _h_proc = if name == "VirtualAllocEx" { args[0] } else { 0 };
                let addr = if name == "VirtualAllocEx" { args[1] } else { args[0] };
                let size = if name == "VirtualAllocEx" { args[2] } else { args[1] };
                let _alloc_type = if name == "VirtualAllocEx" { args[3] } else { args[2] };
                let _prot = if name == "VirtualAllocEx" { args[4] } else { args[3] };
                
                let base = if addr == 0 { 0x2000000 } else { addr };
                Ok(base) 
            },
            "GetModuleHandleA" | "GetModuleHandleW" => {
                let lp_name = args[0];
                if lp_name == 0 {
                    Ok(0x400000) // Main module
                } else {
                    Ok(0x70000000) // DLL
                }
            },
            "GetProcAddress" => {
                let _h_mod = args[0];
                let _lp_name = args[1];
                Ok(0x7FFFFFFF) // Placeholder for dynamic API address
            },
            "LoadLibraryA" | "LoadLibraryW" => {
                Ok(0x70000000)
            },
            "CreateFileA" | "CreateFileW" => {
                Ok(0x100) // Dummy handle
            },
            "ReadFile" => {
                let _h_file = args[0];
                let lp_buf = args[1];
                let num_to_read = args[2] as usize;
                let lp_num_read = args[3];
                
                let data = vec![0u8; num_to_read];
                emu.mem_write(lp_buf, &data)?;
                if lp_num_read != 0 {
                    emu.mem_write(lp_num_read, &(num_to_read as u32).to_le_bytes())?;
                }
                Ok(1) // TRUE
            },
            "WriteFile" => {
                let _h_file = args[0];
                let lp_buf = args[1];
                let num_to_write = args[2] as usize;
                let lp_num_written = args[3];
                
                let data = emu.mem_read(lp_buf, num_to_write)?;
                if lp_num_written != 0 {
                    emu.mem_write(lp_num_written, &(num_to_write as u32).to_le_bytes())?;
                }
                Ok(1) // TRUE
            },
            "CloseHandle" => Ok(1),
            "ExitProcess" => {
                emu.set_pc(0xDEADBEEF)?; // Trigger exit
                Ok(0)
            },
            "GetSystemTime" | "GetLocalTime" => {
                let lp_time = args[0];
                let mut time = Vec::new();
                time.extend_from_slice(&(2026u16).to_le_bytes()); // wYear
                time.extend_from_slice(&(4u16).to_le_bytes());    // wMonth
                time.extend_from_slice(&(2u16).to_le_bytes());    // wDayOfWeek
                time.extend_from_slice(&(2u16).to_le_bytes());    // wDay
                time.extend_from_slice(&(12u16).to_le_bytes());   // wHour
                time.extend_from_slice(&(0u16).to_le_bytes());    // wMinute
                time.extend_from_slice(&(0u16).to_le_bytes());    // wSecond
                time.extend_from_slice(&(0u16).to_le_bytes());    // wMilliseconds
                emu.mem_write(lp_time, &time)?;
                Ok(0)
            },
            _ => Ok(0),
        }
    }
}
