// Ntoskrnl API implementations

use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::api::ApiHandler;

pub struct NtoskrnlHandler;

impl ApiHandler for NtoskrnlHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "ExAllocatePoolWithTag" | "ExAllocatePool" => {
                let _pool_type = args[0] as u32;
                let size = args[1] as usize;
                let _tag = if name == "ExAllocatePoolWithTag" {
                    args[2] as u32
                } else {
                    0
                };
                Ok(0xBAADF00D)
            }
            "ExFreePoolWithTag" | "ExFreePool" => Ok(0),
            "IoCreateDevice" => {
                let _driver_obj = args[0];
                let _ext_size = args[1];
                let _dev_name = args[2];
                let _dev_type = args[3];
                let _dev_chars = args[4];
                let _exclusive = args[5];
                let out_ptr = args[6];
                emu.mem_write(out_ptr, &(0xDEADC0DEu64).to_le_bytes())?;
                Ok(0) // STATUS_SUCCESS
            }
            "IoCreateSymbolicLink" => {
                let _sym_link = args[0];
                let _dev_name = args[1];
                Ok(0)
            }
            "MmIsAddressValid" => {
                let addr = args[0];
                if addr != 0 {
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
            "KeQuerySystemTime" => {
                let out_ptr = args[0];
                emu.mem_write(out_ptr, &(131911108955110000u64).to_le_bytes())?;
                Ok(0)
            }
            "PsCreateSystemThread" => {
                let h_thread_ptr = args[0];
                let _access = args[1];
                let _obj_attr = args[2];
                let _proc_h = args[3];
                let _client_id = args[4];
                let _start_routine = args[5];
                let _start_ctx = args[6];

                emu.mem_write(h_thread_ptr, &(0x200u64).to_le_bytes())?;
                Ok(0)
            }
            "KeInitializeEvent" => {
                let _event = args[0];
                let _etype = args[1];
                let _state = args[2];
                Ok(0)
            }
            "ObReferenceObjectByHandle" => {
                let _handle = args[0];
                let _access = args[1];
                let _obj_type = args[2];
                let _mode = args[3];
                let out_obj = args[4];
                let _granted_access = args[5];

                emu.mem_write(out_obj, &(0xDEADC0DEu64).to_le_bytes())?;
                Ok(0)
            }
            "PsGetCurrentProcess" => Ok(0xDEADC0DE),
            "PsGetCurrentThread" => Ok(0xDEADC0DF),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Ntoskrnl"
    }
}
