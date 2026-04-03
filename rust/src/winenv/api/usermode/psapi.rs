use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct PsapiHandler;

impl PsapiHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn enum_processes(&self) -> Vec<u32> {
        vec![4, 888, 1337]
    }

    pub fn enum_process_modules(&self, _process: u32) -> Vec<u64> {
        vec![0x400000, 0x70000000]
    }

    pub fn get_module_base_name(&self, module: u64) -> String {
        match module {
            0x400000 => "sample.exe".to_string(),
            0x70000000 => "ntdll.dll".to_string(),
            _ => "unknown.dll".to_string(),
        }
    }

    pub fn get_module_information(&self, module: u64) -> (u64, u32, u64) {
        (module, 0x1000, module + 0x100)
    }
}

impl Default for PsapiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for PsapiHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "EnumProcesses" => {
                let lpid_process = args[0];
                let cb = args[1] as usize;
                let lpcb_needed = args[2];

                let processes = self.enum_processes();

                if lpcb_needed != 0 {
                    let needed = (processes.len() * 4) as u32;
                    emu.mem_write(lpcb_needed, &needed.to_le_bytes())?;
                }

                if lpid_process == 0 || cb < 4 {
                    return Ok(1);
                }

                let count = (cb / 4).min(processes.len());
                let mut cursor = lpid_process;
                for process in processes.iter().take(count) {
                    emu.mem_write(cursor, &process.to_le_bytes())?;
                    cursor += 4;
                }

                Ok(1)
            },
            "EnumProcessModules" => {
                let _h_process = args[0];
                let lph_module = args[1];
                let cb = args[2] as usize;
                let lpcb_needed = args[3];

                let modules = self.enum_process_modules(0);

                if lpcb_needed != 0 {
                    let needed = (modules.len() * 8) as u32;
                    emu.mem_write(lpcb_needed, &needed.to_le_bytes())?;
                }

                if lph_module == 0 || cb < 8 {
                    return Ok(1);
                }

                let count = (cb / 8).min(modules.len());
                let mut cursor = lph_module;
                for module in modules.iter().take(count) {
                    emu.mem_write(cursor, &module.to_le_bytes())?;
                    cursor += 8;
                }

                Ok(1)
            },
            "GetModuleBaseName" | "GetModuleBaseNameA" | "GetModuleBaseNameW" => {
                let _h_process = args[0];
                let h_module = args[1];
                let lp_base_name = args[2];
                let n_size = args[3] as usize;

                if lp_base_name == 0 || n_size == 0 {
                    return Ok(0);
                }

                let module_name = self.get_module_base_name(h_module);
                let truncated = if module_name.len() > n_size - 1 {
                    &module_name[..n_size - 1]
                } else {
                    &module_name
                };

                let output = format!("{}\0", truncated);
                emu.mem_write(lp_base_name, output.as_bytes())?;

                Ok(truncated.len() as u64)
            },
            "GetModuleFileNameEx" | "GetModuleFileNameExA" | "GetModuleFileNameExW" => {
                let _h_process = args[0];
                let h_module = args[1];
                let lp_filename = args[2];
                let n_size = args[3] as usize;

                if lp_filename == 0 || n_size == 0 {
                    return Ok(0);
                }

                let module_name = self.get_module_base_name(h_module);
                let truncated = if module_name.len() > n_size - 1 {
                    &module_name[..n_size - 1]
                } else {
                    &module_name
                };

                let output = format!("{}\0", truncated);
                emu.mem_write(lp_filename, output.as_bytes())?;

                Ok(truncated.len() as u64)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Psapi"
    }
}
