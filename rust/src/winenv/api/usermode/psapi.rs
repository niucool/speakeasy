use crate::winenv::api::ApiHandler;

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
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.enum_processes().len() as u64,
            1 => self.enum_process_modules(args[0] as u32).len() as u64,
            2 => self.get_module_information(args[1]).1 as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Psapi"
    }
}
