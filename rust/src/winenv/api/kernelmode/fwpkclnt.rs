use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct FwpkclntHandler {
    next_id: u64,
}

impl FwpkclntHandler {
    pub fn new() -> Self {
        Self { next_id: 0x6000 }
    }

    fn fwpm_engine_open(&mut self) -> u64 {
        let handle = self.next_id;
        self.next_id += 4;
        handle
    }
}

impl Default for FwpkclntHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for FwpkclntHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "FwpmEngineOpen" => Ok(self.fwpm_engine_open()),
            "FwpmEngineClose" => Ok(0),
            "FwpmFilterAdd" => Ok(self.next_id),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Fwpkclnt"
    }
}
