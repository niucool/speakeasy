use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct MscoreeHandler;

impl MscoreeHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MscoreeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for MscoreeHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "CorExitProcess" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Mscoree"
    }
}
