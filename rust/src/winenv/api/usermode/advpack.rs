use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct AdvpackHandler;

impl AdvpackHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AdvpackHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for AdvpackHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "IsNTAdmin" => {
                Ok(1)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Advpack"
    }
}
