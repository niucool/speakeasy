use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Lz32Handler;

impl Lz32Handler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Lz32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Lz32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "LZSeek" => Ok(0xFFFFFFFF),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Lz32"
    }
}
