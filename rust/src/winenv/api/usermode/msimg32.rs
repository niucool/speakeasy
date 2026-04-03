use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Msimg32Handler;

impl Msimg32Handler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Msimg32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Msimg32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "TransparentBlt" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Msimg32"
    }
}
