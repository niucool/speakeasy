use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Comctl32Handler;

impl Comctl32Handler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Comctl32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Comctl32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "InitCommonControlsEx" => Ok(1),
            "InitCommonControls" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Comctl32"
    }
}
