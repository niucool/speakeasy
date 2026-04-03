use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct Wtsapi32Handler;

impl ApiHandler for Wtsapi32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Wtsapi32"
    }
}
