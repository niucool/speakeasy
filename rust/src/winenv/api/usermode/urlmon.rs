use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct UrlmonHandler;

impl ApiHandler for UrlmonHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Urlmon"
    }
}
