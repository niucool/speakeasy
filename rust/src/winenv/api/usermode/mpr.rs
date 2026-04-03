use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub const ERROR_NO_NETWORK: u32 = 1202;

pub struct MprHandler;

impl MprHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MprHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for MprHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "WNetOpenEnum" => Ok(ERROR_NO_NETWORK as u64),
            "WNetEnumResource" | "WNetEnumResourceA" | "WNetEnumResourceW" => Ok(ERROR_NO_NETWORK as u64),
            "WNetAddConnection2" | "WNetAddConnection2W" => Ok(ERROR_NO_NETWORK as u64),
            "WNetGetConnection" | "WNetGetConnectionA" | "WNetGetConnectionW" => Ok(ERROR_NO_NETWORK as u64),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Mpr"
    }
}
