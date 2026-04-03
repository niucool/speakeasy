use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Msi32Handler;

impl Msi32Handler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Msi32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Msi32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "MsiDatabaseMergeA" | "MsiDatabaseMerge" => Ok(0),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Msi32"
    }
}
