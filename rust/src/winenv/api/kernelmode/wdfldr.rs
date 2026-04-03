use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct WdfldrHandler {
    version_major: u32,
    version_minor: u32,
}

impl WdfldrHandler {
    pub fn new() -> Self {
        Self {
            version_major: 1,
            version_minor: 33,
        }
    }

    fn get_version(&self) -> (u32, u32) {
        (self.version_major, self.version_minor)
    }
}

impl Default for WdfldrHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WdfldrHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "WdfVersionBind" => Ok(0),
            "WdfVersionUnbind" => Ok(1),
            "WdfDriverGetVersion" => {
                let (major, minor) = self.get_version();
                Ok(((major as u64) << 32) | minor as u64)
            }
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Wdfldr"
    }
}
