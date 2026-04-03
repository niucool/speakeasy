use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::defs::windows::com::S_OK;

pub struct ComApiHandler;

impl ComApiHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ComApiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for ComApiHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "IUnknown.QueryInterface" => Ok(S_OK as u64),
            "IUnknown.AddRef" => Ok(1),
            "IUnknown.Release" => Ok(0),
            "IWbemLocator.ConnectServer" => Ok(S_OK as u64),
            "IWbemServices.ExecQuery" => Ok(0xFFFFFFFFFFFFFFFFu64 as i64 as u64),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "ComApi"
    }
}
