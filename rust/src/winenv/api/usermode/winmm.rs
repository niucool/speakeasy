use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct WinmmHandler;

impl WinmmHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WinmmHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WinmmHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "timeBeginPeriod" => Ok(0),
            "timeEndPeriod" => Ok(0),
            "timeGetTime" => {
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u32;
                Ok(ms as u64)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Winmm"
    }
}
