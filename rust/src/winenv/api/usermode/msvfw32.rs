use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Msvfw32Handler {
    next_handle: u32,
}

impl Msvfw32Handler {
    pub fn new() -> Self {
        Self {
            next_handle: 0x7000,
        }
    }
}

impl Default for Msvfw32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Msvfw32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "ICOpen" => {
                let handle = self.next_handle;
                self.next_handle += 4;
                Ok(handle)
            },
            "ICSendMessage" => Ok(1),
            "ICClose" => Ok(1),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Msvfw32"
    }
}
