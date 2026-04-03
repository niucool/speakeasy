use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct Gdi32Handler {
    next_dc: u32,
}

impl Gdi32Handler {
    pub fn new() -> Self {
        Self { next_dc: 0x5000 }
    }

    fn create_compatible_dc(&mut self) -> u32 {
        let dc = self.next_dc;
        self.next_dc += 4;
        dc
    }

    fn delete_dc(&self, dc: u32) -> bool {
        dc != 0
    }

    fn get_device_caps(&self, _dc: u32, index: i32) -> i32 {
        match index {
            8 => 800,
            10 => 600,
            12 => 32,
            _ => 1,
        }
    }
}

impl Default for Gdi32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Gdi32Handler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "CreateCompatibleDC" => Ok(self.create_compatible_dc() as u64),
            "DeleteDC" => Ok(u64::from(self.delete_dc(args[0] as u32))),
            "GetDeviceCaps" => Ok(self.get_device_caps(args[0] as u32, args[1] as i32) as u64),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Gdi32"
    }
}
