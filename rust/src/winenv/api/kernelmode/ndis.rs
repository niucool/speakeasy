use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct NdisHandler {
    next_handle: u64,
}

impl NdisHandler {
    pub fn new() -> Self {
        Self {
            next_handle: 0x7000,
        }
    }

    fn ndis_allocate_generic_object(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 0x20;
        handle
    }
}

impl Default for NdisHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NdisHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, _args: &[u64]) -> Result<u64> {
        match name {
            "NdisAllocateGenericObject" => Ok(self.ndis_allocate_generic_object()),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Ndis"
    }
}
