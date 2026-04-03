use crate::binemu::BinaryEmulator;
use crate::winenv::api::{ApiHandler, Result};

pub struct NetioHandler {
    compartment_id: u32,
}

impl NetioHandler {
    pub fn new() -> Self {
        Self { compartment_id: 1 }
    }

    fn get_default_compartment_id(&self) -> u32 {
        self.compartment_id
    }
}

impl Default for NetioHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NetioHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "NpGetDefaultCompartmentId" => Ok(self.get_default_compartment_id() as u64),
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Netio"
    }
}
