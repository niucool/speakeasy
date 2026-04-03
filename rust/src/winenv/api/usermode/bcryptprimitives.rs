use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct BcryptprimitivesHandler;

impl BcryptprimitivesHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BcryptprimitivesHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for BcryptprimitivesHandler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "ProcessPrng" => {
                let pb_data = args[0];
                let cb_data = args[1] as usize;

                let mut rand_bytes = vec![0u8; cb_data];
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                std::time::SystemTime::now().timestamp().hash(&mut hasher);
                let hash = hasher.finish();
                for i in 0..cb_data {
                    rand_bytes[i] = ((hash >> (i % 8)) & 0xFF) as u8;
                }

                emu.mem_write(pb_data, &rand_bytes)?;
                Ok(1)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Bcryptprimitives"
    }
}
