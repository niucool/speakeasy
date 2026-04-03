use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;
use crate::winenv::defs::windows::netapi32::NERR_SUCCESS;

pub struct WkscliHandler;

impl WkscliHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WkscliHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WkscliHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "NetGetJoinInformation" => {
                let lp_server = args[0];
                let lp_name_buffer = args[1];
                let buffer_type = args[2];

                if lp_name_buffer != 0 {
                    let domain = "WORKGROUP";
                    let name_buf = domain.encode_utf16()
                        .chain(std::iter::once(0))
                        .flat_map(|c| c.to_le_bytes())
                        .collect::<Vec<u8>>();
                    emu.mem_write(lp_name_buffer, &name_buf)?;
                }

                if buffer_type != 0 {
                    let domain_status: u32 = 2;
                    emu.mem_write(buffer_type, &domain_status.to_le_bytes())?;
                }

                Ok(NERR_SUCCESS as u64)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Wkscli"
    }
}
