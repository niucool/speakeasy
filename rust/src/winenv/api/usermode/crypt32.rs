use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct Crypt32Handler;

impl Crypt32Handler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Crypt32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Crypt32Handler {
    fn call(&mut self, emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "CryptStringToBinary" | "CryptStringToBinaryA" | "CryptStringToBinaryW" => {
                let psz_string = args[0];
                let cch_string = args[1] as usize;
                let dw_flags = args[2];
                let pb_binary = args[3];
                let pcb_binary = args[4];
                let pdw_skip = args[5];
                let _pdw_flags = args[6];

                let mut data = if cch_string > 0 {
                    emu.mem_read(psz_string, cch_string)?
                } else {
                    emu.mem_read(psz_string, 256)?
                };

                while data.last() == Some(&0) {
                    data.pop();
                }

                if let Ok(s) = String::from_utf8(data.clone()) {
                    if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.trim()) {
                        if pcb_binary != 0 {
                            let out_len = decoded.len() as u32;
                            emu.mem_write(pcb_binary, &out_len.to_le_bytes())?;
                        }

                        if pb_binary == 0 {
                            return Ok(decoded.len() as u64);
                        }

                        let cb_binary = if pcb_binary != 0 {
                            u32::from_le_bytes(emu.mem_read(pcb_binary, 4)?.try_into()?) as usize
                        } else {
                            0
                        };

                        if decoded.len() > cb_binary {
                            return Ok(0);
                        }

                        emu.mem_write(pb_binary, &decoded)?;
                        if pcb_binary != 0 {
                            let out_len = decoded.len() as u32;
                            emu.mem_write(pcb_binary, &out_len.to_le_bytes())?;
                        }

                        if pdw_skip != 0 {
                            emu.mem_write(pdw_skip, &[0, 0, 0, 0])?;
                        }

                        return Ok(1);
                    }
                }

                Ok(0)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Crypt32"
    }
}
