use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub const DNS_TYPE_TEXT: u16 = 0x0010;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INVALID_PARAMETER: u32 = 87;

pub struct DnsapiHandler;

impl DnsapiHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsapiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for DnsapiHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "DnsQuery_" | "DnsQuery_A" | "DnsQuery_UTF8" | "DnsQuery_W" => {
                let psz_name = args[0];
                let w_type = args[1] as u16;
                let _options = args[2];
                let _p_extra = args[3];
                let pp_query_results = args[4];
                let _p_reserved = args[5];

                if pp_query_results != 0 && psz_name != 0 {
                    if w_type == DNS_TYPE_TEXT {
                    }

                    let result: u64 = 0;
                    emu.mem_write(pp_query_results, &result.to_le_bytes())?;
                    Ok(ERROR_SUCCESS as u64)
                } else {
                    Ok(ERROR_INVALID_PARAMETER as u64)
                }
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Dnsapi"
    }
}
