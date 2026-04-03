use crate::winenv::api::ApiHandler;
use crate::binemu::BinaryEmulator;
use crate::errors::Result;

pub struct IphlpapiHandler;

impl IphlpapiHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IphlpapiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for IphlpapiHandler {
    fn call(&mut self, _emu: &mut dyn BinaryEmulator, name: &str, args: &[u64]) -> Result<u64> {
        match name {
            "GetAdaptersInfo" => {
                let _ptr_adapter_info = args[0];
                let _size_ptr = args[1];
                Ok(0)
            },
            _ => Ok(0),
        }
    }

    fn get_name(&self) -> &str {
        "Iphlpapi"
    }
}
