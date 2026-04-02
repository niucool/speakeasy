use crate::winenv::api::ApiHandler;

pub struct IphlpapiHandler;

impl ApiHandler for IphlpapiHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Iphlpapi"
    }
}
