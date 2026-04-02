use crate::winenv::api::ApiHandler;

pub struct NetutilsHandler;

impl ApiHandler for NetutilsHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Netutils"
    }
}
