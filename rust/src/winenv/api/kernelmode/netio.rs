use crate::winenv::api::ApiHandler;

pub struct NetioHandler;

impl ApiHandler for NetioHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Netio"
    }
}
