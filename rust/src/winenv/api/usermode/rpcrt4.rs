use crate::winenv::api::ApiHandler;

pub struct Rpcrt4Handler;

impl ApiHandler for Rpcrt4Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Rpcrt4"
    }
}
