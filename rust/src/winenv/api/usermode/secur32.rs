use crate::winenv::api::ApiHandler;

pub struct Secur32Handler;

impl ApiHandler for Secur32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Secur32"
    }
}
