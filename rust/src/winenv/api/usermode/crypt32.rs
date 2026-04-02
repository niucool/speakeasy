use crate::winenv::api::ApiHandler;

pub struct Crypt32Handler;

impl ApiHandler for Crypt32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Crypt32"
    }
}
