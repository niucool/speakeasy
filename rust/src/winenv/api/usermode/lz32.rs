use crate::winenv::api::ApiHandler;

pub struct Lz32Handler;

impl ApiHandler for Lz32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Lz32"
    }
}
