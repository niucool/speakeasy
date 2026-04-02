use crate::winenv::api::ApiHandler;

pub struct Ole32Handler;

impl ApiHandler for Ole32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Ole32"
    }
}
