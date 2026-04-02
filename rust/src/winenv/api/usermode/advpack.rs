use crate::winenv::api::ApiHandler;

pub struct AdvpackHandler;

impl ApiHandler for AdvpackHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Advpack"
    }
}
