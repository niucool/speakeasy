use crate::winenv::api::ApiHandler;

pub struct HalHandler;

impl ApiHandler for HalHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Hal"
    }
}
