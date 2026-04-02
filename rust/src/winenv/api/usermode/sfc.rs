use crate::winenv::api::ApiHandler;

pub struct SfcHandler;

impl ApiHandler for SfcHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Sfc"
    }
}
