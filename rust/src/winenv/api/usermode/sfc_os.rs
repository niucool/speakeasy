use crate::winenv::api::ApiHandler;

pub struct SfcOsHandler;

impl ApiHandler for SfcOsHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "SfcOs"
    }
}
