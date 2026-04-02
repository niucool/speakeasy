use crate::winenv::api::ApiHandler;

pub struct MprHandler;

impl ApiHandler for MprHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Mpr"
    }
}
