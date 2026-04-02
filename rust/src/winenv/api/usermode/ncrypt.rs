use crate::winenv::api::ApiHandler;

pub struct NcryptHandler;

impl ApiHandler for NcryptHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Ncrypt"
    }
}
