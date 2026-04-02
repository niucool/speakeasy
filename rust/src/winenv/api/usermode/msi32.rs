use crate::winenv::api::ApiHandler;

pub struct Msi32Handler;

impl ApiHandler for Msi32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Msi32"
    }
}
