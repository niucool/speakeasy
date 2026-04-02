use crate::winenv::api::ApiHandler;

pub struct Gdi32Handler;

impl ApiHandler for Gdi32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Gdi32"
    }
}
