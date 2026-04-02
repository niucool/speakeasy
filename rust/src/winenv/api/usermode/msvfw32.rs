use crate::winenv::api::ApiHandler;

pub struct Msvfw32Handler;

impl ApiHandler for Msvfw32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Msvfw32"
    }
}
