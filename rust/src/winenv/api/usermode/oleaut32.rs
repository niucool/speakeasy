use crate::winenv::api::ApiHandler;

pub struct Oleaut32Handler;

impl ApiHandler for Oleaut32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Oleaut32"
    }
}
