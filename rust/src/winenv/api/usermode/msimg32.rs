use crate::winenv::api::ApiHandler;

pub struct Msimg32Handler;

impl ApiHandler for Msimg32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Msimg32"
    }
}
