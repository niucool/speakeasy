use crate::winenv::api::ApiHandler;

pub struct Shell32Handler;

impl ApiHandler for Shell32Handler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Shell32"
    }
}
