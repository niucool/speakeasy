use crate::winenv::api::ApiHandler;

pub struct WininetHandler;

impl ApiHandler for WininetHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Wininet"
    }
}
