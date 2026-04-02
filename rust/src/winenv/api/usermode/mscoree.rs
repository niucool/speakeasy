use crate::winenv::api::ApiHandler;

pub struct MscoreeHandler;

impl ApiHandler for MscoreeHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Mscoree"
    }
}
