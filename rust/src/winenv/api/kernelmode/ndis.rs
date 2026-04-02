use crate::winenv::api::ApiHandler;

pub struct NdisHandler;

impl ApiHandler for NdisHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Ndis"
    }
}
