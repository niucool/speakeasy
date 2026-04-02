use crate::winenv::api::ApiHandler;

pub struct FwpkclntHandler;

impl ApiHandler for FwpkclntHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Fwpkclnt"
    }
}
