use crate::winenv::api::ApiHandler;

pub struct NtdllHandler;

impl ApiHandler for NtdllHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Ntdll"
    }
}
