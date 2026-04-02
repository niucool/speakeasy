use crate::winenv::api::ApiHandler;

pub struct WinmmHandler;

impl ApiHandler for WinmmHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Winmm"
    }
}
