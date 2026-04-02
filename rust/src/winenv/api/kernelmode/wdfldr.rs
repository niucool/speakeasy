use crate::winenv::api::ApiHandler;

pub struct WdfldrHandler;

impl ApiHandler for WdfldrHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Wdfldr"
    }
}
