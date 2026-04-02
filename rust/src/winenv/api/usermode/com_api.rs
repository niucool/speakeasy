use crate::winenv::api::ApiHandler;

pub struct ComApiHandler;

impl ApiHandler for ComApiHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "ComApi"
    }
}
