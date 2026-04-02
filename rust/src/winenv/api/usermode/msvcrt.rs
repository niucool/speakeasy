use crate::winenv::api::ApiHandler;

pub struct MsvcrtHandler;

impl ApiHandler for MsvcrtHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Msvcrt"
    }
}
