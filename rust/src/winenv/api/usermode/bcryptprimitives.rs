use crate::winenv::api::ApiHandler;

pub struct BcryptprimitivesHandler;

impl ApiHandler for BcryptprimitivesHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Bcryptprimitives"
    }
}
