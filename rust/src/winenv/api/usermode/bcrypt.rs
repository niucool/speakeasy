use crate::winenv::api::ApiHandler;

pub struct BcryptHandler;

impl ApiHandler for BcryptHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Bcrypt"
    }
}
