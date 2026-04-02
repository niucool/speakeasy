use crate::winenv::api::ApiHandler;

pub struct UsbdHandler;

impl ApiHandler for UsbdHandler {
    fn call(&mut self, _args: &[u64]) -> u64 {
        0
    }

    fn get_name(&self) -> &str {
        "Usbd"
    }
}
