pub mod usermode;
pub mod kernelmode;
pub mod api;
pub mod winapi;

use std::collections::HashMap;
use crate::errors::Result;

pub trait ApiHandler {
    fn call(&mut self, args: &[u64]) -> u64;
    fn get_name(&self) -> &str;
}

pub struct ApiDispatcher {
    handlers: HashMap<String, Box<dyn ApiHandler>>,
}

impl ApiDispatcher {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: &str, handler: Box<dyn ApiHandler>) {
        self.handlers.insert(name.to_lowercase(), handler);
    }

    pub fn dispatch(&mut self, module_name: &str, api_name: &str, args: &[u64]) -> Result<u64> {
        let name = format!("{}!{}", module_name, api_name).to_lowercase();
        if let Some(handler) = self.handlers.get_mut(&name) {
            Ok(handler.call(args))
        } else {
            Err(crate::errors::SpeakeasyError::ApiError(format!(
                "API callback failed for {}",
                name
            )))
        }
    }
}
