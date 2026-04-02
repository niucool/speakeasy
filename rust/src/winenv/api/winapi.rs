use super::ApiHandler;
use std::collections::HashMap;

/// Serves as the central registry system analogous to Python's WindowsApi class in speakeasy/winenv/api/winapi.py
/// It maps loaded module APIs string names to the corresponding ApiHandler dynamic boxed objects.
pub struct WindowsApiRegistry {
    handlers: HashMap<String, Box<dyn ApiHandler>>,
}

impl WindowsApiRegistry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Analogous to load_api_handler / autoload_api_handlers in Python winapi.py.
    pub fn register(&mut self, module_name: &str, handler: Box<dyn ApiHandler>) {
        self.handlers.insert(module_name.to_lowercase(), handler);
    }

    /// Maps to get_export_func_handler in winapi.py
    pub fn get_export_func_handler(&self, module_name: &str) -> Option<&Box<dyn ApiHandler>> {
        self.handlers.get(&module_name.to_lowercase())
    }

    pub fn get_export_func_handler_mut(&mut self, module_name: &str) -> Option<&mut Box<dyn ApiHandler>> {
        self.handlers.get_mut(&module_name.to_lowercase())
    }
}
