// Module (DLL/EXE) management

use crate::config::SpeakeasyConfig;
use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub path: String,
    pub base_address: u64,
    pub size: u32,
    pub entry_point: u32,
}

pub struct ModuleManager {
    modules: HashMap<String, Module>,
    base_address: u64,
}

impl ModuleManager {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            base_address: 0x400000,
        }
    }

    /// Load a PE module
    pub fn load_module(&mut self, path: &str, _config: &SpeakeasyConfig) -> Result<String> {
        // This would parse a PE file using goblin/pelite
        let module_name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let module = Module {
            name: module_name.clone(),
            path: path.to_string(),
            base_address: self.base_address,
            size: 0x10000, // Placeholder
            entry_point: 0x401000,
        };

        self.modules.insert(module_name.clone(), module);
        self.base_address += 0x100000; // Allocate 1MB per module

        Ok(module_name)
    }

    /// Get a loaded module
    pub fn get_module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }

    /// Get all loaded modules
    pub fn get_modules(&self) -> Vec<&Module> {
        self.modules.values().collect()
    }

    /// Unload a module
    pub fn unload_module(&mut self, name: &str) -> Result<()> {
        if self.modules.remove(name).is_none() {
            return Err(SpeakeasyError::InvalidModule(format!(
                "Module not found: {}",
                name
            )));
        }
        Ok(())
    }
}

impl Default for ModuleManager {
    fn default() -> Self {
        Self::new()
    }
}
