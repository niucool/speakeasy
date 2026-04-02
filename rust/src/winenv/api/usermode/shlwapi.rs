use std::path::{Path, PathBuf};

use crate::winenv::api::ApiHandler;

pub struct ShlwapiHandler;

impl ShlwapiHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn path_append(base: &str, more: &str) -> String {
        let mut path = PathBuf::from(base);
        path.push(more);
        path.to_string_lossy().to_string()
    }

    pub fn path_file_exists(path: &str) -> bool {
        Path::new(path).exists()
    }

    pub fn path_find_file_name(path: &str) -> String {
        Path::new(path)
            .file_name()
            .map(|part| part.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string())
    }

    pub fn path_remove_file_spec(path: &str) -> String {
        Path::new(path)
            .parent()
            .map(|part| part.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    pub fn path_is_relative(path: &str) -> bool {
        Path::new(path).is_relative()
    }
}

impl Default for ShlwapiHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for ShlwapiHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            1 => u64::from(Self::path_is_relative("relative\\path")),
            2 => Self::path_append("C:\\Windows", "System32").len() as u64,
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Shlwapi"
    }
}
