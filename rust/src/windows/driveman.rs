// Drive Manager
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Drive {
    pub letter: String,
    pub drive_type: u32,
    pub serial_number: u32,
    pub volume_name: String,
    pub file_system: String,
}

pub struct DriveManager {
    drives: HashMap<String, Drive>,
}

impl DriveManager {
    pub fn new() -> Self {
        Self {
            drives: HashMap::new(),
        }
    }
    
    pub fn get_drive(&self, letter: &str) -> Option<&Drive> {
        self.drives.get(letter)
    }
}

impl Default for DriveManager {
    fn default() -> Self {
        Self::new()
    }
}
