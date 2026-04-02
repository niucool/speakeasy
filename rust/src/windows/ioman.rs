// IO Manager
use std::collections::HashMap;

pub struct IoManager {
    devices: HashMap<String, u32>,
}

impl IoManager {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }
}

impl Default for IoManager {
    fn default() -> Self {
        Self::new()
    }
}
