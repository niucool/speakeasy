// ApiHammer
use std::collections::HashMap;

pub struct ApiHammer {
    pub is_enabled: bool,
    callbacks: HashMap<String, Box<dyn Fn(&[u64])>>,
}

impl ApiHammer {
    pub fn new() -> Self {
        Self {
            is_enabled: true,
            callbacks: HashMap::new(),
        }
    }
}

impl Default for ApiHammer {
    fn default() -> Self {
        Self::new()
    }
}
