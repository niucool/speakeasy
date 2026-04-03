// API Hammering detection and mitigation

use crate::errors::Result;
use crate::config::SpeakeasyConfig;
use crate::binemu::BinaryEmulator;
use std::collections::HashMap;

pub struct ApiHammer {
    pub enabled: bool,
    pub threshold: u32,
    pub allow_list: Vec<String>,
    pub api_stats: HashMap<String, u32>,
    pub hammer_memregion: Option<u64>,
}

impl ApiHammer {
    pub fn new(config: &SpeakeasyConfig) -> Self {
        Self {
            enabled: config.api_hammering.enabled,
            threshold: config.api_hammering.threshold,
            allow_list: config.api_hammering.allow_list.clone().unwrap_or_default(),
            api_stats: HashMap::new(),
            hammer_memregion: None,
        }
    }

    pub fn is_allowed_api(&self, name: &str) -> bool {
        self.allow_list.iter().any(|a| a.to_lowercase() == name.to_lowercase())
    }

    pub fn handle_import_func(&mut self, _emu: &mut dyn BinaryEmulator, name: &str) -> Result<()> {
        if !self.enabled || self.is_allowed_api(name) {
            return Ok(());
        }

        let count = self.api_stats.entry(name.to_string()).or_insert(0);
        *count += 1;

        if *count >= self.threshold {
            // Mitigation logic would go here
            // e.g. patching the call site to return immediately
        }

        Ok(())
    }
}
