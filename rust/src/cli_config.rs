// CLI configuration for Speakeasy

use crate::config::SpeakeasyConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn get_default_config_dict() -> crate::errors::Result<String> {
    let config = SpeakeasyConfig::default();
    Ok(serde_json::to_string_pretty(&config)?)
}

pub fn load_merged_config(config_path: Option<&str>) -> crate::errors::Result<SpeakeasyConfig> {
    let mut config = SpeakeasyConfig::default();
    if let Some(path) = config_path {
        let file_config = SpeakeasyConfig::from_file(path)?;
        config = file_config;
    }
    Ok(config)
}

pub fn apply_env_overrides(
    config: &mut SpeakeasyConfig,
    env_vars: &[String],
) -> crate::errors::Result<()> {
    for env in env_vars {
        if let Some((key, value)) = env.split_once('=') {
            config.env_vars.insert(key.to_string(), value.to_string());
        }
    }
    Ok(())
}

pub fn apply_module_paths(config: &mut SpeakeasyConfig, paths: &[PathBuf]) {
    for path in paths {
        config.modules.module_paths.push(path.clone());
    }
}
