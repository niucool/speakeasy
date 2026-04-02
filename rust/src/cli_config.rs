use crate::config::SpeakeasyConfig;
use crate::errors::{Result, SpeakeasyError};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn get_default_config_dict() -> Result<Value> {
    serde_json::to_value(SpeakeasyConfig::default()).map_err(Into::into)
}

pub fn merge_config_dicts(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            for (key, value) in overlay_map {
                merge_config_dicts(base_map.entry(key).or_insert(Value::Null), value);
            }
        }
        (slot, value) => *slot = value,
    }
}

pub fn load_config_file(path: &Path) -> Result<Value> {
    let contents = std::fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(Into::into)
}

pub fn load_merged_config(path: Option<&Path>) -> Result<SpeakeasyConfig> {
    let mut config = get_default_config_dict()?;
    if let Some(path) = path {
        merge_config_dicts(&mut config, load_config_file(path)?);
    }
    serde_json::from_value(config).map_err(Into::into)
}

pub fn parse_mapping_entry(raw: &str) -> Result<(String, String)> {
    let Some((key, value)) = raw.split_once('=') else {
        return Err(SpeakeasyError::ConfigError(format!(
            "invalid mapping {raw:?}; expected KEY=VALUE"
        )));
    };
    if key.is_empty() {
        return Err(SpeakeasyError::ConfigError(format!(
            "invalid mapping {raw:?}; key is empty"
        )));
    }
    Ok((key.to_string(), value.to_string()))
}

pub fn apply_env_overrides(config: &mut SpeakeasyConfig, env: &[String]) -> Result<()> {
    for raw in env {
        let (key, value) = parse_mapping_entry(raw)?;
        config.env_vars.insert(key, value);
    }
    Ok(())
}

pub fn apply_module_paths(config: &mut SpeakeasyConfig, module_paths: &[PathBuf]) {
    config.modules.module_paths.extend(module_paths.iter().cloned());
}
