// Volume mounting support for Speakeasy

use crate::errors::{Result, SpeakeasyError};
use crate::config::SpeakeasyConfig;
use std::path::{Path, PathBuf};

pub fn parse_volume_spec(spec: &str) -> Result<(PathBuf, String)> {
    if spec.is_empty() {
        return Err(SpeakeasyError::ConfigError("Empty volume specification".to_string()));
    }

    let mut start = 0;
    if spec.len() >= 2 && spec.as_bytes()[1] == b':' {
        start = 2;
    }

    match spec[start..].find(':') {
        Some(idx) => {
            let host_str = &spec[..start + idx];
            let guest_str = &spec[start + idx + 1..];
            
            if host_str.is_empty() || guest_str.is_empty() {
                return Err(SpeakeasyError::ConfigError(format!("Invalid volume spec: {}", spec)));
            }
            Ok((PathBuf::from(host_str), guest_str.to_string()))
        },
        None => Err(SpeakeasyError::ConfigError(format!("Invalid volume spec (missing ':' separator): {}", spec))),
    }
}

pub fn apply_volumes(config: &mut SpeakeasyConfig, volume_specs: &[String]) -> Result<()> {
    for spec in volume_specs {
        let (host_path, guest_path) = parse_volume_spec(spec)?;
        // In a real implementation, we would expand directories here
        // and update config.file_system.files
    }
    Ok(())
}
