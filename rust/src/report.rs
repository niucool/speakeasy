// Report Generator for Speakeasy

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryRegion {
    pub tag: String,
    pub address: u64,
    pub size: u64,
    pub prot: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorInfo {
    pub r#type: String,
    pub pc: Option<u64>,
    pub api_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntryPoint {
    pub ep_type: String,
    pub start_addr: u64,
    pub ep_args: Vec<u64>,
    pub instr_count: u32,
    pub error: Option<ErrorInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataArtifact {
    pub compression: String,
    pub encoding: String,
    pub size: usize,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    pub report_version: String,
    pub emulation_total_runtime: f64,
    pub timestamp: u64,
    pub arch: String,
    pub entry_points: Vec<EntryPoint>,
    pub data: Option<HashMap<String, DataArtifact>>,
}

impl Report {
    pub fn new(arch: String) -> Self {
        Self {
            report_version: "3.0.0".to_string(),
            emulation_total_runtime: 0.0,
            timestamp: 0,
            arch,
            entry_points: Vec::new(),
            data: None,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}
