// Report generation for executed samples

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Sample SHA256 hash
    pub sha256: String,

    /// Sample SHA1 hash
    pub sha1: String,

    /// Sample MD5 hash
    pub md5: String,

    /// File type (exe, dll, sys, shellcode)
    pub filetype: String,

    /// Architecture (x86 or amd64)
    pub arch: String,

    /// Entry points
    pub entry_points: Vec<EntryPoint>,

    /// Loaded modules
    pub modules: Vec<ModuleInfo>,

    /// Executed API calls
    pub api_calls: Vec<ApiCall>,

    /// File system accesses
    pub file_accesses: Vec<FileAccess>,

    /// Registry accesses
    pub registry_accesses: Vec<RegistryAccess>,

    /// Network activity
    pub network_activity: Vec<NetworkActivity>,

    /// Memory allocations
    pub memory_allocations: Vec<MemoryAllocation>,

    /// Exceptions/errors
    pub exceptions: Vec<Exception>,

    /// Process information
    pub process_info: ProcessInfo,

    /// Execution statistics
    pub stats: ExecutionStats,

    /// Raw disassembly (optional, may be large)
    pub disassembly: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub address: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: u64,
    pub size: u32,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCall {
    pub timestamp: u64,
    pub function: String,
    pub module: String,
    pub args: HashMap<String, String>,
    pub return_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccess {
    pub timestamp: u64,
    pub path: String,
    pub access_type: String,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAccess {
    pub timestamp: u64,
    pub key: String,
    pub value: Option<String>,
    pub access_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub timestamp: u64,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAllocation {
    pub timestamp: u64,
    pub address: u64,
    pub size: u32,
    pub allocator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub timestamp: u64,
    pub code: u32,
    pub address: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub path: String,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    pub total_instructions: u64,
    pub total_api_calls: u32,
    pub total_allocations: u32,
    pub total_files_accessed: u32,
    pub total_registry_accesses: u32,
    pub execution_time_ms: u64,
}

impl Report {
    pub fn new() -> Self {
        Self {
            sha256: String::new(),
            sha1: String::new(),
            md5: String::new(),
            filetype: String::new(),
            arch: String::new(),
            entry_points: vec![],
            modules: vec![],
            api_calls: vec![],
            file_accesses: vec![],
            registry_accesses: vec![],
            network_activity: vec![],
            memory_allocations: vec![],
            exceptions: vec![],
            process_info: ProcessInfo {
                process_id: 0,
                parent_pid: 0,
                process_name: String::new(),
                path: String::new(),
                command_line: String::new(),
            },
            stats: ExecutionStats {
                total_instructions: 0,
                total_api_calls: 0,
                total_allocations: 0,
                total_files_accessed: 0,
                total_registry_accesses: 0,
                execution_time_ms: 0,
            },
            disassembly: None,
        }
    }

    pub fn to_json(&self) -> crate::errors::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize report to compact JSON string
    pub fn to_json_compact(&self) -> crate::errors::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}
