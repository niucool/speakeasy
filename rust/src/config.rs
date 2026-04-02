// Configuration management for Speakeasy emulator

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeakeasyConfig {
    /// Memory configuration  
    pub memory: MemoryConfig,

    /// Module configuration
    pub modules: ModuleConfig,

    /// File system configuration
    pub file_system: FileSystemConfig,

    /// Registry configuration
    pub registry: RegistryConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// API configuration
    pub api: ApiConfig,

    /// Process configuration
    pub process: ProcessConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Custom environment variables
    pub env_vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Stack size in bytes (default: 2MB)
    pub stack_size: u32,

    /// Heap size in bytes (default: 512MB)
    pub heap_size: u32,

    /// Track memory accesses
    pub track_accesses: bool,

    /// Maximum memory allocations (0 = unlimited)
    pub max_allocations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// Base address for module loading
    pub load_base: u64,

    /// Modules to skip loading
    pub skip_modules: Vec<String>,

    /// Modules to use decoys for
    pub use_decoys: Vec<String>,

    /// Custom module paths
    pub module_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemConfig {
    /// Virtual file system root directory
    pub vfs_root: PathBuf,

    /// Path to dropped files directory
    pub dropped_files_path: PathBuf,

    /// Track file accesses
    pub track_accesses: bool,

    /// Allowed path prefixes (read-only if not listed)
    pub allowed_writes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Enable registry emulation
    pub enabled: bool,

    /// Path to registry hive files
    pub hive_path: PathBuf,

    /// Track registry accesses
    pub track_accesses: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable network emulation
    pub enabled: bool,

    /// Mock network responses
    pub use_mocks: bool,

    /// Track network accesses
    pub track_accesses: bool,

    /// Allowed domains
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Enable API hooking
    pub hook_apis: bool,

    /// APIs to skip hooking
    pub skip_apis: Vec<String>,

    /// Timeout for API calls
    pub api_timeout_ms: u64,

    /// Track API calls
    pub track_calls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    /// Process ID to emulate
    pub process_id: u32,

    /// Parent process ID
    pub parent_pid: u32,

    /// Process name
    pub process_name: String,

    /// Command line arguments
    pub command_line: Vec<String>,

    /// Current directory
    pub current_dir: PathBuf,

    /// Emulate child processes
    pub emulate_children: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Logging level (trace, debug, info, warn, error)
    pub level: String,

    /// Log file path (None = stdout)
    pub file: Option<PathBuf>,

    /// Include timestamps in logs
    pub timestamps: bool,

    /// Include source locations in logs
    pub source_locations: bool,
}

impl Default for SpeakeasyConfig {
    fn default() -> Self {
        Self {
            memory: MemoryConfig {
                stack_size: 2 * 1024 * 1024,      // 2MB
                heap_size: 512 * 1024 * 1024,     // 512MB
                track_accesses: false,
                max_allocations: 0,
            },
            modules: ModuleConfig {
                load_base: 0x400000,
                skip_modules: vec![],
                use_decoys: vec![],
                module_paths: vec![],
            },
            file_system: FileSystemConfig {
                vfs_root: PathBuf::from("vfs"),
                dropped_files_path: PathBuf::from("dropped_files"),
                track_accesses: false,
                allowed_writes: vec![],
            },
            registry: RegistryConfig {
                enabled: true,
                hive_path: PathBuf::from("registry"),
                track_accesses: false,
            },
            network: NetworkConfig {
                enabled: true,
                use_mocks: true,
                track_accesses: false,
                allowed_domains: vec![],
            },
            api: ApiConfig {
                hook_apis: true,
                skip_apis: vec![],
                api_timeout_ms: 30000,
                track_calls: true,
            },
            process: ProcessConfig {
                process_id: 1000,
                parent_pid: 8,
                process_name: "explorer.exe".to_string(),
                command_line: vec![],
                current_dir: PathBuf::from("C:\\Windows"),
                emulate_children: false,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                timestamps: true,
                source_locations: false,
            },
            env_vars: HashMap::new(),
        }
    }
}

impl SpeakeasyConfig {
    /// Load configuration from a JSON file
    pub fn from_file(path: &str) -> crate::errors::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str::<Self>(&contents)?)
    }

    /// Save configuration to a JSON file
    pub fn save_to_file(&self, path: &str) -> crate::errors::Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Load configuration from JSON string
    pub fn from_json(json: &str) -> crate::errors::Result<Self> {
        Ok(serde_json::from_str::<Self>(json)?)
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> crate::errors::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}
