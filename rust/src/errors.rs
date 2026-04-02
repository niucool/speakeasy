// Error types for Speakeasy emulator

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SpeakeasyError {
    #[error("Emulator not initialized")]
    EmulatorNotInitialized,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("File error: {0}")]
    FileError(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Invalid architecture: {0}")]
    InvalidArchitecture(String),

    #[error("Invalid module: {0}")]
    InvalidModule(String),

    #[error("Memory error: {0}")]
    MemoryError(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, SpeakeasyError>;
