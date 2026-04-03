// CLI configuration for Speakeasy

use clap::Parser;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Path to the input file
    #[arg(short, long)]
    pub file: String,

    /// Architecture (x86 or x64)
    #[arg(short, long)]
    pub arch: Option<String>,

    /// Timeout in seconds
    #[arg(short, long, default_value_t = 60)]
    pub timeout: u32,

    /// Output report file
    #[arg(short, long)]
    pub output: Option<String>,
}

pub struct CliConfig {
    pub args: CliArgs,
}

impl CliConfig {
    pub fn parse() -> Self {
        Self {
            args: CliArgs::parse(),
        }
    }
}
