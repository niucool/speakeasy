// Speakeasy - Windows Malware Emulation Framework
// Copyright (C) Mandiant. All Rights Reserved.

pub mod artifacts;
pub mod binemu;
pub mod cli;
pub mod cli_config;
pub mod common;
pub mod config;
pub mod engines;
pub mod errors;
pub mod memmgr;
pub mod profiler;
pub mod profiler_events;
pub mod report;
pub mod r#struct;
pub mod speakeasy;
pub mod structs;
pub mod version;
pub mod volumes;
pub mod windows;
pub mod winenv;

pub use speakeasy::Speakeasy;
pub use windows::win32::Win32Emulator;
pub use windows::winemu::WinKernelEmulator;
pub use config::SpeakeasyConfig;
pub use errors::{SpeakeasyError, Result};
pub use report::Report;

pub const VERSION: &str = "3.0.0";
