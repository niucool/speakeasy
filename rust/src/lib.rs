// Speakeasy - Windows Malware Emulation Framework
// Copyright (C) Mandiant. All Rights Reserved.

pub mod winenv;
pub mod config;
pub mod common;
pub mod speakeasy;
pub mod memmgr;
pub mod binemu;
pub mod errors;
pub mod engines;
pub mod profiler;
pub mod report;
pub mod windows;
pub mod version;
pub mod profiler_events;
pub mod structs;
pub mod artifacts;
pub mod volumes;

pub use speakeasy::Speakeasy;
pub use windows::win32::Win32Emulator;
pub use windows::winemu::WinKernelEmulator;
pub use config::SpeakeasyConfig;
pub use errors::{SpeakeasyError, Result};
pub use report::Report;

pub const VERSION: &str = "3.0.0";
