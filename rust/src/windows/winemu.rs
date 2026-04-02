// Windows Emulator base class

use crate::config::SpeakeasyConfig;
use crate::errors::{Result, SpeakeasyError};
use crate::speakeasy::Speakeasy;
use crate::windows::sessman::SessionManager;
use crate::windows::{
    KernelManager, FileSystemManager, RegistryManager, NetworkManager, ObjectManager
};

use std::sync::{Arc, Mutex};

/// Represents the Bootstrap phase of the emulator
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum BootstrapPhase {
    Initialized = 0,
    EngineApiReady = 1,
    ObjectManagerReady = 2,
    FullSetupReady = 3,
}

/// Base class providing emulation of all Windows modules and shellcode.
/// Provides overlapping functionality for both user mode and kernel mode samples.
pub struct WindowsEmulator {
    pub emu: Speakeasy,
    pub config: SpeakeasyConfig,
    
    // Core state
    pub bootstrap_phase: BootstrapPhase,
    pub is_kernel_mode: bool,
    pub peb_addr: u64,
    pub fs_addr: u64,
    pub gs_addr: u64,
    
    // Subsystem Managers
    pub sessman: Arc<Mutex<SessionManager>>,
    pub regman: Arc<Mutex<RegistryManager>>,
    pub fileman: Arc<Mutex<FileSystemManager>>,
    pub netman: Arc<Mutex<NetworkManager>>,
    pub objman: Arc<Mutex<ObjectManager>>,
    pub kernel: Arc<Mutex<KernelManager>>,
}

impl WindowsEmulator {
    pub fn new(config: SpeakeasyConfig, is_kernel_mode: bool) -> Result<Self> {
        let emu = Speakeasy::new(Some(config.clone()))?;
        let sessman = Arc::new(Mutex::new(SessionManager::new(&config)));
        let regman = Arc::new(Mutex::new(RegistryManager::new()));
        let fileman = Arc::new(Mutex::new(FileSystemManager::new()));
        let netman = Arc::new(Mutex::new(NetworkManager::new()));
        let objman = Arc::new(Mutex::new(ObjectManager::new()));
        let kernel = Arc::new(Mutex::new(KernelManager::new()));

        Ok(Self {
            emu,
            config,
            bootstrap_phase: BootstrapPhase::Initialized,
            is_kernel_mode,
            peb_addr: 0,
            fs_addr: 0,
            gs_addr: 0,
            
            sessman,
            regman,
            fileman,
            netman,
            objman,
            kernel,
        })
    }

    pub fn advance_bootstrap_phase(&mut self, phase: BootstrapPhase) -> Result<()> {
        if phase <= self.bootstrap_phase {
            return Ok(());
        }

        match (self.bootstrap_phase, phase) {
            (BootstrapPhase::Initialized, BootstrapPhase::EngineApiReady) => {},
            (BootstrapPhase::EngineApiReady, BootstrapPhase::ObjectManagerReady) |
            (BootstrapPhase::EngineApiReady, BootstrapPhase::FullSetupReady) => {},
            (BootstrapPhase::ObjectManagerReady, BootstrapPhase::FullSetupReady) => {},
            _ => {
                return Err(SpeakeasyError::ApiError(format!(
                    "Invalid bootstrap transition from {:?} to {:?}", 
                    self.bootstrap_phase, phase
                )));
            }
        }

        self.bootstrap_phase = phase;
        Ok(())
    }

    pub fn validate_bootstrap_phase(&self, phase: BootstrapPhase, reason: &str) -> Result<()> {
        if self.bootstrap_phase < phase {
            return Err(SpeakeasyError::ApiError(format!(
                "{} requires bootstrap phase {:?}, current phase is {:?}",
                reason, phase, self.bootstrap_phase
            )));
        }
        Ok(())
    }

    pub fn get_session_manager(&self) -> Arc<Mutex<SessionManager>> {
        Arc::clone(&self.sessman)
    }

    pub fn get_file_manager(&self) -> Arc<Mutex<FileSystemManager>> {
        Arc::clone(&self.fileman)
    }

    pub fn get_network_manager(&self) -> Arc<Mutex<NetworkManager>> {
        Arc::clone(&self.netman)
    }

    pub fn get_registry_manager(&self) -> Arc<Mutex<RegistryManager>> {
        Arc::clone(&self.regman)
    }

    /// Load a module for emulation
    pub fn load_module(&self, path: &str) -> Result<String> {
        self.emu.load_module(path)
    }

    /// Load shellcode for emulation
    pub fn load_shellcode(&self, data: &[u8], arch: &str) -> Result<u64> {
        self.emu.load_shellcode(data, arch)
    }

    /// Execute the emulator starting at a specific address
    pub fn start(&self, address: u64) -> Result<()> {
        // Here we would typically prepare PEB, TEB, setup stacks and GDT
        self.emu.run_shellcode(address)
    }

    pub fn alloc_peb(&mut self) -> Result<()> {
        // Allocate space for PEB
        self.peb_addr = 0x7FFDF000; // Standard dummy address
        Ok(())
    }
}

/// Kernel Mode Windows Emulator Class
pub struct WinKernelEmulator {
    pub base: WindowsEmulator,
}

impl WinKernelEmulator {
    pub fn new(config: SpeakeasyConfig) -> Result<Self> {
        let base = WindowsEmulator::new(config, true)?;
        Ok(Self { base })
    }
}
