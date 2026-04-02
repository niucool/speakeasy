// Emulation engine

use crate::config::SpeakeasyConfig;
use crate::errors::Result;
use crate::report::Report;
use std::sync::{Arc, Mutex};

pub use crate::memmgr::MemoryManager;
pub use crate::engines::unicorn_eng::CpuEmulator;
pub use crate::binemu::ModuleManager;

/// Main emulator interface
pub struct Speakeasy {
    config: SpeakeasyConfig,
    memory: Arc<Mutex<MemoryManager>>,
    cpu: Arc<Mutex<CpuEmulator>>,
    modules: Arc<Mutex<ModuleManager>>,
    report: Arc<Mutex<Report>>,
}

impl Speakeasy {
    pub fn new(config: Option<SpeakeasyConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        
        let memory = MemoryManager::new(
            config.memory.stack_size as usize,
            config.memory.heap_size as usize,
        )?;

        // Assuming x86 as default, can be dynamically configured via config later
        let cpu = CpuEmulator::new("x86")?;
        let modules = ModuleManager::new();
        let report = Report::new();

        Ok(Self {
            config,
            memory: Arc::new(Mutex::new(memory)),
            cpu: Arc::new(Mutex::new(cpu)),
            modules: Arc::new(Mutex::new(modules)),
            report: Arc::new(Mutex::new(report)),
        })
    }

    /// Load a PE module
    pub fn load_module(&self, path: &str) -> Result<String> {
        let mut modules = self.modules.lock().unwrap();
        modules.load_module(path, &self.config)
    }

    /// Run a loaded module
    pub fn run_module(&self, _module_name: &str) -> Result<()> {
        let mut cpu = self.cpu.lock().unwrap();
        let memory = self.memory.lock().unwrap();
        let allocations = memory.get_allocations();
        // Get module entry point from ModuleManager. For now, default to 0x400000
        let entry_point = 0x400000;
        cpu.execute(&allocations, entry_point)
    }

    /// Load and execute raw shellcode
    pub fn load_shellcode(&self, data: &[u8], _arch: &str) -> Result<u64> {
        let mut memory = self.memory.lock().unwrap();
        memory.allocate(data.len() as u32)
    }

    /// Run loaded shellcode
    pub fn run_shellcode(&self, address: u64) -> Result<()> {
        let mut cpu = self.cpu.lock().unwrap();
        let memory = self.memory.lock().unwrap();
        let allocations = memory.get_allocations();
        cpu.execute(&allocations, address)
    }

    /// Get the execution report
    pub fn get_report(&self) -> Report {
        self.report.lock().unwrap().clone()
    }

    /// Get JSON report
    pub fn get_json_report(&self) -> Result<String> {
        let report = self.report.lock().unwrap();
        report.to_json()
    }

    /// Shutdown the emulator
    pub fn shutdown(&mut self) -> Result<()> {
        // Cleanup resources
        Ok(())
    }
}

impl Drop for Speakeasy {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}


