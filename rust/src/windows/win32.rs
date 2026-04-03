// Win32 Emulation Subsystem

use crate::config::SpeakeasyConfig;
use crate::errors::Result;
use crate::windows::winemu::WindowsEmulator;

/// User Mode Windows Emulator Class
pub struct Win32Emulator {
    pub base: WindowsEmulator,
    pub last_error: u32,
    pub argv: Vec<String>,
}

impl Win32Emulator {
    pub fn new(config: SpeakeasyConfig, argv: Option<Vec<String>>) -> Result<Self> {
        let base = WindowsEmulator::new(config, false)?;

        Ok(Self {
            base,
            last_error: 0,
            argv: argv.unwrap_or_default(),
        })
    }

    pub fn get_argv(&self) -> Vec<String> {
        self.argv.clone()
    }

    pub fn set_last_error(&mut self, code: u32) {
        self.last_error = code;
        // In real implementation, set it on the current thread context
    }

    pub fn get_last_error(&self) -> u32 {
        self.last_error
    }

    pub fn setup_user_shared_data(&mut self) -> Result<()> {
        // Setup KUSER_SHARED_DATA (e.g. 0x7FFE0000 mapping)
        // Self::base.mem_map(0x1000, 0x7FFE0000);
        Ok(())
    }

    pub fn emulate_module(&mut self, path: &str) -> Result<()> {
        self.base.load_module(path)?;
        // Emulation pipeline setup: setup_user_shared_data(), init_peb(), start()
        Ok(())
    }

    pub fn emulate_shellcode(&mut self, path: &str, data: &[u8], arch: &str) -> Result<()> {
        let addr = self.base.load_shellcode(data, arch)?;
        // Start shellcode execution
        self.base.start(addr)?;
        Ok(())
    }
}
