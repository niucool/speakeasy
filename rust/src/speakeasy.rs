// Speakeasy wrapper class

use crate::errors::{Result, SpeakeasyError};
use crate::config::SpeakeasyConfig;
use crate::windows::winemu::{Win32Emulator, WinKernelEmulator, WindowsEmulator};
use crate::binemu::BinaryEmulator;
use crate::report::Report;
use crate::windows::loaders::{PeLoader, ShellcodeLoader, LoadedImage};

pub struct Speakeasy {
    pub config: SpeakeasyConfig,
    pub emu: Option<Box<dyn BinaryEmulator>>,
}

impl Speakeasy {
    pub fn new(config: Option<SpeakeasyConfig>) -> Result<Self> {
        let cfg = config.unwrap_or_default();
        Ok(Self {
            config: cfg,
            emu: None,
        })
    }

    pub fn load_module(&mut self, path: &str) -> Result<String> {
        let loader = PeLoader::new(Some(path.to_string()), None, None, "".to_string());
        let image = loader.make_image()?;
        
        let module_name = image.name.clone();
        
        if image.module_type == "driver" {
            let mut wink = WinKernelEmulator::new(self.config.clone())?;
            // wink.base.load_image(image)?;
            self.emu = Some(Box::new(wink.base));
        } else {
            let mut win32 = Win32Emulator::new(self.config.clone())?;
            // win32.base.load_image(image)?;
            self.emu = Some(Box::new(win32.base));
        }
        
        Ok(module_name)
    }

    pub fn load_shellcode(&mut self, data: &[u8], arch: &str) -> Result<u64> {
        let arch_id = if arch == "x64" || arch == "amd64" { 9 } else { 0 };
        let loader = ShellcodeLoader {
            data: data.to_vec(),
            arch: arch_id,
        };
        let _image = loader.make_image()?;
        
        let mut win32 = Win32Emulator::new(self.config.clone())?;
        // win32.base.load_image(image)?;
        self.emu = Some(Box::new(win32.base));
        
        Ok(0) // Return loaded address
    }

    pub fn run_module(&mut self, _name: &str) -> Result<()> {
        if let Some(ref mut emu) = self.emu {
            let pc = emu.get_pc()?;
            // emu.start(pc)?;
            Ok(())
        } else {
            Err(SpeakeasyError::ApiError("Emulator not initialized".to_string()))
        }
    }

    pub fn run_shellcode(&mut self, addr: u64) -> Result<()> {
        if let Some(ref mut emu) = self.emu {
            // emu.start(addr)?;
            Ok(())
        } else {
            Err(SpeakeasyError::ApiError("Emulator not initialized".to_string()))
        }
    }

    pub fn get_report(&self) -> Result<Report> {
        let arch = if let Some(ref emu) = self.emu {
            if emu.get_arch() == 9 { "x64".to_string() } else { "x86".to_string() }
        } else {
            "unknown".to_string()
        };
        Ok(Report::new(arch))
    }

    pub fn get_json_report(&self) -> Result<String> {
        let report = self.get_report()?;
        Ok(report.to_json())
    }
}
