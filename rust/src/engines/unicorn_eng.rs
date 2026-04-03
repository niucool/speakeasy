// CPU emulation using Unicorn engine

use crate::errors::{Result, SpeakeasyError};
use unicorn::{Unicorn, Arch, Mode, PROT_ALL, RegisterX86};
use crate::common;

pub trait EngineCallback: Send + Sync {
    fn on_code(&mut self, addr: u64, size: u32);
    fn on_mem_invalid(&mut self, access: i32, addr: u64, size: usize, value: i64) -> bool;
    fn on_intr(&mut self, intno: u32);
}

pub struct EmuEngine {
    pub uc: Unicorn,
}

impl EmuEngine {
    pub fn new(arch: &str) -> Result<Self> {
        let (uarch, mode) = if arch == "amd64" || arch == "x64" {
            (Arch::X86, Mode::MODE_64)
        } else {
            (Arch::X86, Mode::MODE_32)
        };

        let uc = Unicorn::new(uarch, mode)
            .map_err(|e| SpeakeasyError::Unknown(format!("Unicorn init error: {:?}", e)))?;

        Ok(Self { uc })
    }

    pub fn mem_map(&mut self, addr: u64, size: usize, prot: u32) -> Result<()> {
        let uprot = self.convert_prot(prot);
        self.uc.mem_map(addr, size, uprot)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_map error: {:?}", e)))
    }

    pub fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.uc.mem_write(addr, data)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_write error: {:?}", e)))
    }

    pub fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.uc.mem_read(addr, size)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_read error: {:?}", e)))
    }

    pub fn reg_write(&mut self, reg: i32, val: u64) -> Result<()> {
        self.uc.reg_write(reg, val)
            .map_err(|e| SpeakeasyError::Unknown(format!("reg_write error: {:?}", e)))
    }

    pub fn reg_read(&self, reg: i32) -> Result<u64> {
        self.uc.reg_read(reg)
            .map_err(|e| SpeakeasyError::Unknown(format!("reg_read error: {:?}", e)))
    }

    pub fn start(&mut self, addr: u64, timeout: u64, count: usize) -> Result<()> {
        self.uc.emu_start(addr, 0xFFFFFFFF, timeout, count)
            .map_err(|e| SpeakeasyError::Unknown(format!("emu_start error: {:?}", e)))
    }

    pub fn stop(&mut self) -> Result<()> {
        self.uc.emu_stop()
            .map_err(|e| SpeakeasyError::Unknown(format!("emu_stop error: {:?}", e)))
    }

    fn convert_prot(&self, prot: u32) -> u32 {
        let mut u = unicorn::PROT_NONE;
        if prot & common::PERM_MEM_READ != 0 { u |= unicorn::PROT_READ; }
        if prot & common::PERM_MEM_WRITE != 0 { u |= unicorn::PROT_WRITE; }
        if prot & common::PERM_MEM_EXEC != 0 { u |= unicorn::PROT_EXEC; }
        u
    }
}
