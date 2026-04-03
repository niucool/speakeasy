// Binary Emulator for Speakeasy

use crate::errors::{Result, SpeakeasyError};
use crate::memmgr::MemoryManager;
use crate::config::SpeakeasyConfig;
use crate::common;
use crate::profiler::Profiler;

/// Base trait for all binary emulators
pub trait BinaryEmulator: Send {
    fn get_arch(&self) -> u32;
    fn get_ptr_size(&self) -> u32;
    
    // Register access
    fn reg_read(&self, reg: u32) -> Result<u64>;
    fn reg_write(&mut self, reg: u32, val: u64) -> Result<()>;
    
    // Memory access (delegated to MemoryManager in implementation)
    fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>>;
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()>;
    
    // PC access
    fn get_pc(&self) -> Result<u64>;
    fn set_pc(&mut self, addr: u64) -> Result<()>;
    
    // Stack management
    fn get_stack_ptr(&self) -> Result<u64>;
    fn set_stack_ptr(&mut self, addr: u64) -> Result<()>;
}

/// Core emulator state
pub struct BaseBinaryEmulator {
    pub mem: MemoryManager,
    pub config: SpeakeasyConfig,
    pub profiler: Profiler,
    pub arch: u32,
    pub ptr_size: u32,
}

impl BaseBinaryEmulator {
    pub fn new(config: SpeakeasyConfig, arch: u32) -> Self {
        let ptr_size = if arch == 9 { 8 } else { 4 }; // ARCH_AMD64 = 9
        Self {
            mem: MemoryManager::new(),
            config,
            profiler: Profiler::new(),
            arch,
            ptr_size,
        }
    }

    pub fn push_stack(&mut self, emu: &mut dyn BinaryEmulator, val: u64) -> Result<()> {
        let mut sp = emu.get_stack_ptr()?;
        sp -= self.ptr_size as u64;
        let bytes = if self.ptr_size == 8 {
            val.to_le_bytes().to_vec()
        } else {
            (val as u32).to_le_bytes().to_vec()
        };
        emu.mem_write(sp, &bytes)?;
        emu.set_stack_ptr(sp)?;
        Ok(())
    }

    pub fn pop_stack(&mut self, emu: &mut dyn BinaryEmulator) -> Result<u64> {
        let sp = emu.get_stack_ptr()?;
        let bytes = emu.mem_read(sp, self.ptr_size as usize)?;
        let val = if self.ptr_size == 8 {
            u64::from_le_bytes(bytes.try_into().map_err(|_| SpeakeasyError::ApiError("Failed to read stack".to_string()))?)
        } else {
            u32::from_le_bytes(bytes.try_into().map_err(|_| SpeakeasyError::ApiError("Failed to read stack".to_string()))?) as u64
        };
        emu.set_stack_ptr(sp + self.ptr_size as u64)?;
        Ok(val)
    }
}
