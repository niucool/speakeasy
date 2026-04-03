// CPU emulation using Unicorn engine

use crate::common;
use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;
use unicorn::{Arch, HookType, Mode, Unicorn};

pub trait EngineCallback: Send + Sync {
    fn on_code(&mut self, addr: u64, size: u32);
    fn on_mem_invalid(&mut self, access: i32, addr: u64, size: usize, value: i64) -> bool;
    fn on_intr(&mut self, intno: u32);
}

pub struct ToggleableHook {
    pub enabled: bool,
}

impl ToggleableHook {
    pub fn new() -> Self {
        Self { enabled: false }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for ToggleableHook {
    fn default() -> Self {
        Self::new()
    }
}

pub struct EmuEngine {
    pub uc: Unicorn,
    callbacks: HashMap<usize, ToggleableHook>,
    next_hook_id: usize,
    regs: HashMap<u32, u32>,
    mem_access: HashMap<u32, u32>,
    perms: HashMap<u32, u32>,
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

        let mut regs = HashMap::new();
        regs.insert(0, 0); // X86_REG_EAX
        regs.insert(1, 1); // X86_REG_ECX
        regs.insert(2, 2); // X86_REG_EDX
        regs.insert(3, 3); // X86_REG_EBX
        regs.insert(4, 4); // X86_REG_ESP
        regs.insert(5, 5); // X86_REG_EBP
        regs.insert(6, 6); // X86_REG_ESI
        regs.insert(7, 7); // X86_REG_EDI
        regs.insert(8, 8); // X86_REG_EIP
        regs.insert(9, 9); // X86_REG_EFLAGS

        // 64-bit registers
        regs.insert(10, 10); // AMD64_REG_RAX
        regs.insert(11, 11); // AMD64_REG_RCX
        regs.insert(12, 12); // AMD64_REG_RDX
        regs.insert(13, 13); // AMD64_REG_RBX
        regs.insert(14, 14); // AMD64_REG_RSP
        regs.insert(15, 15); // AMD64_REG_RBP
        regs.insert(16, 16); // AMD64_REG_RSI
        regs.insert(17, 17); // AMD64_REG_RDI
        regs.insert(18, 18); // AMD64_REG_RIP

        let mut mem_access = HashMap::new();
        mem_access.insert(common::INVALID_MEM_EXEC, 64); // UC_MEM_FETCH_UNMAPPED
        mem_access.insert(common::INVALID_MEM_READ, 16); // UC_MEM_READ_UNMAPPED
        mem_access.insert(common::INVAL_PERM_MEM_EXEC, 512); // UC_MEM_FETCH_PROT
        mem_access.insert(common::INVAL_PERM_MEM_WRITE, 256); // UC_MEM_WRITE_PROT
        mem_access.insert(common::INVAL_PERM_MEM_READ, 128); // UC_MEM_READ_PROT
        mem_access.insert(common::INVALID_MEM_WRITE, 32); // UC_MEM_WRITE_UNMAPPED

        let mut perms = HashMap::new();
        perms.insert(common::PERM_MEM_NONE, 0);
        perms.insert(common::PERM_MEM_EXEC, 1);
        perms.insert(common::PERM_MEM_READ, 2);
        perms.insert(common::PERM_MEM_WRITE, 4);
        perms.insert(common::PERM_MEM_RW, 6);
        perms.insert(common::PERM_MEM_RX, 3);
        perms.insert(common::PERM_MEM_RWX, 7);

        Ok(Self {
            uc,
            callbacks: HashMap::new(),
            next_hook_id: 1000,
            regs,
            mem_access,
            perms,
        })
    }

    pub fn init_engine(&mut self, _eng_arch: u32, _mode: u32) -> Result<()> {
        // Already initialized in new() - this is for compatibility
        Ok(())
    }

    pub fn sec_to_usec(&self, sec: u64) -> u64 {
        sec * 1_000_000
    }

    pub fn mem_map(&mut self, addr: u64, size: usize, prot: u32) -> Result<()> {
        let uprot = self.convert_prot(prot);
        self.uc
            .mem_map(addr, size, uprot)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_map error: {:?}", e)))
    }

    pub fn mem_unmap(&mut self, addr: u64, size: usize) -> Result<()> {
        self.uc
            .mem_unmap(addr, size)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_unmap error: {:?}", e)))
    }

    pub fn mem_regions(&self) -> Result<Vec<(u64, usize, u32)>> {
        let regions = self
            .uc
            .mem_regions()
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_regions error: {:?}", e)))?;

        let mut result = Vec::new();
        for region in regions {
            result.push((region.begin, region.size, region.perms.bits()));
        }
        Ok(result)
    }

    pub fn mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_write error: {:?}", e)))
    }

    pub fn mem_read(&self, addr: u64, size: usize) -> Result<Vec<u8>> {
        self.uc
            .mem_read(addr, size)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_read error: {:?}", e)))
    }

    pub fn mem_protect(&mut self, addr: u64, size: usize, prot: u32) -> Result<()> {
        let uprot = self.convert_prot(prot);
        self.uc
            .mem_protect(addr, size, uprot)
            .map_err(|e| SpeakeasyError::MemoryError(format!("mem_protect error: {:?}", e)))
    }

    pub fn reg_write(&mut self, reg: u32, val: u64) -> Result<()> {
        let ereg = self.regs.get(&reg).copied();
        if let Some(ereg) = ereg {
            self.uc
                .reg_write(ereg, val)
                .map_err(|e| SpeakeasyError::Unknown(format!("reg_write error: {:?}", e)))
        } else {
            Err(SpeakeasyError::Unknown(format!(
                "Unknown register: {}",
                reg
            )))
        }
    }

    pub fn reg_read(&self, reg: u32) -> Result<u64> {
        let ereg = self.regs.get(&reg).copied();
        if let Some(ereg) = ereg {
            self.uc
                .reg_read(ereg)
                .map_err(|e| SpeakeasyError::Unknown(format!("reg_read error: {:?}", e)))
        } else {
            Err(SpeakeasyError::Unknown(format!(
                "Unknown register: {}",
                reg
            )))
        }
    }

    pub fn start(&mut self, addr: u64, timeout: u64, count: usize) -> Result<()> {
        let timeout_us = self.sec_to_usec(timeout);
        let count = if count == usize::MAX { 0 } else { count };
        self.uc
            .emu_start(addr, 0xFFFFFFFF, timeout_us, count)
            .map_err(|e| SpeakeasyError::Unknown(format!("emu_start error: {:?}", e)))
    }

    pub fn stop(&mut self) -> Result<()> {
        self.uc
            .emu_stop()
            .map_err(|e| SpeakeasyError::Unknown(format!("emu_stop error: {:?}", e)))
    }

    pub fn hook_add(&mut self, _htype: u32, _begin: u64, _end: u64) -> Result<usize> {
        // Basic hook_add implementation
        // Returns a hook handle
        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_code<F>(&mut self, begin: u64, end: u64, callback: F) -> Result<usize>
    where
        F: Fn(u64, u32) + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(HookType::CODE, callback, begin, end)
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_mem<F>(&mut self, hook_type: HookType, callback: F) -> Result<usize>
    where
        F: Fn(u64, usize) -> bool + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(hook_type, callback, 1, 0)
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_mem_invalid<F>(&mut self, callback: F) -> Result<usize>
    where
        F: Fn(u64, usize, i64) -> bool + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(
                HookType::MEM_READ_UNMAPPED
                    | HookType::MEM_WRITE_UNMAPPED
                    | HookType::MEM_FETCH_UNMAPPED,
                callback,
                1,
                0,
            )
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_intr<F>(&mut self, callback: F) -> Result<usize>
    where
        F: Fn(u32) + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(HookType::INTR, callback, 1, 0)
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_insn<F>(&mut self, callback: F, insn: u32) -> Result<usize>
    where
        F: Fn() + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(HookType::INSN, callback, 1, 0, insn)
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_add_block<F>(&mut self, callback: F) -> Result<usize>
    where
        F: Fn(u64) + Send + 'static,
    {
        let hook_handle = self
            .uc
            .hook_add(HookType::BLOCK, callback, 1, 0)
            .map_err(|e| SpeakeasyError::Unknown(format!("hook_add error: {:?}", e)))?;

        let handle = self.next_hook_id;
        self.next_hook_id += 1;

        let hook = ToggleableHook::new();
        self.callbacks.insert(handle, hook);

        Ok(handle)
    }

    pub fn hook_enable(&mut self, hook_handle: usize) -> Result<()> {
        if let Some(hook) = self.callbacks.get_mut(&hook_handle) {
            hook.enable();
            Ok(())
        } else {
            Err(SpeakeasyError::Unknown(format!(
                "Hook handle {} not found",
                hook_handle
            )))
        }
    }

    pub fn hook_disable(&mut self, hook_handle: usize) -> Result<()> {
        if let Some(hook) = self.callbacks.get_mut(&hook_handle) {
            hook.disable();
            Ok(())
        } else {
            Err(SpeakeasyError::Unknown(format!(
                "Hook handle {} not found",
                hook_handle
            )))
        }
    }

    pub fn hook_remove(&mut self, hook_handle: usize) -> Result<()> {
        self.callbacks.remove(&hook_handle);
        Ok(())
    }

    pub fn close(&mut self) {
        for handle in self.callbacks.keys().copied().collect::<Vec<_>>() {
            self.callbacks.remove(&handle);
        }
        self.callbacks.clear();
    }

    fn convert_prot(&self, prot: u32) -> unicorn::Protection {
        let mut u = unicorn::Protection::NONE;
        if prot & common::PERM_MEM_READ != 0 {
            u |= unicorn::Protection::READ;
        }
        if prot & common::PERM_MEM_WRITE != 0 {
            u |= unicorn::Protection::WRITE;
        }
        if prot & common::PERM_MEM_EXEC != 0 {
            u |= unicorn::Protection::EXEC;
        }
        u
    }
}
