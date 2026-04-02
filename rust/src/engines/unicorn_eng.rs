// CPU emulation using Unicorn engine

use crate::errors::{Result, SpeakeasyError};

pub struct CpuEmulator {
    state: EmulatorState,
    pub arch: String,
}

#[derive(Debug, Clone)]
pub struct EmulatorState {
    pub registers: Registers,
    pub running: bool,
    pub instruction_count: u64,
}

#[derive(Debug, Clone)]
pub struct Registers {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub eip: u32,
}

impl CpuEmulator {
    pub fn new(arch: &str) -> Result<Self> {
        Ok(Self {
            arch: arch.to_string(),
            state: EmulatorState {
                registers: Registers {
                    eax: 0,
                    ebx: 0,
                    ecx: 0,
                    edx: 0,
                    esi: 0,
                    edi: 0,
                    ebp: 0,
                    esp: 0xfffff000,
                    eip: 0x400000,
                },
                running: false,
                instruction_count: 0,
            },
        })
    }

    /// Execute the emulator
    pub fn execute(&mut self, memory_map: &[(u64, usize)], entry_point: u64) -> Result<()> {
        self.state.running = true;
        
        let arch = if self.arch == "amd64" {
            unicorn::Arch::X86
        } else {
            unicorn::Arch::X86
        };
        
        let mode = if self.arch == "amd64" {
            unicorn::Mode::MODE_64
        } else {
            unicorn::Mode::MODE_32
        };
        
        let mut emu = match unicorn::Unicorn::new(arch, mode) {
            Ok(e) => e,
            Err(e) => return Err(SpeakeasyError::Unknown(format!("Unicorn init error: {:?}", e))),
        };
        
        // Map memory safely to avoid unmapped memory exception
        for (addr, size) in memory_map {
            // Memory already aligned by `MemoryManager::allocate` page boundaries
            let prot = unicorn::PROT_ALL;
            if let Err(e) = emu.mem_map(*addr, *size, prot) {
                return Err(SpeakeasyError::MemoryError(
                    format!("Failed to map memory at {:#x}: {:?}", addr, e)
                ));
            }
        }
        
        // Setup simple registers
        if mode == unicorn::Mode::MODE_32 {
            // These registers correspond to X86
            let _ = emu.reg_write(unicorn::RegisterX86::EAX as i32, self.state.registers.eax as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::EBX as i32, self.state.registers.ebx as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::ECX as i32, self.state.registers.ecx as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::EDX as i32, self.state.registers.edx as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::ESI as i32, self.state.registers.esi as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::EDI as i32, self.state.registers.edi as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::EBP as i32, self.state.registers.ebp as u64);
            let _ = emu.reg_write(unicorn::RegisterX86::ESP as i32, self.state.registers.esp as u64);
        }

        // Start emulation until exhaustion or crash
        let _ = emu.emu_start(entry_point, 0, 0, 0);

        // Read out registers after emulation
        if mode == unicorn::Mode::MODE_32 {
            self.state.registers.eax = emu.reg_read(unicorn::RegisterX86::EAX as i32).unwrap_or(0) as u32;
            self.state.registers.ebx = emu.reg_read(unicorn::RegisterX86::EBX as i32).unwrap_or(0) as u32;
            self.state.registers.ecx = emu.reg_read(unicorn::RegisterX86::ECX as i32).unwrap_or(0) as u32;
            self.state.registers.edx = emu.reg_read(unicorn::RegisterX86::EDX as i32).unwrap_or(0) as u32;
            self.state.registers.esi = emu.reg_read(unicorn::RegisterX86::ESI as i32).unwrap_or(0) as u32;
            self.state.registers.edi = emu.reg_read(unicorn::RegisterX86::EDI as i32).unwrap_or(0) as u32;
            self.state.registers.ebp = emu.reg_read(unicorn::RegisterX86::EBP as i32).unwrap_or(0) as u32;
            self.state.registers.esp = emu.reg_read(unicorn::RegisterX86::ESP as i32).unwrap_or(0) as u32;
            self.state.registers.eip = emu.reg_read(unicorn::RegisterX86::EIP as i32).unwrap_or(unicorn::RegisterX86::EIP as u64) as u32;
        }

        // Set running state false
        self.state.running = false;
        Ok(())
    }

    /// Get current register state
    pub fn get_registers(&self) -> &Registers {
        &self.state.registers
    }

    /// Set register value
    pub fn set_register(&mut self, name: &str, value: u32) -> Result<()> {
        match name {
            "eax" => self.state.registers.eax = value,
            "ebx" => self.state.registers.ebx = value,
            "ecx" => self.state.registers.ecx = value,
            "edx" => self.state.registers.edx = value,
            "esi" => self.state.registers.esi = value,
            "edi" => self.state.registers.edi = value,
            "ebp" => self.state.registers.ebp = value,
            "esp" => self.state.registers.esp = value,
            "eip" => self.state.registers.eip = value,
            _ => return Err(SpeakeasyError::Unknown(format!("Unknown register: {}", name))),
        }
        Ok(())
    }

    /// Get instruction count
    pub fn get_instruction_count(&self) -> u64 {
        self.state.instruction_count
    }
}

impl Default for CpuEmulator {
    fn default() -> Self {
        Self::new("x86").unwrap()
    }
}
