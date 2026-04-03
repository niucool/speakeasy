// Memory Manager for Speakeasy

use crate::errors::{Result, SpeakeasyError};
use crate::common;
use std::sync::{Arc, Mutex};

/// Represents a memory mapping in the emulator
#[derive(Clone, Debug)]
pub struct MemMap {
    pub base: u64,
    pub size: u64,
    pub tag: String,
    pub prot: u32,
    pub flags: u32,
    pub shared: bool,
    pub free: bool,
    pub block_base: u64,
    pub block_size: u64,
}

impl MemMap {
    pub fn new(base: u64, size: u64, tag: Option<String>, prot: u32, flags: u32, block_base: u64, block_size: u64, shared: bool) -> Self {
        let mut final_tag = tag.unwrap_or_default();
        let base_addr_tag = format!(".0x{:x}", base);
        
        if !final_tag.contains(&base_addr_tag) {
            final_tag.push_str(&base_addr_tag);
        }

        // Sanitize tag
        final_tag = final_tag.chars().map(|c| {
            if "\\?[]:]".contains(c) { '_' } else { c }
        }).collect();

        Self {
            base,
            size,
            tag: final_tag,
            prot,
            flags,
            shared,
            free: false,
            block_base,
            block_size,
        }
    }
}

/// Core memory management logic
pub struct MemoryManager {
    pub maps: Vec<MemMap>,
    pub mem_reserves: Vec<MemMap>,
    pub block_base: u64,
    pub block_size: u64,
    pub block_offset: u64,
    pub page_size: u64,
    pub keep_memory_on_free: bool,
}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            maps: Vec::new(),
            mem_reserves: Vec::new(),
            block_base: 0,
            block_size: 0,
            block_offset: 0,
            page_size: 0x1000,
            keep_memory_on_free: false,
        }
    }

    /// Map a block of memory
    pub fn mem_map(&mut self, size: u64, base: Option<u64>, perms: u32, tag: Option<String>) -> Result<u64> {
        // Simple implementation for now, will be expanded to match Python's block logic
        let addr = base.unwrap_or_else(|| {
            // Find a gap (placeholder logic)
            let mut max_addr = 0x1000;
            for m in &self.maps {
                max_addr = max_addr.max(m.base + m.size);
            }
            for m in &self.mem_reserves {
                max_addr = max_addr.max(m.base + m.size);
            }
            common::align_to_page(max_addr, self.page_size)
        });

        let aligned_size = if size % self.page_size != 0 {
            common::align_to_page(size, self.page_size)
        } else {
            size
        };

        let mm = MemMap::new(addr, aligned_size, tag, perms, 0, addr, aligned_size, false);
        self.maps.push(mm);
        
        Ok(addr)
    }

    /// Reserve a block of memory
    pub fn mem_reserve(&mut self, size: u64, base: Option<u64>, tag: Option<String>) -> Result<u64> {
        let addr = base.unwrap_or_else(|| {
            let mut max_addr = 0x1000;
            for m in &self.maps {
                max_addr = max_addr.max(m.base + m.size);
            }
            for m in &self.mem_reserves {
                max_addr = max_addr.max(m.base + m.size);
            }
            common::align_to_page(max_addr, self.page_size)
        });

        let aligned_size = if size % self.page_size != 0 {
            common::align_to_page(size, self.page_size)
        } else {
            size
        };

        let mm = MemMap::new(addr, aligned_size, tag, common::PERM_MEM_RW, 0, addr, aligned_size, false);
        self.mem_reserves.push(mm);
        
        Ok(addr)
    }

    pub fn get_address_map(&self, address: u64) -> Option<&MemMap> {
        self.maps.iter().find(|m| address >= m.base && address < (m.base + m.size))
    }

    pub fn get_address_tag(&self, address: u64) -> Option<String> {
        self.get_address_map(address).map(|m| m.tag.clone())
    }

    pub fn is_address_valid(&self, address: u64) -> bool {
        self.get_address_map(address).is_some() || 
        self.mem_reserves.iter().any(|m| address >= m.base && address < (m.base + m.size))
    }
}
