// Memory management

use crate::errors::{Result, SpeakeasyError};
use std::collections::HashMap;

pub struct MemoryManager {
    stack_size: usize,
    heap_size: usize,
    allocations: HashMap<u64, usize>,
    stack_pointer: u64,
    heap_pointer: u64,
}

impl MemoryManager {
    pub fn new(stack_size: usize, heap_size: usize) -> Result<Self> {
        if stack_size == 0 || heap_size == 0 {
            return Err(SpeakeasyError::MemoryError(
                "Stack and heap sizes must be > 0".to_string(),
            ));
        }

        Ok(Self {
            stack_size,
            heap_size,
            allocations: HashMap::new(),
            stack_pointer: 0x400000,
            heap_pointer: 0x500000,
        })
    }

    /// Allocate memory from the heap
    pub fn allocate(&mut self, size: u32) -> Result<u64> {
        // Ensure starting address is page-aligned (4KB)
        let align = 0x1000;
        if self.heap_pointer % align != 0 {
            self.heap_pointer = (self.heap_pointer + align - 1) & !(align - 1);
        }
        
        let addr = self.heap_pointer;
        self.allocations.insert(addr, size as usize);
        
        // Page align the size to advance the pointer
        let aligned_size = (size as u64 + align - 1) & !(align - 1);
        self.heap_pointer += aligned_size;

        if self.heap_pointer - 0x500000 > self.heap_size as u64 {
            return Err(SpeakeasyError::MemoryError(
                "Heap exhausted".to_string(),
            ));
        }

        Ok(addr)
    }

    /// Deallocate memory
    pub fn deallocate(&mut self, address: u64) -> Result<()> {
        self.allocations.remove(&address);
        Ok(())
    }

    /// Get the size of an allocation
    pub fn get_allocation_size(&self, address: u64) -> Option<usize> {
        self.allocations.get(&address).copied()
    }

    /// Get all allocations
    pub fn get_allocations(&self) -> Vec<(u64, usize)> {
        self.allocations
            .iter()
            .map(|(addr, size)| (*addr, *size))
            .collect()
    }
}
