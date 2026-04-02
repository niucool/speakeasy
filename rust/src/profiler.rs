// Profiler events and data collection

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerEvent {
    pub timestamp: u64,
    pub event_type: EventType,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ApiCall,
    MemoryAlloc,
    MemoryFree,
    FileAccess,
    RegistryAccess,
    NetworkActivity,
    Exception,
    DllLoad,
    DllUnload,
}

pub struct Profiler {
    events: Vec<ProfilerEvent>,
    start_time: u64,
    stats: ProfilerStats,
}

#[derive(Debug, Clone, Default)]
pub struct ProfilerStats {
    pub api_calls: u32,
    pub memory_allocations: u32,
    pub memory_deallocations: u32,
    pub file_accesses: u32,
    pub registry_accesses: u32,
    pub network_operations: u32,
    pub exceptions: u32,
}

impl Profiler {
    pub fn new() -> Self {
        Self {
            events: vec![],
            start_time: 0,
            stats: ProfilerStats::default(),
        }
    }

    pub fn start(&mut self) {
        self.start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
    }

    pub fn record_event(&mut self, event_type: EventType, data: String) {
        self.events.push(ProfilerEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            event_type: event_type.clone(),
            data,
        });

        // Update stats
        match event_type {
            EventType::ApiCall => self.stats.api_calls += 1,
            EventType::MemoryAlloc => self.stats.memory_allocations += 1,
            EventType::MemoryFree => self.stats.memory_deallocations += 1,
            EventType::FileAccess => self.stats.file_accesses += 1,
            EventType::RegistryAccess => self.stats.registry_accesses += 1,
            EventType::NetworkActivity => self.stats.network_operations += 1,
            EventType::Exception => self.stats.exceptions += 1,
            _ => {}
        }
    }

    pub fn get_events(&self) -> &[ProfilerEvent] {
        &self.events
    }

    pub fn get_stats(&self) -> &ProfilerStats {
        &self.stats
    }

    pub fn get_event_count(&self, event_type: &EventType) -> usize {
        self.events
            .iter()
            .filter(|e| std::mem::discriminant(&e.event_type) == std::mem::discriminant(event_type))
            .count()
    }
}

impl Default for Profiler {
    fn default() -> Self {
        Self::new()
    }
}
