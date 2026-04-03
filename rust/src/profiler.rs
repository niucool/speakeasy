// Profiler for Speakeasy

use crate::profiler_events::{AnyEvent, TracePosition};
use crate::report::{EntryPoint, ErrorInfo, Report};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct MemAccess {
    pub base: u64,
    pub size: u64,
    pub sym: Option<String>,
    pub reads: u32,
    pub writes: u32,
    pub execs: u32,
}

pub struct Run {
    pub instr_cnt: u64,
    pub start_addr: u64,
    pub run_type: String,
    pub events: Vec<AnyEvent>,
    pub args: Vec<u64>,
    pub error: Option<ErrorInfo>,
    pub ret_val: Option<u64>,
}

impl Run {
    pub fn new(start_addr: u64, run_type: String) -> Self {
        Self {
            instr_cnt: 0,
            start_addr,
            run_type,
            events: Vec::new(),
            args: Vec::new(),
            error: None,
            ret_val: None,
        }
    }
}

pub struct Profiler {
    pub start_time: SystemTime,
    pub runs: Vec<Run>,
    pub meta: HashMap<String, String>,
}

impl Profiler {
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
            runs: Vec::new(),
            meta: HashMap::new(),
        }
    }

    pub fn add_run(&mut self, run: Run) {
        self.runs.push(run);
    }

    pub fn record_api_event(
        &mut self,
        run_idx: usize,
        pos: TracePosition,
        name: String,
        ret: Option<u64>,
        args: Vec<String>,
    ) {
        if let Some(run) = self.runs.get_mut(run_idx) {
            let event = AnyEvent::Api {
                pos,
                api_name: name,
                args,
                ret_val: ret.map(|r| format!("0x{:x}", r)),
            };
            run.events.push(event);
        }
    }

    pub fn get_report(&self, arch: String) -> Report {
        let mut entry_points = Vec::new();
        for run in &self.runs {
            entry_points.push(EntryPoint {
                ep_type: run.run_type.clone(),
                start_addr: run.start_addr,
                ep_args: run.args.clone(),
                instr_count: run.instr_cnt as u32,
                error: run.error.clone(),
            });
        }

        let timestamp = self
            .start_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Report {
            report_version: "3.0.0".to_string(),
            emulation_total_runtime: self
                .start_time
                .elapsed()
                .map(|e| e.as_secs_f64())
                .unwrap_or(0.0),
            timestamp,
            arch,
            entry_points,
            data: None,
        }
    }
}
