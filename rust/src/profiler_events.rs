// Profiler Events for Speakeasy

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracePosition {
    pub tick: u64,
    pub tid: u32,
    pub pid: u32,
    pub pc: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event")]
pub enum AnyEvent {
    #[serde(rename = "api")]
    Api {
        pos: TracePosition,
        api_name: String,
        args: Vec<String>,
        ret_val: Option<String>,
    },
    #[serde(rename = "process_create")]
    ProcessCreate {
        pos: TracePosition,
        path: String,
        cmdline: String,
    },
    #[serde(rename = "mem_alloc")]
    MemAlloc {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
        protect: Option<String>,
    },
    #[serde(rename = "mem_write")]
    MemWrite {
        pos: TracePosition,
        path: String,
        base: String,
        size: usize,
        data_ref: Option<String>,
    },
    #[serde(rename = "mem_read")]
    MemRead {
        pos: TracePosition,
        path: String,
        base: String,
        size: usize,
        data_ref: Option<String>,
    },
    #[serde(rename = "mem_protect")]
    MemProtect {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
        protect: Option<String>,
    },
    #[serde(rename = "mem_free")]
    MemFree {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
    },
    #[serde(rename = "module_load")]
    ModuleLoad {
        pos: TracePosition,
        name: String,
        path: String,
        base: String,
        size: String,
    },
    #[serde(rename = "file_create")]
    FileCreate {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "file_open")]
    FileOpen {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "file_read")]
    FileRead {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        size: Option<usize>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "file_write")]
    FileWrite {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        size: Option<usize>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_open_key")]
    RegOpenKey {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "reg_create_key")]
    RegCreateKey {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "reg_read_value")]
    RegReadValue {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        value_name: Option<String>,
        size: Option<usize>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_write_value")]
    RegWriteValue {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        value_name: Option<String>,
        size: Option<usize>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_list_subkeys")]
    RegListSubkeys {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
    },
    #[serde(rename = "net_dns")]
    NetDns {
        pos: TracePosition,
        query: String,
        response: Option<String>,
    },
    #[serde(rename = "net_traffic")]
    NetTraffic {
        pos: TracePosition,
        server: String,
        port: u16,
        proto: String,
        r#type: Option<String>,
        data_ref: Option<String>,
        method: Option<String>,
    },
    #[serde(rename = "net_http")]
    NetHttp {
        pos: TracePosition,
        server: String,
        port: u16,
        proto: String,
        headers: Option<String>,
        body_ref: Option<String>,
    },
    #[serde(rename = "exception")]
    Exception {
        pos: TracePosition,
        instr: String,
        exception_code: String,
        handler_address: String,
        registers: std::collections::HashMap<String, String>,
        faulting_address: Option<String>,
        pc_module: Option<String>,
        stack_trace: Option<Vec<String>>,
    },
}
