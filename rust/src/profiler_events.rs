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
    ApiEvent {
        pos: TracePosition,
        api_name: String,
        args: Vec<String>,
        ret_val: Option<String>,
    },
    #[serde(rename = "process_create")]
    ProcessCreateEvent {
        pos: TracePosition,
        path: String,
        cmdline: String,
    },
    #[serde(rename = "mem_alloc")]
    MemAllocEvent {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
        protect: Option<String>,
    },
    #[serde(rename = "mem_write")]
    MemWriteEvent {
        pos: TracePosition,
        path: String,
        base: String,
        size: u32,
        data_ref: Option<String>,
    },
    #[serde(rename = "mem_read")]
    MemReadEvent {
        pos: TracePosition,
        path: String,
        base: String,
        size: u32,
        data_ref: Option<String>,
    },
    #[serde(rename = "mem_protect")]
    MemProtectEvent {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
        protect: Option<String>,
    },
    #[serde(rename = "mem_free")]
    MemFreeEvent {
        pos: TracePosition,
        path: String,
        base: String,
        size: String,
    },
    #[serde(rename = "module_load")]
    ModuleLoadEvent {
        pos: TracePosition,
        name: String,
        path: String,
        base: String,
        size: String,
    },
    #[serde(rename = "thread_create")]
    ThreadCreateEvent {
        pos: TracePosition,
        path: String,
        start_addr: String,
        param: String,
    },
    #[serde(rename = "thread_inject")]
    ThreadInjectEvent {
        pos: TracePosition,
        path: String,
        start_addr: String,
        param: String,
    },
    #[serde(rename = "file_create")]
    FileCreateEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "file_open")]
    FileOpenEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "file_read")]
    FileReadEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        size: Option<u32>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "file_write")]
    FileWriteEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        size: Option<u32>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_open_key")]
    RegOpenKeyEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "reg_create_key")]
    RegCreateKeyEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        open_flags: Option<Vec<String>>,
        access_flags: Option<Vec<String>>,
    },
    #[serde(rename = "reg_read_value")]
    RegReadValueEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        value_name: Option<String>,
        size: Option<u32>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_write_value")]
    RegWriteValueEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
        value_name: Option<String>,
        size: Option<u32>,
        data_ref: Option<String>,
        buffer: Option<String>,
    },
    #[serde(rename = "reg_list_subkeys")]
    RegListSubkeysEvent {
        pos: TracePosition,
        path: String,
        handle: Option<String>,
    },
    #[serde(rename = "net_dns")]
    NetDnsEvent {
        pos: TracePosition,
        query: String,
        response: Option<String>,
    },
    #[serde(rename = "net_traffic")]
    NetTrafficEvent {
        pos: TracePosition,
        server: String,
        port: u16,
        proto: String,
        r#type: Option<String>,
        data_ref: Option<String>,
        method: Option<String>,
    },
    #[serde(rename = "net_http")]
    NetHttpEvent {
        pos: TracePosition,
        server: String,
        port: u16,
        proto: String,
        headers: Option<String>,
        body_ref: Option<String>,
    },
    #[serde(rename = "exception")]
    ExceptionEvent {
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
