use crate::winenv::api::ApiHandler;
use crate::winenv::defs::nt::ddk;

const PROCESS_BASIC_INFORMATION: u32 = 0;
const PROCESS_WOW64_INFORMATION: u32 = 0x1A;
const PROCESS_IMAGE_FILE_NAME: u32 = 0x1B;

pub struct NtdllHandler {
    last_error: u32,
}

impl NtdllHandler {
    pub fn new() -> Self {
        Self { last_error: 0 }
    }

    pub fn rtl_get_last_win32_error(&self) -> u32 {
        self.last_error
    }

    pub fn rtl_set_last_win32_error(&mut self, error: u32) {
        self.last_error = error;
    }

    pub fn nt_close(&mut self, handle: u64) -> u32 {
        if handle == 0 {
            self.last_error = ddk::STATUS_INVALID_HANDLE;
            ddk::STATUS_INVALID_HANDLE
        } else {
            ddk::STATUS_SUCCESS
        }
    }

    pub fn nt_query_information_process(&self, _process: u64, process_information_class: u32) -> u32 {
        match process_information_class {
            PROCESS_BASIC_INFORMATION | PROCESS_WOW64_INFORMATION | PROCESS_IMAGE_FILE_NAME => {
                ddk::STATUS_SUCCESS
            }
            _ => ddk::STATUS_NOT_SUPPORTED,
        }
    }
}

impl Default for NtdllHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NtdllHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            1 => self.nt_close(args[0]) as u64,
            2 => self.nt_query_information_process(args[0], args[1] as u32) as u64,
            _ => self.rtl_get_last_win32_error() as u64,
        }
    }

    fn get_name(&self) -> &str {
        "Ntdll"
    }
}
