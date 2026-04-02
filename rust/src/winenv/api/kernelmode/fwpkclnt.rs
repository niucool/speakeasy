use crate::winenv::api::ApiHandler;
use crate::winenv::defs::wfp::fwpmtypes::GUID;

pub struct FwpkclntHandler {
    next_id: u64,
}

impl FwpkclntHandler {
    pub fn new() -> Self {
        Self { next_id: 0x6000 }
    }

    pub fn fwpm_engine_open(&mut self) -> u64 {
        let handle = self.next_id;
        self.next_id += 4;
        handle
    }

    pub fn fwpm_sub_layer_add(&mut self, _engine_handle: u64, _sub_layer: Option<GUID>) -> u32 {
        0
    }

    pub fn fwpm_filter_add(&mut self, _engine_handle: u64, _filter_key: Option<GUID>) -> u64 {
        let filter_id = self.next_id;
        self.next_id += 4;
        filter_id
    }

    pub fn fwpm_engine_close(&self, handle: u64) -> bool {
        handle != 0
    }
}

impl Default for FwpkclntHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for FwpkclntHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.fwpm_engine_open(),
            1 => u64::from(self.fwpm_engine_close(args[0])),
            2 => self.fwpm_filter_add(args[0], None),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Fwpkclnt"
    }
}
