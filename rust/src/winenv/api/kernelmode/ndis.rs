use crate::winenv::api::ApiHandler;

pub struct NdisHandler {
    next_handle: u64,
}

impl NdisHandler {
    pub fn new() -> Self {
        Self { next_handle: 0x7000 }
    }

    pub fn ndis_allocate_generic_object(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 0x20;
        handle
    }

    pub fn ndis_allocate_net_buffer_list_pool(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 0x20;
        handle
    }

    pub fn ndis_free_memory(&self, handle: u64) -> bool {
        handle != 0
    }
}

impl Default for NdisHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NdisHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.ndis_allocate_generic_object(),
            1 => u64::from(self.ndis_free_memory(args[0])),
            2 => self.ndis_allocate_net_buffer_list_pool(),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Ndis"
    }
}
