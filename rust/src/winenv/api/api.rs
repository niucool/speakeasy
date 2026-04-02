use crate::structs::EmuStruct;

pub trait ApiEmuContext {
    fn get_ptr_size(&self) -> usize;
    fn mem_read(&self, addr: u64, size: usize) -> Vec<u8>;
    fn mem_write(&mut self, addr: u64, data: &[u8]);

    fn read_mem_string(&self, addr: u64, width: usize, max_chars: usize) -> String;
    
    fn read_wide_string(&self, addr: u64, max_chars: usize) -> String {
        self.read_mem_string(addr, 2, max_chars)
    }

    fn read_string(&self, addr: u64, max_chars: usize) -> String {
        self.read_mem_string(addr, 1, max_chars)
    }

    fn sizeof<T: EmuStruct>(&self) -> usize {
        T::sizeof(&unsafe { std::mem::zeroed() })
    }

    fn get_bytes<T: EmuStruct>(&self, obj: &T) -> Vec<u8> {
        obj.get_bytes()
    }

    fn mem_cast<T: EmuStruct>(&self, addr: u64) -> T {
        let struct_bytes = self.mem_read(addr, self.sizeof::<T>());
        T::cast(&struct_bytes)
    }

    // Telemetry Recording Stubs
    fn record_file_access_event(&mut self, path: &str, event_type: &str, handle: u64) {
        log::debug!("file_{}: {} (handle: {})", event_type, path, handle);
    }

    fn record_registry_access_event(&mut self, path: &str, event_type: &str) {
        log::debug!("reg_{}: {}", event_type, path);
    }

    fn record_network_event(&mut self, server: &str, port: u16, proto: &str) {
        log::debug!("net: {}:{} {}", server, port, proto);
    }

    fn record_http_event(&mut self, server: &str, port: u16) {
        log::debug!("http: {}:{}", server, port);
    }

    fn record_dns_event(&mut self, domain: &str, ip: &str) {
        log::debug!("dns: {} -> {}", domain, ip);
    }
}
