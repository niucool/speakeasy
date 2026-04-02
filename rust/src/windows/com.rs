// COM Manager
use std::collections::HashMap;

pub struct ComInterface {
    pub name: String,
    pub address: u64,
    pub ptr_size: usize,
}

pub struct ComManager {
    clsids: HashMap<String, String>,
    progids: HashMap<String, String>,
    interfaces: HashMap<u64, ComInterface>,
}

impl ComManager {
    pub fn new() -> Self {
        Self {
            clsids: HashMap::new(),
            progids: HashMap::new(),
            interfaces: HashMap::new(),
        }
    }

    pub fn register_clsid(&mut self, clsid: &str, name: &str) {
        self.clsids.insert(clsid.to_string(), name.to_string());
    }

    pub fn get_name(&self, clsid: &str) -> Option<&String> {
        self.clsids.get(clsid)
    }

    pub fn register_progid(&mut self, progid: &str, clsid: &str) {
        self.progids.insert(progid.to_string(), clsid.to_string());
    }

    pub fn get_clsid_from_progid(&self, progid: &str) -> Option<&String> {
        self.progids.get(progid)
    }

    pub fn register_interface(&mut self, address: u64, iface: ComInterface) {
        self.interfaces.insert(address, iface);
    }

    pub fn get_interface(&self, address: u64) -> Option<&ComInterface> {
        self.interfaces.get(&address)
    }
}

impl Default for ComManager {
    fn default() -> Self {
        Self::new()
    }
}
