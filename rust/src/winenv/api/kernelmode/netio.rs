use crate::winenv::api::ApiHandler;

pub struct NetioHandler {
    compartment_id: u32,
}

impl NetioHandler {
    pub fn new() -> Self {
        Self { compartment_id: 1 }
    }

    pub fn get_default_compartment_id(&self) -> u32 {
        self.compartment_id
    }

    pub fn set_compartment_id(&mut self, compartment_id: u32) -> u32 {
        let previous = self.compartment_id;
        self.compartment_id = compartment_id;
        previous
    }

    pub fn is_network_alive(&self) -> bool {
        true
    }
}

impl Default for NetioHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for NetioHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.get_default_compartment_id() as u64,
            1 => self.set_compartment_id(args[0] as u32) as u64,
            2 => u64::from(self.is_network_alive()),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Netio"
    }
}
