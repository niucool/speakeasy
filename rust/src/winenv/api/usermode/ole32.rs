use crate::winenv::api::ApiHandler;

const S_OK: u32 = 0;

pub struct Ole32Handler {
    initialized: bool,
}

impl Ole32Handler {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    pub fn co_initialize(&mut self) -> u32 {
        self.initialized = true;
        S_OK
    }

    pub fn co_uninitialize(&mut self) {
        self.initialized = false;
    }

    pub fn co_create_instance(&self, clsid: &str, iid: &str) -> u32 {
        if self.initialized && !clsid.is_empty() && !iid.is_empty() {
            S_OK
        } else {
            1
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for Ole32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Ole32Handler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => self.co_initialize() as u64,
            1 => {
                self.co_uninitialize();
                0
            }
            2 => self.co_create_instance("CLSID", "IID") as u64,
            _ => u64::from(self.is_initialized()),
        }
    }

    fn get_name(&self) -> &str {
        "Ole32"
    }
}
