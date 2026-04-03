use crate::binemu::BinaryEmulator;
use crate::winenv::api::ApiHandler;

const S_OK: u32 = 0;

pub struct Ole32Handler {
    initialized: bool,
}

impl Ole32Handler {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    fn co_initialize(&mut self) -> u32 {
        self.initialized = true;
        S_OK
    }

    fn co_uninitialize(&mut self) {
        self.initialized = false;
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for Ole32Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for Ole32Handler {
    fn call(
        &mut self,
        _emu: &mut dyn BinaryEmulator,
        name: &str,
        _args: &[u64],
    ) -> crate::winenv::api::Result<u64> {
        match name {
            "CoInitializeEx" | "CoInitialize" => Ok(self.co_initialize() as u64),
            "CoUninitialize" => {
                self.co_uninitialize();
                Ok(0)
            }
            _ => Ok(u64::from(self.is_initialized())),
        }
    }

    fn get_name(&self) -> &str {
        "Ole32"
    }
}
