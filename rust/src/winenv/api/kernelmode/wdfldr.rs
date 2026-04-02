use crate::winenv::api::ApiHandler;
use crate::winenv::defs::wdf::WDF_BIND_INFO;

pub struct WdfldrHandler {
    version_major: u32,
    version_minor: u32,
}

impl WdfldrHandler {
    pub fn new() -> Self {
        Self {
            version_major: 1,
            version_minor: 33,
        }
    }

    pub fn wdf_version_bind(&self, bind_info: Option<&WDF_BIND_INFO>) -> u32 {
        if bind_info.is_some() {
            0
        } else {
            1
        }
    }

    pub fn wdf_version_unbind(&self) -> bool {
        true
    }

    pub fn get_version(&self) -> (u32, u32) {
        (self.version_major, self.version_minor)
    }
}

impl Default for WdfldrHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiHandler for WdfldrHandler {
    fn call(&mut self, args: &[u64]) -> u64 {
        match args.len() {
            0 => {
                let (major, minor) = self.get_version();
                ((major as u64) << 32) | minor as u64
            }
            1 => self.wdf_version_bind(None) as u64,
            2 => u64::from(self.wdf_version_unbind()),
            _ => 0,
        }
    }

    fn get_name(&self) -> &str {
        "Wdfldr"
    }
}
