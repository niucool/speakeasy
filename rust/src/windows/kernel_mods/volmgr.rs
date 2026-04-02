// Volume Manager device
pub struct VolumeManager {
    pub name: String,
}

impl VolumeManager {
    pub fn new() -> Self {
        Self {
            name: "VolMgr".to_string(),
        }
    }
}

impl Default for VolumeManager {
    fn default() -> Self {
        Self::new()
    }
}
