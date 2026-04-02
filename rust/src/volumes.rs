use std::collections::HashMap;

// Handles mounting physical volumes into the emulator
pub struct VolumeMapping {
    pub mount_point: String,
    pub physical_path: String,
}

pub struct VolumeManager {
    volumes: HashMap<String, VolumeMapping>,
}

impl VolumeManager {
    pub fn new() -> Self {
        Self {
            volumes: HashMap::new(),
        }
    }

    pub fn map_volume(&mut self, mount_point: &str, physical_path: &str) {
        self.volumes.insert(mount_point.to_string(), VolumeMapping {
            mount_point: mount_point.to_string(),
            physical_path: physical_path.to_string(),
        });
    }

    pub fn get_mapping(&self, mount_point: &str) -> Option<&VolumeMapping> {
        self.volumes.get(mount_point)
    }
}
