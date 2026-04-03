// Drive Manager for Windows emulator

use crate::winenv::defs::windows::kernel32;

#[derive(Clone, Debug)]
pub struct Drive {
    pub root_path: Option<String>,
    pub volume_guid_path: Option<String>,
    pub drive_type: String,
}

pub struct DriveManager {
    pub drives: Vec<Drive>,
    pub drive_letters: Vec<char>,
}

impl DriveManager {
    pub fn new(config: Vec<Drive>) -> Self {
        let mut drive_letters = Vec::new();

        for drive in &config {
            if let Some(ref path) = drive.root_path {
                if let Some(c) = path.chars().next() {
                    drive_letters.push(c);
                }
            }
        }

        Self {
            drives: config,
            drive_letters,
        }
    }

    pub fn walk_drives(&self) -> impl Iterator<Item = &Drive> {
        self.drives.iter()
    }

    pub fn get_drive(&self, root_path: &str, volume_guid_path: &str) -> Option<&Drive> {
        for drive in &self.drives {
            if !root_path.is_empty() {
                if let Some(ref p) = drive.root_path {
                    if p == root_path {
                        return Some(drive);
                    }
                }
            } else if !volume_guid_path.is_empty() {
                if let Some(ref p) = drive.volume_guid_path {
                    if p == volume_guid_path {
                        return Some(drive);
                    }
                }
            }
        }
        None
    }

    pub fn get_drive_type(&self, root_path: &str) -> u32 {
        if let Some(drive) = self.get_drive(root_path, "") {
            match drive.drive_type.as_str() {
                "DRIVE_UNKNOWN" => kernel32::DRIVE_UNKNOWN,
                "DRIVE_NO_ROOT_DIR" => kernel32::DRIVE_NO_ROOT_DIR,
                "DRIVE_REMOVABLE" => kernel32::DRIVE_REMOVABLE,
                "DRIVE_FIXED" => kernel32::DRIVE_FIXED,
                "DRIVE_REMOTE" => kernel32::DRIVE_REMOTE,
                "DRIVE_CDROM" => kernel32::DRIVE_CDROM,
                "DRIVE_RAMDISK" => kernel32::DRIVE_RAMDISK,
                _ => kernel32::DRIVE_UNKNOWN,
            }
        } else {
            kernel32::DRIVE_NO_ROOT_DIR
        }
    }
}
