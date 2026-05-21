// driveman.cpp
#include "driveman.h"
#include <algorithm>

// Drive type constants (from win32 kernel32 definitions)
constexpr int DRIVE_NO_ROOT_DIR = 1;
constexpr int DRIVE_REMOVABLE = 2;
constexpr int DRIVE_FIXED = 3;
constexpr int DRIVE_REMOTE = 4;
constexpr int DRIVE_CDROM = 5;
constexpr int DRIVE_RAMDISK = 6;

// DriveManager implementation
DriveManager::DriveManager(const std::vector<speakeasy::DriveEntry>& config)
    : drives(config) {
    
    // super(DriveManager, this).__init__() - Not needed in C++
    
    // Populate drive_letters
    for (const auto& drive : drives) {
        drive_letters.push_back(drive.root_path[0]);
    }
}

std::vector<speakeasy::DriveEntry>::const_iterator DriveManager::walk_drives() {
    return drives.cbegin();
}

const speakeasy::DriveEntry* DriveManager::get_drive(const std::string& root_path,
                                                            const std::string& volume_guid_path) {
    for (auto& drive : drives) {
        if (!root_path.empty()) {
            if (drive.root_path == root_path) {
                return &drive;
            }
        } else if (!volume_guid_path.empty()) {
            if (drive.volume_guid_path == volume_guid_path) {
                return &drive;
            }
        }
    }
    return nullptr;
}

int DriveManager::get_drive_type(const std::string& root_path) {
    const speakeasy::DriveEntry* drive = get_drive(root_path);
    if (drive) {
        // Look up the drive type value by name (equivalent to Python k32defs.get_define_value)
        const std::string& dt = drive->drive_type;
        if (dt == "DRIVE_REMOVABLE") return DRIVE_REMOVABLE;
        else if (dt == "DRIVE_FIXED") return DRIVE_FIXED;
        else if (dt == "DRIVE_REMOTE") return DRIVE_REMOTE;
        else if (dt == "DRIVE_CDROM") return DRIVE_CDROM;
        else if (dt == "DRIVE_RAMDISK") return DRIVE_RAMDISK;
        else return DRIVE_NO_ROOT_DIR;
    }
    
    return DRIVE_NO_ROOT_DIR;
}