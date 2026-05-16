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
DriveManager::DriveManager(const std::vector<std::map<std::string, std::string>>& config) 
    : drives(config) {
    
    // super(DriveManager, this).__init__() - Not needed in C++
    
    // Populate drive_letters
    for (const auto& drive : drives) {
        auto root_path_it = drive.find("root_path");
        if (root_path_it != drive.end() && !root_path_it->second.empty()) {
            drive_letters.push_back(root_path_it->second[0]);
        }
    }
}

std::vector<std::map<std::string, std::string>>::iterator DriveManager::walk_drives() {
    // In C++, we return an iterator instead of using yield
    return drives.begin();
}

std::map<std::string, std::string>* DriveManager::get_drive(const std::string& root_path, 
                                                            const std::string& volume_guid_path) {
    for (auto& drive : drives) {
        if (!root_path.empty()) {
            auto config_root_path_it = drive.find("root_path");
            if (config_root_path_it != drive.end() && 
                config_root_path_it->second == root_path) {
                return &drive;
            }
        } else if (!volume_guid_path.empty()) {
            auto config_volume_guid_path_it = drive.find("volume_guid_path");
            if (config_volume_guid_path_it != drive.end() && 
                config_volume_guid_path_it->second == volume_guid_path) {
                return &drive;
            }
        }
    }
    return nullptr;
}

int DriveManager::get_drive_type(const std::string& root_path) {
    std::map<std::string, std::string>* drive = get_drive(root_path);
    if (drive) {
        auto config_root_path_it = drive->find("root_path");
        if (config_root_path_it != drive->end() && 
            config_root_path_it->second == root_path) {
            auto config_drive_type_it = drive->find("drive_type");
            if (config_drive_type_it != drive->end()) {
                // Look up the drive type value by name (equivalent to Python k32defs.get_define_value)
                const std::string& dt = config_drive_type_it->second;
                if (dt == "DRIVE_REMOVABLE") return DRIVE_REMOVABLE;
                else if (dt == "DRIVE_FIXED") return DRIVE_FIXED;
                else if (dt == "DRIVE_REMOTE") return DRIVE_REMOTE;
                else if (dt == "DRIVE_CDROM") return DRIVE_CDROM;
                else if (dt == "DRIVE_RAMDISK") return DRIVE_RAMDISK;
                else return DRIVE_NO_ROOT_DIR;
            }
        }
    }
    
    return DRIVE_NO_ROOT_DIR;
}