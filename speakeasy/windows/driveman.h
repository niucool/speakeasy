// driveman.h
#ifndef DRIVEMAN_H
#define DRIVEMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include "speakeasy/winenv/defs/windows/kernel32.h"

// Forward declarations
class DriveManager;

// Manages the emulation of Windows drives. Currently assumes one volume per drive.
class DriveManager {
private:
    std::vector<std::map<std::string, std::string>> drives;
    std::vector<char> drive_letters;

public:
    // Constructor
    DriveManager(const std::vector<std::map<std::string, std::string>>& config = {});
    
    // Methods
    std::vector<std::map<std::string, std::string>>::iterator walk_drives();
    std::map<std::string, std::string>* get_drive(const std::string& root_path = "", 
                                                  const std::string& volume_guid_path = "");
    int get_drive_type(const std::string& root_path);
};

#endif // DRIVEMAN_H