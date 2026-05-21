// driveman.h
#ifndef DRIVEMAN_H
#define DRIVEMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

#include "../winenv/arch.h"
#include "../config.h"

// Forward declarations
class DriveManager;

// Manages the emulation of Windows drives. Currently assumes one volume per drive.
class DriveManager {
private:
    const std::vector<speakeasy::DriveEntry>& drives;
    std::vector<char> drive_letters;

public:
    // Constructor
    DriveManager(const std::vector<speakeasy::DriveEntry>& config);
    
    // Methods
    std::vector<speakeasy::DriveEntry>::const_iterator walk_drives();
    const speakeasy::DriveEntry* get_drive(const std::string& root_path = "",
                                                  const std::string& volume_guid_path = "");
    int get_drive_type(const std::string& root_path);
};

#endif // DRIVEMAN_H