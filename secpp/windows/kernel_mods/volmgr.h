// volmgr.h  Volume Manager kernel module
//
// Maps to: speakeasy/windows/kernel_mods/volmgr.py
//
// Handles IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS by returning a
// single disk extent with fixed geometry.

#ifndef SPEAKEASY_VOLMGR_H
#define SPEAKEASY_VOLMGR_H

#include <string>
#include <vector>
#include <cstdint>
#include "kernel_mod.h"
#include "../../struct.h"

namespace speakeasy {

//  Disk extent structures 

struct DISK_EXTENT : EmuStruct {
    uint32_t DiskNumber = 0;
    uint64_t StartingOffset = 0;
    uint64_t ExtentLength = 0;

    size_t sizeof_obj() const override { return 4 + 8 + 8; }  // 20 bytes

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> buf(sizeof_obj());
        write_le(buf, 0, DiskNumber, 4);
        write_le(buf, 4, StartingOffset, 8);
        write_le(buf, 12, ExtentLength, 8);
        return buf;
    }
};

struct VOLUME_DISK_EXTENTS : EmuStruct {
    uint32_t NumberOfDiskExtents = 0;
    DISK_EXTENT Extents;  // typically 1

    size_t sizeof_obj() const override {
        return 4 + Extents.sizeof_obj();
    }

    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> buf(sizeof_obj());
        write_le(buf, 0, NumberOfDiskExtents, 4);
        auto ext_bytes = Extents.get_bytes();
        std::copy(ext_bytes.begin(), ext_bytes.end(), buf.begin() + 4);
        return buf;
    }
};

//  Volume Manager driver module 

class VolMgrModule : public KernelModBase {
public:
    VolMgrModule() : KernelModBase("volmgr") {}

    std::pair<uint32_t, std::vector<uint8_t>>
    ioctl(int arch, uint32_t code, const std::vector<uint8_t>& inbuf) override;
};

} // namespace speakeasy

#endif // SPEAKEASY_VOLMGR_H
