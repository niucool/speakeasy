// volmgr.cpp — Volume Manager kernel module implementation

#include "volmgr.h"

namespace speakeasy {

std::pair<uint32_t, std::vector<uint8_t>>
VolMgrModule::ioctl(int arch, uint32_t code, const std::vector<uint8_t>& inbuf) {
    (void)inbuf;  // unused for this ioctl

    // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
    constexpr uint32_t IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000;
    constexpr uint32_t STATUS_SUCCESS = 0x00000000;
    constexpr uint32_t STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;

    if (code == IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) {
        VOLUME_DISK_EXTENTS vde;
        vde.NumberOfDiskExtents = 1;
        vde.Extents.DiskNumber = 0;
        vde.Extents.StartingOffset = 0;
        vde.Extents.ExtentLength = 0x1000;

        return {STATUS_SUCCESS, vde.get_bytes()};
    }

    return {STATUS_INVALID_DEVICE_REQUEST, {}};
}

// ── Module registry ──────────────────────────────────────────

std::vector<std::unique_ptr<KernelModule>> create_kernel_modules() {
    std::vector<std::unique_ptr<KernelModule>> mods;
    mods.push_back(std::make_unique<VolMgrModule>());
    return mods;
}

} // namespace speakeasy
