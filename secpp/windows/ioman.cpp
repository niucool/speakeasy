// ioman.cpp — I/O Manager implementation

#include "ioman.h"
#include "objman.h"   // for Driver, Device

namespace speakeasy {

IoManager::IoManager() {
    // Kernel modules are registered by subclasses (WinKernelEmulator)
}

void IoManager::register_module(std::unique_ptr<KernelModule> mod) {
    emu_kmods_.push_back(std::move(mod));
}

std::pair<uint32_t, std::vector<uint8_t>>
IoManager::dev_ioctl(int arch, Device* dev, uint32_t ioctl_code,
                     const std::vector<uint8_t>& inbuf) {
    // STATUS_INVALID_DEVICE_REQUEST
    const uint32_t STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;

    if (!dev) {
        return {STATUS_INVALID_DEVICE_REQUEST, {}};
    }

    // Get parent driver for the device
    void* drv = dev->get_parent_driver();
    if (!drv) {
        return {STATUS_INVALID_DEVICE_REQUEST, {}};
    }

    // Find the matching kernel module by driver basename
    auto* driver = static_cast<Driver*>(drv);
    std::string bn = driver->get_basename();

    for (const auto& mod : emu_kmods_) {
        if (bn == mod->get_mod_name()) {
            return mod->ioctl(arch, ioctl_code, inbuf);
        }
    }

    return {STATUS_INVALID_DEVICE_REQUEST, {}};
}

} // namespace speakeasy
