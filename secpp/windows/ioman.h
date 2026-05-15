// ioman.h — I/O Manager for kernel emulation
//
// Maps to: speakeasy/windows/ioman.py
//
// Directs IO requests (ioctls) to registered kernel module handlers.
// Used by WinKernelEmulator to dispatch device IO control requests.

#ifndef SPEAKEASY_IOMAN_H
#define SPEAKEASY_IOMAN_H

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include "objman.h"

namespace speakeasy {

// Driver and Device are defined in objman.h (global scope)

/**
 * Interface for emulated kernel modules that handle IO requests.
 */
class KernelModule {
public:
    virtual ~KernelModule() = default;

    /** Return the module basename used for matching (e.g. "volmgr"). */
    virtual std::string get_mod_name() const = 0;

    /**
     * Handle a device IO control request.
     * @param arch   Architecture (32 or 64).
     * @param ioctl  The IO control code.
     * @param inbuf  Input buffer (raw bytes).
     * @return pair of (NTSTATUS, output buffer)
     */
    virtual std::pair<uint32_t, std::vector<uint8_t>>
    ioctl(int arch, uint32_t ioctl_code, const std::vector<uint8_t>& inbuf) = 0;
};

/**
 * Directs IO requests to a module handler. For example, if a user mode
 * application sends an ioctl to a device, this can be handled here.
 */
class IoManager {
public:
    IoManager();

    /**
     * Dispatch a device IO control request to the appropriate kernel module.
     * @return pair of (NTSTATUS, output buffer)
     */
    std::pair<uint32_t, std::vector<uint8_t>>
    dev_ioctl(int arch, Device* dev, uint32_t ioctl_code, const std::vector<uint8_t>& inbuf);

    /**
     * Register a kernel module.  Modules registered earlier take priority.
     */
    void register_module(std::unique_ptr<KernelModule> mod);

    /**
     * Get all registered kernel modules.
     */
    const std::vector<std::unique_ptr<KernelModule>>& get_modules() const { return emu_kmods_; }

private:
    std::vector<std::unique_ptr<KernelModule>> emu_kmods_;
};

} // namespace speakeasy

#endif // SPEAKEASY_IOMAN_H