// kernel_mod.h  Kernel module base class (concrete stub)
//
// Maps to: speakeasy/windows/kernel_mods/kernel_mod.py
//
// Provides a minimal concrete base for kernel-mode driver modules.
// The abstract interface is KernelModule in ioman.h.

#ifndef SPEAKEASY_KERNEL_MOD_H
#define SPEAKEASY_KERNEL_MOD_H

#include <string>
#include <vector>
#include <cstdint>
#include "../ioman.h"

namespace speakeasy {

/**
 * Minimal concrete base for kernel driver modules.
 * Subclasses override ioctl() to handle driver-specific IO control codes.
 */
class KernelModBase : public KernelModule {
public:
    KernelModBase() : name_("") {}
    explicit KernelModBase(const std::string& name) : name_(name) {}

    std::string get_mod_name() const override {
        return name_;
    }

    std::pair<uint32_t, std::vector<uint8_t>>
    ioctl(int /*arch*/, uint32_t /*code*/, const std::vector<uint8_t>& /*inbuf*/) override {
        // Default: STATUS_NOT_IMPLEMENTED
        return {0xC0000002, {}};
    }

protected:
    std::string name_;
};

/**
 * Registry of available kernel modules (maps to _get_kmods()).
 */
std::vector<std::unique_ptr<KernelModule>> create_kernel_modules();

} // namespace speakeasy

#endif // SPEAKEASY_KERNEL_MOD_H
