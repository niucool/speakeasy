// kernel.h — Windows Kernel Emulator (stub)
//
// Maps to: speakeasy/windows/kernel.py
//
// NOTE: Full WinKernelEmulator integration requires winemu.h +
// BinaryEmulator dependency chain to be completed (Phase 4).
// This header provides the class skeleton and constants.

#ifndef SPEAKEASY_KERNEL_H
#define SPEAKEASY_KERNEL_H

#include <string>
#include <vector>
#include <tuple>
#include <memory>
#include <cstdint>

#include "ioman.h"
#include "objman.h"

namespace speakeasy {

// ── Constants ────────────────────────────────────────────────

constexpr uint32_t EP_DRIVER_ENTRY = 0x1B;
constexpr uint32_t EP_DRIVER_UNLOAD = 0x1C;
constexpr int KERNEL_MAX_EXPORTS = 10;
constexpr uint64_t SYSTEM_TIME_START = 131911108955110000ULL;

// ── WinKernelEmulator ────────────────────────────────────────

/**
 * Stub for the kernel-mode emulator.
 *
 * TODO: Inherit from WindowsEmulator + IoManager once winemu.h
 * dependency chain is resolved (Phase 4).
 */
class WinKernelEmulator : public IoManager {
public:
    WinKernelEmulator();
    virtual ~WinKernelEmulator() = default;

    uint64_t get_system_time() const { return system_time_; }

    Process* get_system_process();
    std::vector<void*> get_processes();

    int get_current_irql() const { return irql_; }
    void set_current_irql(int irql) { irql_ = irql; }

    Driver* create_driver_object(const std::string& name = "",
                                 void* pe = nullptr);
    uint64_t pool_alloc(int pooltype, size_t size,
                        const std::string& tag = "None");

    void* load_module(const std::string& path = "",
                      const std::vector<uint8_t>& data = {},
                      const std::string& filename = "");

    void setup();
    void bootstrap_object_services();

private:
    bool kernel_mode_ = true;
    int irql_ = 0;
    uint64_t system_time_ = SYSTEM_TIME_START;
    std::vector<void*> processes_;
    std::vector<Driver*> drivers_;
    std::vector<std::tuple<uint64_t, int, size_t, std::string>> pool_allocs_;
};

} // namespace speakeasy

#endif // SPEAKEASY_KERNEL_H
