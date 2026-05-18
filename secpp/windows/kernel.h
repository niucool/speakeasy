// kernel.h — Windows Kernel Emulator
//
// Maps to: speakeasy/windows/kernel.py
// Python: class WinKernelEmulator(WindowsEmulator, IoManager):

#ifndef SPEAKEASY_KERNEL_H
#define SPEAKEASY_KERNEL_H

#include <string>
#include <vector>
#include <tuple>
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>

#include "win32.h"
#include "ioman.h"

namespace speakeasy {

// ── Constants ────────────────────────────────────────────────

constexpr uint32_t EP_DRIVER_ENTRY = 0x1B;
constexpr uint32_t EP_DRIVER_UNLOAD = 0x1C;
constexpr int KERNEL_MAX_EXPORTS = 10;
constexpr uint64_t SYSTEM_TIME_START = 131911108955110000ULL;

/**
 * Kernel-mode emulator.
 * Inherits from Win32Emulator (→WindowsEmulator) + IoManager, matching Python:
 *   class WinKernelEmulator(WindowsEmulator, IoManager)
 * Win32Emulator base provides run_module/load_shellcode/run_shellcode needed by Speakeasy.
 * Handles driver loading, device objects, IRP dispatch, and pool allocation.
 */
class WinKernelEmulator : public Win32Emulator, public IoManager {
public:
    WinKernelEmulator(const speakeasy::SpeakeasyConfig& cfg, const std::vector<std::string>& argv = {},
                      bool debug = false, void* logger = nullptr, void* exit_event = nullptr);
    virtual ~WinKernelEmulator() = default;

    // ── WindowsEmulator pure-virtual overrides ────────────────
    void on_run_complete() override;
    void on_emu_complete() override;
    void alloc_peb(Process* proc) override {}

    // ── System ────────────────────────────────────────────────
    uint64_t get_system_time() const { return system_time_; }
    Process* get_system_process();
    std::vector<void*> get_processes() { return processes_; }
    int get_current_irql() const { return irql_; }
    void set_current_irql(int irql) { irql_ = irql; }

    // ── Driver management ─────────────────────────────────────
    Driver* create_driver_object(const std::string& name = "", void* pe = nullptr);
    std::vector<Driver*> get_drivers() const { return drivers_; }

    // ── Module loading ────────────────────────────────────────
    void* load_module(const std::string& path = "",
                      const std::vector<uint8_t>& data = {},
                      const std::string& filename = "");
    void* load_driver(const std::string& path, std::vector<uint8_t> data = {},
                      const std::string& filename = "", bool builtin = false);

    // ── I/O ───────────────────────────────────────────────────
    void* create_device(Driver* drv, const std::string& name = "",
                        uint32_t dev_type = 0, uint32_t chars = 0);
    uint64_t ioctl(uint32_t ctl_code, void* in_buf, size_t in_len,
                   void* out_buf, size_t out_len);

    // ── IRP dispatch ──────────────────────────────────────────
    uint64_t irp_mj_create(void* drv, void* dev);
    uint64_t irp_mj_close(void* drv, void* dev);
    uint64_t irp_mj_read(void* drv, void* dev, void* buf, size_t len);
    uint64_t irp_mj_write(void* drv, void* dev, void* buf, size_t len);
    uint64_t irp_mj_device_control(void* drv, uint32_t ctl_code,
                                   void* in_buf, size_t in_len,
                                   void* out_buf, size_t out_len);

    // ── Pool ──────────────────────────────────────────────────
    uint64_t pool_alloc(int pooltype, size_t size, const std::string& tag = "None");
    void pool_free(uint64_t addr);
    uint64_t alloc_paged_pool(size_t size, const std::string& tag = "None");

    // ── Object services ───────────────────────────────────────
    void bootstrap_object_services();
    bool _hook_interrupt(void* emu, int intnum);
    void setup();

private:
    bool kernel_mode_ = true;
    int irql_ = 0;
    uint64_t system_time_ = SYSTEM_TIME_START;
    std::vector<void*> processes_;
    std::vector<Driver*> drivers_;
    std::vector<std::tuple<uint64_t, int, size_t, std::string>> pool_allocs_;
};

} // namespace speakeasy

#endif
