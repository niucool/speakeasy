// kernel.h — Windows Kernel Emulator
//
// Maps to: speakeasy/windows/kernel.py

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

// ── IRP Major Function Codes ─────────────────────────────────

constexpr int IRP_MJ_CREATE                   = 0x00;
constexpr int IRP_MJ_CREATE_NAMED_PIPE        = 0x01;
constexpr int IRP_MJ_CLOSE                    = 0x02;
constexpr int IRP_MJ_READ                     = 0x03;
constexpr int IRP_MJ_WRITE                    = 0x04;
constexpr int IRP_MJ_QUERY_INFORMATION        = 0x05;
constexpr int IRP_MJ_SET_INFORMATION          = 0x06;
constexpr int IRP_MJ_QUERY_EA                 = 0x07;
constexpr int IRP_MJ_SET_EA                   = 0x08;
constexpr int IRP_MJ_FLUSH_BUFFERS            = 0x09;
constexpr int IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a;
constexpr int IRP_MJ_SET_VOLUME_INFORMATION   = 0x0b;
constexpr int IRP_MJ_DIRECTORY_CONTROL        = 0x0c;
constexpr int IRP_MJ_FILE_SYSTEM_CONTROL      = 0x0d;
constexpr int IRP_MJ_DEVICE_CONTROL           = 0x0e;
constexpr int IRP_MJ_INTERNAL_DEVICE_CONTROL  = 0x0f;
constexpr int IRP_MJ_SHUTDOWN                 = 0x10;
constexpr int IRP_MJ_LOCK_CONTROL             = 0x11;
constexpr int IRP_MJ_CLEANUP                  = 0x12;
constexpr int IRP_MJ_CREATE_MAILSLOT          = 0x13;
constexpr int IRP_MJ_QUERY_SECURITY           = 0x14;
constexpr int IRP_MJ_SET_SECURITY             = 0x15;
constexpr int IRP_MJ_POWER                    = 0x16;
constexpr int IRP_MJ_SYSTEM_CONTROL           = 0x17;
constexpr int IRP_MJ_DEVICE_CHANGE            = 0x18;
constexpr int IRP_MJ_QUERY_QUOTA              = 0x19;
constexpr int IRP_MJ_SET_QUOTA                = 0x1a;
constexpr int IRP_MJ_PNP                      = 0x1b;

/**
 * Kernel-mode emulator.
 * Handles driver loading, device objects, IRP dispatch, and pool allocation.
 */
class WinKernelEmulator : public IoManager {
public:
    WinKernelEmulator();
    virtual ~WinKernelEmulator() = default;

    // ── System ────────────────────────────────────────────────
    uint64_t get_system_time() const { return system_time_; }
    Process* get_system_process();
    std::vector<void*> get_processes();
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
    /**
     * Allocate paged pool.
     * Mapping from Python: `emu.alloc_paged_pool(size, tag)`
     */
    uint64_t alloc_paged_pool(size_t size, const std::string& tag = "None");

    // ── Object services ───────────────────────────────────────
    void bootstrap_object_services();
    bool _hook_interrupt(void* emu, int intnum);

    void setup();
    void on_emu_complete();

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
