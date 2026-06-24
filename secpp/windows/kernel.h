// kernel.h  Windows Kernel Emulator
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

//  Constants 

constexpr uint32_t EP_DRIVER_ENTRY = 0x1B;
constexpr uint32_t EP_DRIVER_UNLOAD = 0x1C;
constexpr int KERNEL_MAX_EXPORTS = 10;
constexpr uint64_t SYSTEM_TIME_START = 131911108955110000ULL;

/**
 * Kernel-mode emulator.
 * Inherits from Win32Emulator (WindowsEmulator) + IoManager, matching Python:
 *   class WinKernelEmulator(WindowsEmulator, IoManager)
 * Win32Emulator base provides run_module/load_shellcode/run_shellcode needed by Speakeasy.
 * Handles driver loading, device objects, IRP dispatch, and pool allocation.
 */
class WinKernelEmulator : public Win32Emulator, public IoManager {
public:
    WinKernelEmulator(const speakeasy::SpeakeasyConfig& cfg, const std::vector<std::string>& argv = {},
                      bool debug = false, void* exit_event = nullptr);
    virtual ~WinKernelEmulator() = default;

    //  WindowsEmulator pure-virtual overrides 
    void on_run_complete() override;
    void on_emu_complete() override;
    void alloc_peb(std::shared_ptr<Process> proc) override {}

    //  System 
    uint64_t get_system_time() const { return system_time_; }
    std::shared_ptr<Process> get_system_process();
    int get_current_irql() const { return irql_; }
    void set_current_irql(int irql) { irql_ = irql; }

    //  Driver management 
    Driver* create_driver_object(const std::string& name = "", std::shared_ptr<speakeasy::RuntimeModule> pe = nullptr);
    std::vector<Driver*> get_drivers() const { return drivers_; }

    //  Module loading 
    std::shared_ptr<speakeasy::RuntimeModule> load_module(const std::string& path = "",
                      const std::vector<uint8_t>& data = {},
                      const std::string& filename = "");
    std::shared_ptr<speakeasy::RuntimeModule> load_driver(const std::string& path, std::vector<uint8_t> data = {},
                      const std::string& filename = "", bool builtin = false);

    //  I/O 
    void* create_device(Driver* drv, const std::string& name = "",
                        uint32_t dev_type = 0, uint32_t chars = 0);
    uint64_t ioctl(uint32_t ctl_code, void* in_buf, size_t in_len,
                   void* out_buf, size_t out_len);

    //  IRP dispatch 
    uint64_t irp_mj_create(void* drv, void* dev);
    uint64_t irp_mj_close(void* drv, void* dev);
    uint64_t irp_mj_read(void* drv, void* dev, void* buf, size_t len);
    uint64_t irp_mj_write(void* drv, void* dev, void* buf, size_t len);
    uint64_t irp_mj_device_control(void* drv, uint32_t ctl_code,
                                   void* in_buf, size_t in_len,
                                   void* out_buf, size_t out_len);

    //  Pool 
    uint64_t pool_alloc(int pooltype, size_t size, const std::string& tag = "None");
    void pool_free(uint64_t addr);
    uint64_t alloc_paged_pool(size_t size, const std::string& tag = "None");

    //  Object services
    void bootstrap_object_services();
    bool _hook_interrupt(void* emu, int intnum);
    void setup() override;

    //  Driver / IRP dispatch
    void add_symlink(const std::string& symlink, const std::string& devname);
    void init_sys_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config);
    void init_processes(const std::vector<speakeasy::ProcessEntry>& processes);
    void* create_device_object(const std::string& name = "", void* drv = nullptr,
                                size_t ext_size = 0, uint32_t devtype = 0,
                                uint32_t chars = 0, const std::string& tag = "");
    std::shared_ptr<Irp> new_irp();
    void driver_unload(Driver* drv);
    uint64_t next_driver_func(Driver* drv);
    void irp_mj_cleanup(Driver* drv, void* dev);
    void irp_mj_dev_io(Driver* drv, void* dev);
    void _set_entry_point_names();

    //  Kernel helpers
    uint64_t get_kernel_base();
    std::shared_ptr<speakeasy::RuntimeModule> get_kernel_mod();
    uint64_t get_ssdt_ptr();
    void setup_kernel_mode();
    void setup_msrs();
    void _call_driver_dispatch(uint64_t func, uint64_t dev_addr, uint64_t irp_addr);

private:
    uint64_t ssdt_ptr_ = 0;

private:
    bool kernel_mode_ = true;
    int irql_ = 0;
    uint64_t system_time_ = SYSTEM_TIME_START;
    // processes_ inherited from WindowsEmulator
    std::vector<Driver*> drivers_;
    std::vector<std::tuple<uint64_t, int, size_t, std::string>> pool_allocs_;
};

} // namespace speakeasy

#endif
