// kernel.cpp — Windows Kernel Emulator implementation

#include "kernel.h"
#include <cstring>
#include <algorithm>

namespace speakeasy {

WinKernelEmulator::WinKernelEmulator() {
    kernel_mode_ = true;
}

Process* WinKernelEmulator::get_system_process() {
    for (auto* ptr : processes_) {
        auto* proc = static_cast<Process*>(ptr);
        if (proc->get_pid() == 4) return proc;
    }
    return nullptr;
}

std::vector<void*> WinKernelEmulator::get_processes() {
    return processes_;
}

Driver* WinKernelEmulator::create_driver_object(const std::string& name,
                                                  void* pe) {
    auto drv = std::make_unique<Driver>(static_cast<void*>(this));
    drv->init_driver_object(name, pe, false);
    Driver* drv_ptr = drv.get();
    drivers_.push_back(drv_ptr);
    (void)drv.release();  // TODO: proper ownership
    return drv_ptr;
}

uint64_t WinKernelEmulator::pool_alloc(int pooltype, size_t size,
                                        const std::string& tag) {
    (void)pooltype; (void)tag;
    // TODO: call mem_map from base class
    uint64_t addr = 0;
    pool_allocs_.push_back({addr, pooltype, size, tag});
    return addr;
}

void WinKernelEmulator::pool_free(uint64_t addr) {
    for (auto it = pool_allocs_.begin(); it != pool_allocs_.end(); ++it) {
        if (std::get<0>(*it) == addr) {
            // TODO: call mem_unmap
            pool_allocs_.erase(it);
            return;
        }
    }
}

uint64_t WinKernelEmulator::alloc_paged_pool(size_t size, const std::string& tag) {
    return pool_alloc(1, size, tag);  // PagedPool = 1
}

void* WinKernelEmulator::load_module(const std::string& path,
                                      const std::vector<uint8_t>& data,
                                      const std::string& filename) {
    (void)path; (void)data; (void)filename;
    // TODO: use PeLoader to load .sys, then map into kernel space
    return nullptr;
}

void* WinKernelEmulator::load_driver(const std::string& path,
                                      std::vector<uint8_t> data,
                                      const std::string& filename,
                                      bool builtin) {
    (void)builtin;
    // TODO: full driver loading with EP_DRIVER_ENTRY dispatch
    if (!data.empty() || !path.empty()) {
        // PeLoader loader(path, data);
        // auto img = loader.make_image();
        // Driver* drv = create_driver_object(filename, ...);
        // auto* mod = load_image(&img);
        // Call DriverEntry
    }
    return nullptr;
}

void* WinKernelEmulator::create_device(Driver* drv, const std::string& name,
                                        uint32_t dev_type, uint32_t chars) {
    if (!drv) return nullptr;
    auto* dev = new Device(static_cast<void*>(this));
    dev->init_device(name, dev_type, chars, drv);
    drv->devices.push_back(dev);
    return dev;
}

uint64_t WinKernelEmulator::ioctl(uint32_t ctl_code, void* in_buf, size_t in_len,
                                   void* out_buf, size_t out_len) {
    (void)ctl_code; (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;
    // TODO: dispatch to the appropriate device's IRP handler
    return 0;
}

uint64_t WinKernelEmulator::irp_mj_create(void* drv, void* dev) {
    (void)drv; (void)dev;
    return 0;  // STATUS_SUCCESS
}

uint64_t WinKernelEmulator::irp_mj_close(void* drv, void* dev) {
    (void)drv; (void)dev;
    return 0;
}

uint64_t WinKernelEmulator::irp_mj_read(void* drv, void* dev, void* buf, size_t len) {
    (void)drv; (void)dev; (void)buf; (void)len;
    return 0;
}

uint64_t WinKernelEmulator::irp_mj_write(void* drv, void* dev, void* buf, size_t len) {
    (void)drv; (void)dev; (void)buf; (void)len;
    return 0;
}

uint64_t WinKernelEmulator::irp_mj_device_control(void* drv, uint32_t ctl_code,
                                                   void* in_buf, size_t in_len,
                                                   void* out_buf, size_t out_len) {
    (void)drv; (void)ctl_code; (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;
    return 0;
}

void WinKernelEmulator::bootstrap_object_services() {
    // TODO: init kernel object manager, load built-in kernel modules
}

bool WinKernelEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}

void WinKernelEmulator::setup() {
    // TODO: initialize kernel environment
}

void WinKernelEmulator::on_emu_complete() {
    // TODO: cleanup
}

} // namespace speakeasy
