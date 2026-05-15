// kernel.cpp — Windows Kernel Emulator (stub implementation)

#include "kernel.h"

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
    constexpr int NonPagedPool   = 0;
    constexpr int PagedPool      = 1;
    constexpr int NonPagedPoolNx = 2;

    std::string pt = "unk";
    switch (pooltype) {
        case NonPagedPool:   pt = "NonPagedPool";   break;
        case PagedPool:      pt = "PagedPool";      break;
        case NonPagedPoolNx: pt = "NonPagedPoolNx"; break;
    }

    // TODO: call mem_map from base class
    uint64_t addr = 0;  // placeholder
    pool_allocs_.push_back({addr, pooltype, size, tag});
    return addr;
}

void* WinKernelEmulator::load_module(const std::string& path,
                                      const std::vector<uint8_t>& data,
                                      const std::string& filename) {
    (void)path; (void)data; (void)filename;
    // TODO: PeLoader integration
    return nullptr;
}

void WinKernelEmulator::setup() {
    bootstrap_object_services();
}

void WinKernelEmulator::bootstrap_object_services() {
    // TODO: init_processes, advance_bootstrap_phase
}

} // namespace speakeasy
