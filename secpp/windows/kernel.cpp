// kernel.cpp — Windows Kernel Emulator implementation
//
// Maps to: speakeasy/windows/kernel.py
// Python: class WinKernelEmulator(WindowsEmulator, IoManager):

#include "kernel.h"
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include "loaders.h"

namespace speakeasy {

WinKernelEmulator::WinKernelEmulator(const speakeasy::SpeakeasyConfig& cfg,
                                     const std::vector<std::string>& argv,
                                     bool debug, void* logger, void* exit_event)
    : Win32Emulator(cfg, argv, debug, logger, exit_event),
      IoManager() {
    kernel_mode_ = true;
}

std::shared_ptr<Process> WinKernelEmulator::get_system_process() {
    for (auto& proc : processes_) {
        if (proc->get_pid() == 4) return proc;
    }
    // Create SYSTEM process (PID 4)
    auto proc = std::make_shared<Process>(static_cast<void*>(this));
    proc->set_id(4);
    processes_.push_back(proc);
    return proc;
}

Driver* WinKernelEmulator::create_driver_object(const std::string& name, std::shared_ptr<speakeasy::RuntimeModule> pe) {
    auto drv = std::make_unique<Driver>(static_cast<void*>(this));
    drv->init_driver_object(name, pe, false);
    Driver* drv_ptr = drv.get();
    drivers_.push_back(drv_ptr);
    (void)drv.release();
    return drv_ptr;
}

uint64_t WinKernelEmulator::pool_alloc(int pooltype, size_t size, const std::string& tag) {
    std::string pt;
    if (pooltype == 0)         pt = "NonPagedPool";
    else if (pooltype == 1)    pt = "PagedPool";
    else if (pooltype == 2)    pt = "NonPagedPoolNx";
    else                       pt = "unk";
    std::string mem_tag = "api.pool." + pt + "." + tag;
    std::shared_ptr<Process> system_proc = get_system_process();
    uint64_t addr = static_cast<MemoryManager*>(this)->mem_map(size, 0, PERM_MEM_RWX, mem_tag, 0, false, system_proc);
    pool_allocs_.push_back({addr, pooltype, size, tag});
    return addr;
}

void WinKernelEmulator::pool_free(uint64_t addr) {
    for (auto it = pool_allocs_.begin(); it != pool_allocs_.end(); ++it) {
        if (std::get<0>(*it) == addr) {
            size_t size = std::get<2>(*it);
            if (addr != 0) mem_unmap(addr, size);
            pool_allocs_.erase(it);
            return;
        }
    }
}

uint64_t WinKernelEmulator::alloc_paged_pool(size_t size, const std::string& tag) {
    return pool_alloc(1, size, tag);
}

std::shared_ptr<speakeasy::RuntimeModule> WinKernelEmulator::load_module(const std::string& path,
                                     const std::vector<uint8_t>& data,
                                     const std::string& filename) {
    std::vector<uint8_t> buf = data;
    if (buf.empty() && !path.empty()) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return nullptr;
        size_t fsize = static_cast<size_t>(file.tellg());
        file.seekg(0);
        buf.resize(fsize);
        file.read(reinterpret_cast<char*>(buf.data()), fsize);
    }
    if (buf.empty()) return nullptr;

    std::string file_name, mod_name;
    if (!filename.empty()) {
        file_name = filename;
        auto pos = file_name.rfind('/');
        if (pos == std::string::npos) pos = file_name.rfind('\\');
        if (pos != std::string::npos) file_name = file_name.substr(pos + 1);
        auto dot = file_name.rfind('.');
        mod_name = (dot != std::string::npos) ? file_name.substr(0, dot) : file_name;
    } else if (!path.empty()) {
        file_name = path;
        auto pos = path.rfind('/');
        if (pos == std::string::npos) pos = path.rfind('\\');
        if (pos != std::string::npos) file_name = path.substr(pos + 1);
        auto dot = file_name.rfind('.');
        mod_name = (dot != std::string::npos) ? file_name.substr(0, dot) : file_name;
    } else {
        mod_name = "loaded_module";
        file_name = "loaded_module.sys";
    }

    PeLoader loader(path, buf);
    auto img = loader.make_image();
    img->name = mod_name;
    img->emu_path = "\\\\??\\\\" + path;

    auto rtmod = load_image(img);
    return rtmod;
}

std::shared_ptr<speakeasy::RuntimeModule> WinKernelEmulator::load_driver(const std::string& path,
                                     std::vector<uint8_t> data,
                                     const std::string& filename,
                                     bool builtin) {
    (void)builtin;

    std::vector<uint8_t> parsedata = data;
    if (parsedata.empty() && !path.empty()) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (file) {
            size_t fsize = static_cast<size_t>(file.tellg());
            file.seekg(0);
            parsedata.resize(fsize);
            file.read(reinterpret_cast<char*>(parsedata.data()), fsize);
        }
    }

    auto mod = load_module(path, data, filename);
    if (!mod) return nullptr;

    std::string drv_name = filename.empty() ? path : filename;
    Driver* drv = create_driver_object(drv_name, mod);

    PeLoader loader(path, parsedata);
    auto img = loader.make_image();

    uint64_t base = mod->base;
    drv->driver_init_addr = base + img->ep;
    drv->driver_unload_addr = 0;
    return mod;
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
    (void)out_buf; (void)out_len;
    if (!in_buf) return 0;

    const uint8_t* raw = static_cast<const uint8_t*>(in_buf);
    std::vector<uint8_t> invec(raw, raw + in_len);
    int arch = get_arch();

    for (auto* drv : drivers_) {
        if (drv->devices.empty()) continue;
        for (auto* dev_ptr : drv->devices) {
            auto* dev = static_cast<Device*>(dev_ptr);
            auto result = IoManager::dev_ioctl(arch, dev, ctl_code, invec);
            auto status = result.first;
            (void)status; (void)result;
            if (status == 0) return 0;
        }
    }
    return 0;
}

// IRP stubs
uint64_t WinKernelEmulator::irp_mj_create(void* drv, void* dev) { (void)drv; (void)dev; return 0; }
uint64_t WinKernelEmulator::irp_mj_close(void* drv, void* dev) { (void)drv; (void)dev; return 0; }
uint64_t WinKernelEmulator::irp_mj_read(void* drv, void* dev, void* buf, size_t len) { (void)drv; (void)dev; (void)buf; (void)len; return 0; }
uint64_t WinKernelEmulator::irp_mj_write(void* drv, void* dev, void* buf, size_t len) { (void)drv; (void)dev; (void)buf; (void)len; return 0; }
uint64_t WinKernelEmulator::irp_mj_device_control(void* drv, uint32_t ctl_code, void* in_buf, size_t in_len, void* out_buf, size_t out_len) {
    (void)drv; (void)ctl_code; (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;
    return 0;
}

void WinKernelEmulator::bootstrap_object_services() {
    if (processes_.empty()) {
        auto sys_proc = std::make_shared<Process>(static_cast<void*>(this));
        sys_proc->set_id(4);
        processes_.push_back(sys_proc);
        Thread sys_thread(static_cast<void*>(this));
        sys_proc->threads.push_back(sys_thread);
    }
    advance_bootstrap_phase(BootstrapPhase::OBJECT_MANAGER_READY);
}

bool WinKernelEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}

void WinKernelEmulator::setup() {
    bootstrap_object_services();
    int arch = get_arch();
    _setup_gdt(arch);
    setup_user_shared_data();
    kernel_mode_ = true;
}

void WinKernelEmulator::on_run_complete() {
    run_complete = true;
}

void WinKernelEmulator::on_emu_complete() {
    // Free pool allocations
    for (auto& alloc : pool_allocs_) {
        uint64_t addr = std::get<0>(alloc);
        size_t size = std::get<2>(alloc);
        if (addr != 0) mem_unmap(addr, size);
    }
    pool_allocs_.clear();

    // Free drivers
    for (auto* drv : drivers_) delete drv;
    drivers_.clear();

    // Clear process list (automatically cleaned up by std::shared_ptr)
    processes_.clear();
}

} // namespace speakeasy
