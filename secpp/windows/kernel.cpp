// kernel.cpp — Windows Kernel Emulator implementation

#include "kernel.h"
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>

namespace speakeasy {

WinKernelEmulator::WinKernelEmulator(WindowsEmulator* emu)
    : IoManager(), emu_(emu) {
    kernel_mode_ = true;
}

Process* WinKernelEmulator::get_system_process() {
    for (auto* ptr : processes_) {
        auto* proc = static_cast<Process*>(ptr);
        if (proc->get_pid() == 4) return proc;
    }
    // If no system process exists yet, create one
    if (emu_) {
        auto* proc = new Process(static_cast<void*>(emu_));
        proc->set_id(4);
        processes_.push_back(static_cast<void*>(proc));
        return proc;
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
    // Transfer ownership — drivers_ owns the pointer
    (void)drv.release();
    return drv_ptr;
}

uint64_t WinKernelEmulator::pool_alloc(int pooltype, size_t size,
                                        const std::string& tag) {
    // Determine pool type string (matching Python kernel.py logic)
    std::string pt;
    if (pooltype == 0)         pt = "NonPagedPool";
    else if (pooltype == 1)    pt = "PagedPool";
    else if (pooltype == 2)    pt = "NonPagedPoolNx";
    else                       pt = "unk";

    std::string mem_tag = "api.pool." + pt + "." + tag;

    // Get system process for the allocation context
    Process* system_proc = get_system_process();

    // Allocate memory via the emulator's memory manager
    uint64_t addr = 0;
    if (emu_) {
        addr = emu_->mem_map(size, 0, PERM_MEM_RWX, mem_tag, 0, false, system_proc);
    }

    pool_allocs_.push_back({addr, pooltype, size, tag});
    return addr;
}

void WinKernelEmulator::pool_free(uint64_t addr) {
    for (auto it = pool_allocs_.begin(); it != pool_allocs_.end(); ++it) {
        if (std::get<0>(*it) == addr) {
            size_t size = std::get<2>(*it);
            // Free the mapped memory region
            if (emu_ && addr != 0) {
                emu_->mem_unmap(addr, size);
            }
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
    // Load a kernel module (.sys) into the emulator address space.
    // Uses PeLoader to parse the PE and load_image to map it.
    if (!emu_) return nullptr;

    std::vector<uint8_t> buf = data;

    // If no data but path is given, read the file
    if (buf.empty() && !path.empty()) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return nullptr;
        size_t fsize = static_cast<size_t>(file.tellg());
        file.seekg(0);
        buf.resize(fsize);
        file.read(reinterpret_cast<char*>(buf.data()), fsize);
    }

    if (buf.empty()) return nullptr;

    // Derive module name and file name (matching Python load_module logic)
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

    // Construct PeLoader and call load_image (matching Python:
    //   loader = PeLoader(path=path, data=data)
    //   image = loader.make_image()
    //   image.name = mod_name
    //   image.emu_path = emu_path
    //   rtmod = self.load_image(image))
    speakeasy::PeLoader loader(path, buf);
    auto img = loader.make_image();
    img.name = mod_name;
    img.emu_path = "\\??\\" + path;

    void* rtmod = emu_->load_image(&img);
    return rtmod;
}

void* WinKernelEmulator::load_driver(const std::string& path,
                                      std::vector<uint8_t> data,
                                      const std::string& filename,
                                      bool builtin) {
    // Full driver loading: parse PE, create driver object, map image,
    // and set up DriverInit (entry point) and DriverUnload.
    (void)builtin;

    if (!emu_) return nullptr;

    // Ensure we have data for PE parsing in case data was empty
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

    // Load the module first (may re-read the file if data is empty)
    void* mod = load_module(path, data, filename);
    if (!mod) return nullptr;

    // Create a driver object for this module
    std::string drv_name = filename.empty() ? path : filename;
    Driver* drv = create_driver_object(drv_name, mod);

    // Set up driver entry point and unload routine
    // Parse the loaded module's PE header to find DriverInit
    // and DriverUnload (initially NULL).
    // Reference Python:
    //   drvobj.DriverInit = pe.base + pe.ep
    //   drvobj.DriverUnload = pe.base + pe.unload  (initially 0)
    speakeasy::PeLoader loader(path, parsedata);
    auto img = loader.make_image();

    uint64_t base = reinterpret_cast<uint64_t>(mod);
    drv->driver_init_addr = base + img.ep;
    drv->driver_unload_addr = 0;  // DriverUnload is NULL initially;
                                  // set by driver during execution via DRIVER_OBJECT write-back

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
    // Dispatch the IOCTL to the appropriate device's IRP handler
    // via the IoManager framework
    (void)out_buf; (void)out_len;

    if (!emu_ || !in_buf) return 0;

    // Convert input buffer to vector
    const uint8_t* raw = static_cast<const uint8_t*>(in_buf);
    std::vector<uint8_t> invec(raw, raw + in_len);

    // Get the arch and dispatch through IoManager's dev_ioctl
    int arch = emu_->get_arch();

    // Try all drivers to find who handles this ioctl
    for (auto* drv : drivers_) {
        if (drv->devices.empty()) continue;
        for (auto* dev_ptr : drv->devices) {
            auto* dev = static_cast<Device*>(dev_ptr);
            auto [status, outvec] = dev_ioctl(arch, dev, ctl_code, invec);
            (void)outvec;
            if (status == 0) {  // STATUS_SUCCESS
                return 0;
            }
        }
    }

    return 0;  // STATUS_SUCCESS
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
    // Initialize kernel object manager and load built-in kernel modules
    if (!emu_) return;

    // WindowsEmulator already has an ObjectManager (om member)
    // Bootstrap processes if not already done
    if (processes_.empty()) {
        // Create the SYSTEM process (PID 4)
        auto* sys_proc = new Process(static_cast<void*>(emu_));
        sys_proc->set_id(4);
        processes_.push_back(static_cast<void*>(sys_proc));

        // Create an initial thread for the system process
        Thread sys_thread(static_cast<void*>(emu_));
        sys_proc->threads.push_back(sys_thread);
    }

    // Advance the bootstrap phase through the emulator
    emu_->advance_bootstrap_phase(BootstrapPhase::OBJECT_MANAGER_READY);
}

bool WinKernelEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}

void WinKernelEmulator::setup() {
    // Initialize the full kernel emulation environment
    bootstrap_object_services();

    if (!emu_) return;

    // Set up GDT for kernel-mode execution
    int arch = emu_->get_arch();
    emu_->_setup_gdt(arch);

    // Set up kernel-mode shared data
    emu_->setup_user_shared_data();

    // Mark kernel mode
    kernel_mode_ = true;
}

void WinKernelEmulator::on_emu_complete() {
    // Cleanup: free all pool allocations, release drivers
    for (auto& alloc : pool_allocs_) {
        uint64_t addr = std::get<0>(alloc);
        size_t size = std::get<2>(alloc);
        if (emu_ && addr != 0) {
            emu_->mem_unmap(addr, size);
        }
    }
    pool_allocs_.clear();

    // Free drivers (transfer ownership via unique_ptr wrappers)
    for (auto* drv : drivers_) {
        delete drv;
    }
    drivers_.clear();

    // Clear process list
    for (auto* proc : processes_) {
        delete static_cast<Process*>(proc);
    }
    processes_.clear();
}

} // namespace speakeasy
