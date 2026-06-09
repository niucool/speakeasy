// kernel.cpp  Windows Kernel Emulator implementation
//
// Maps to: speakeasy/windows/kernel.py
// Python: class WinKernelEmulator(WindowsEmulator, IoManager):

#include "kernel.h"
#include "objman.h"
#include "../errors.h"
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include "loaders.h"

namespace speakeasy {

WinKernelEmulator::WinKernelEmulator(const speakeasy::SpeakeasyConfig& cfg,
                                     const std::vector<std::string>& argv,
                                     bool debug, void* exit_event)
    : Win32Emulator(cfg, argv, debug, exit_event),
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
    // Python kernel.py:68-85 — creates driver, registers with object manager
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
    // Python kernel.py:87-94
    if (!om) om = std::make_shared<ObjectManager>(static_cast<void*>(this));
    if (processes_.empty())
        init_processes(config_.processes);
    advance_bootstrap_phase(BootstrapPhase::OBJECT_MANAGER_READY);
}

bool WinKernelEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}

void WinKernelEmulator::setup() {
    // Python kernel.py:96-101
    bootstrap_object_services();
    int arch = get_arch();
    _setup_gdt(arch);
    init_sys_modules(config_.modules.system_modules);
    setup_kernel_mode();
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

//
//  Driver / IRP dispatch (ported from kernel.py)
//

void WinKernelEmulator::add_symlink(const std::string& symlink, const std::string& devname) {
    if (om) om->add_symlink(symlink, devname);
}

std::shared_ptr<Irp> WinKernelEmulator::new_irp() {
    return std::make_shared<Irp>(static_cast<void*>(this));
}

void WinKernelEmulator::driver_unload(Driver* drv) {
    if (!drv) return;
    if (drv->driver_unload_addr) {
        uint64_t dev_addr = drv->devices.empty() ? 0 : reinterpret_cast<uint64_t>(drv->devices[0]);
        _call_driver_dispatch(drv->driver_unload_addr, dev_addr, new_irp()->get_address());
    }
    auto it = std::find(drivers_.begin(), drivers_.end(), drv);
    if (it != drivers_.end()) drivers_.erase(it);
}

uint64_t WinKernelEmulator::next_driver_func(Driver* drv) {
    if (!drv) return 0;
    return drv->driver_init_addr ? drv->driver_init_addr : drv->driver_unload_addr;
}

void WinKernelEmulator::irp_mj_cleanup(Driver* drv, void* dev) { (void)drv; (void)dev; }
void WinKernelEmulator::irp_mj_dev_io(Driver* drv, void* dev)   { (void)drv; (void)dev; }

void WinKernelEmulator::_call_driver_dispatch(uint64_t func, uint64_t dev_addr, uint64_t irp_addr) {
    if (!func) return;
    set_func_args(get_stack_ptr(), func, {dev_addr, irp_addr});
    call(func);
}

void WinKernelEmulator::_set_entry_point_names() {
    for (auto& proc : processes_)
        if (proc && proc->pe)
            for (auto& exp : proc->pe->get_exports())
                if (exp.ordinal == 1) { proc->title = exp.name; break; }
}

uint64_t WinKernelEmulator::get_kernel_base() {
    auto mod = get_mod_by_name("ntoskrnl");
    return mod ? mod->base : 0x80000000;
}

std::shared_ptr<speakeasy::RuntimeModule> WinKernelEmulator::get_kernel_mod() {
    // Python kernel.py:555-562 — returns the kernel RuntimeModule (not a string)
    auto mod = get_mod_by_name("ntoskrnl");
    if (!mod) throw KernelEmuError("Failed to get kernel base");
    return mod;
}

uint64_t WinKernelEmulator::get_ssdt_ptr() {
    return ssdt_ptr_;
}

void WinKernelEmulator::setup_kernel_mode() {
    // Python kernel.py:591-611 — creates IDT, SSDT, configures MSRs and symlinks.
    auto idt = std::make_shared<IDT>(static_cast<void*>(this));
    idt->init_descriptors();

    // Setup the SSDT (System Service Descriptor Table)
    int ptr_sz = get_ptr_size();
    size_t ssdt_size = static_cast<size_t>(ptr_sz) * 256 + static_cast<size_t>(ptr_sz) * 2;
    ssdt_ptr_ = mem_map(ssdt_size, 0, PERM_MEM_RW, "api.struct.SSDT");
    uint64_t tbl_size = static_cast<uint64_t>(ptr_sz) * 256;
    uint64_t ssdt_base = ssdt_ptr_ + static_cast<uint64_t>(ptr_sz) * 2;
    std::vector<uint8_t> ssdt_bytes(static_cast<size_t>(ptr_sz) * 2, 0);
    write_le(ssdt_bytes, 0, ssdt_base, static_cast<size_t>(ptr_sz));
    write_le(ssdt_bytes, static_cast<size_t>(ptr_sz), tbl_size, static_cast<size_t>(ptr_sz));
    mem_write(ssdt_ptr_, ssdt_bytes);

    setup_msrs();

    if (om) {
        for (auto& sl : config_.symlinks)
            om->add_symlink(sl.name, sl.target);
    }
}

void WinKernelEmulator::init_sys_modules(const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config) {
    // Python kernel.py:157-171 — calls super, creates driver objects for driver configs
    auto sysmods = WindowsEmulator::init_sys_modules(modules_config);
    for (auto& mcp : modules_config) {
        auto sm = std::dynamic_pointer_cast<SystemModule>(mcp);
        if (!sm) continue;
        if (sm->driver.name.empty()) continue;
        auto it = std::find_if(sysmods.begin(), sysmods.end(),
            [&](auto& m) { return m->name == sm->name; });
        if (it == sysmods.end()) continue;
        auto mod = *it;
        create_driver_object(sm->driver.name, mod);
    }
}

void WinKernelEmulator::init_processes(const std::vector<speakeasy::ProcessEntry>& processes) {
    // Python kernel.py:181-214
    for (auto& pe : processes) {
        auto p = std::make_shared<Process>(static_cast<void*>(this));
        if (om) om->add_object(p);
        p->set_obj_name(pe.name);
        p->set_id(pe.pid);
        if (speakeasy::to_lower(p->get_obj_name()) == "system") {
            p->set_id(4);
            p->path = "System";
        }
        if (!p->get_id()) p->set_id(static_cast<int>(KernelObject::curr_id));
        try { p->base = static_cast<uint64_t>(std::stoull(pe.base, nullptr, 16)); } catch (...) { p->base = 0; }
        if (p->path.empty()) p->path = pe.path;
        auto t = std::make_shared<Thread>(static_cast<void*>(this));
        if (om) om->add_object(t);
        t->set_process(p);
        p->threads.push_back(t);
        processes_.push_back(p);
    }
    for (auto& p : processes_) {
        if (speakeasy::to_lower(p->get_obj_name()) == "system") {
            set_current_process(p);
            break;
        }
    }
}

void* WinKernelEmulator::create_device_object(const std::string& name, void* drv,
                                               size_t ext_size, uint32_t devtype,
                                               uint32_t chars, const std::string& tag) {
    // Python kernel.py:308-365 — full device object creation with linked list
    auto dev = std::make_shared<Device>(static_cast<void*>(this));
    size_t alloc_size = ext_size + dev->sizeof_obj();
    std::string devname = name.empty() ? "\\Device\\" + hex_str(dev->id) : name;
    std::string mem_tag = tag.empty() ? (name.empty() ? "emu.device.autogen" : "emu.object") : tag;
    mem_tag += "." + devname;
    dev->set_address(mem_map(alloc_size, 0, PERM_MEM_RW, mem_tag));
    dev->set_obj_name(devname);

    if (om) om->add_object(dev);

    if (drv) {
        auto* d = static_cast<Driver*>(drv);
        d->devices.push_back(static_cast<void*>(dev.get()));
    }
    // NOTE: full FILE_OBJECT + linked list linking deferred — see kernel.py:331-354
    return static_cast<void*>(dev.get());
}

void WinKernelEmulator::setup_msrs() {
    // Python kernel.py:613-642
    auto km = get_kernel_mod();
    if (get_arch() != speakeasy::arch::ARCH_AMD64 || km->image_size == 0) return;

    uint64_t kbase = km->base;
    auto km_data = mem_read(kbase, static_cast<size_t>(km->image_size));

    // Search for 100 zero bytes (Python: b"\x00" * 100) — system call handler gap
    size_t ksc64_off = std::string::npos;
    for (size_t i = 0; i + 100 <= km_data.size(); ++i) {
        bool all_zero = true;
        for (size_t j = 0; j < 100; ++j) {
            if (km_data[i + j] != 0) { all_zero = false; break; }
        }
        if (all_zero) { ksc64_off = i; break; }
    }

    if (ksc64_off == std::string::npos) return;

    auto sdt_entry = km->get_export_by_name("KeServiceDescriptorTable");
    uint64_t sdt_addr = sdt_entry ? (kbase + sdt_entry->address) : 0;

    if (sdt_addr) {
        std::string km_name = speakeasy::to_lower(km->get_base_name());
        for (int i = 0; i < 0x20; ++i) {
            symbols[sdt_addr + i] = std::make_tuple(km_name, "KeServiceDescriptorTable");
        }
        symbols[sdt_addr]      = std::make_tuple(km_name, "KeServiceDescriptorTable.pServiceTable");
        symbols[sdt_addr + 0x10] = std::make_tuple(km_name, "KeServiceDescriptorTable.NumberOfServices");

        ksc64_off += 5;
        uint64_t ksc64_addr = kbase + ksc64_off;
        symbols[ksc64_addr] = std::make_tuple(km_name, "KiSystemCall64");

        // Python: self.reg_write(_arch.X86_REG_MSR, (_arch.LSTAR, ksc64_addr))
        // Write MSR: model-specific register for syscall target
        uint64_t sdt_offset = (sdt_addr - ksc64_addr) - 7;
        std::vector<uint8_t> patch = {0x90, 0x90, 0xC3};
        patch.push_back(static_cast<uint8_t>(sdt_offset & 0xFF));
        patch.push_back(static_cast<uint8_t>((sdt_offset >> 8) & 0xFF));
        patch.push_back(static_cast<uint8_t>((sdt_offset >> 16) & 0xFF));
        patch.push_back(static_cast<uint8_t>((sdt_offset >> 24) & 0xFF));
        mem_write(kbase + ksc64_off, patch);
    }
}

} // namespace speakeasy
