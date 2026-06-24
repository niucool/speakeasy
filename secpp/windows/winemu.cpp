// winemu.cpp  Windows Emulator base class implementation
//
// Python reference: speakeasy/windows/winemu.py  (2795 lines)
// Each function definition below includes its Python line number.

#include "winemu.h"
#include "../helper.h"
#include "binemu.h"
#include "profiler.h"
#include "../config.h"
#include "../winenv/api/winapi.h"
#include "../winenv/api/api.h"
#include "../winenv/deffs/nt/ntoskrnl.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <chrono>
#include <plog/Log.h>
#include <sstream>

namespace fs = std::filesystem;

//  Constructor 
// Python winemu.py:73
// def __init__(self, config, exit_event=None, debug=False, gdb_port=None):
//     """Initialize the Windows emulator with configuration.
//     Sets up managers, memory state, bootstrap phase, and parses config."""

WindowsEmulator::WindowsEmulator(const speakeasy::SpeakeasyConfig& cfg,
                                  void* evt, bool dbg)
    : BinaryEmulator(cfg), debug(dbg),
      max_runs(100), kernel_mode(false), virtual_mem_base(0x50000),
      mem_tracing_enabled(false), tmp_code_hook(nullptr),
      run_complete(false), emu_complete(false),
      curr_exception_code(0), prev_pc(0), unhandled_exception_filter(0),
      fs_addr(0), gs_addr(0),
      return_hook(EMU_RETURN_ADDR),
      exit_hook(EXIT_RETURN_ADDR) {
    regman = std::make_shared<RegistryManager>(config_.registry);
    fileman = std::make_shared<FileManager>(config_, this);
    netman = std::make_shared<NetworkManager>(config_.network);
    driveman = std::make_shared<DriveManager>(config_.drives);
    cryptman = std::make_shared<CryptoManager>();
    hammer = std::make_shared<ApiHammer>(this, config_);
    ioman = std::make_shared<speakeasy::IoManager>();
}

//  Bootstrap 
// Python winemu.py:155
// def advance_bootstrap_phase(self, phase):
//     """Advance the bootstrap phase with explicit transition validation.
//     Raises WindowsEmuError on invalid transitions."""

void WindowsEmulator::advance_bootstrap_phase(BootstrapPhase phase) {
    if (static_cast<int>(phase) <= static_cast<int>(bootstrap_phase)) return;

    static const std::map<BootstrapPhase, std::set<BootstrapPhase>> transitions = {
        {BootstrapPhase::INITIALIZED,       {BootstrapPhase::ENGINE_API_READY}},
        {BootstrapPhase::ENGINE_API_READY,  {BootstrapPhase::OBJECT_MANAGER_READY,
                                              BootstrapPhase::FULL_SETUP_READY}},
        {BootstrapPhase::OBJECT_MANAGER_READY, {BootstrapPhase::FULL_SETUP_READY}},
        {BootstrapPhase::FULL_SETUP_READY,  {}}
    };

    auto it = transitions.find(bootstrap_phase);
    if (it != transitions.end() && it->second.count(phase)) {
        bootstrap_phase = phase;
        return;
    }
    throw WindowsEmuError("Invalid bootstrap transition");
}

void WindowsEmulator::validate_bootstrap_phase(BootstrapPhase phase,
                                                const std::string& reason) {
    // Python winemu.py:177
    // def validate_bootstrap_phase(self, phase, reason):
    //     """Validate that the emulator has reached at least the given bootstrap phase."""
    if (static_cast<int>(bootstrap_phase) < static_cast<int>(phase)) {
        throw WindowsEmuError(reason + " requires higher bootstrap phase");
    }
}

// Python winemu.py:183
// def bootstrap_object_services(self):
//     """Initialize ObjectManager services. Subclasses override."""
void WindowsEmulator::bootstrap_object_services() {
    // Subclasses override
}

// Python winemu.py:186
// def validate_object_services(self, reason):
//     """Validate that ObjectManager is initialized. Raises WindowsEmuError if not."""
void WindowsEmulator::validate_object_services(const std::string& reason) {
    if (!om) throw WindowsEmuError(reason + " requires initialized object services");
}

//  Config 
// Python winemu.py: (accessor for registry_config map)
std::map<std::string, std::string> WindowsEmulator::get_registry_config() {
    return registry_config;
}

//  Static trampolines for Unicorn callbacks 
// These bridge the C callback convention to C++ member functions.
// Python winemu.py: (Unicorn engine binding, no direct Python equivalent)

namespace {

bool code_hook_trampoline(void* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    PLOG_DEBUG << "[tramp] code_hook fired at 0x" << std::hex << address << std::dec;
    return emu->_hook_code_core(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool code_trace_trampoline(void* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_code_tracing(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool module_access_trampoline(void* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_module_access_hook(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool code_coverage_trampoline(void* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_code_coverage(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool code_debug_trampoline(void* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_code_debug(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool mem_read_trampoline(void* uc, int type, uint64_t address,
                          int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_read(static_cast<void*>(uc), static_cast<int>(type),
                                address, static_cast<size_t>(size),
                                static_cast<uint64_t>(value));
}

bool mem_write_trampoline(void* uc, int type, uint64_t address,
                           int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_write(static_cast<void*>(uc), static_cast<int>(type),
                                 address, static_cast<size_t>(size),
                                 static_cast<uint64_t>(value));
}

} // anonymous namespace

//  Hook registration helpers 

//  Hooks 
// Python winemu.py:199
// def enable_code_hook(self):
//     """Install the transient code hook needed for deferred work."""

void WindowsEmulator::enable_code_hook() {
    PLOG_DEBUG << "[hook] enable_code_hook: tmp_code_hook=" << (tmp_code_hook != nullptr)
                << " mem_tracing_enabled=" << mem_tracing_enabled;
    if (!tmp_code_hook) {
        tmp_code_hook = add_code_hook(code_hook_trampoline);
    }
    if (tmp_code_hook) {
        tmp_code_hook->enable();
    }
    //if (!tmp_code_hook && !mem_tracing_enabled) {
    //    uc_hook hh = 0;
    //    uc_err err = uc_hook_add(emu_eng_->get_engine(), &hh, UC_HOOK_CODE,
    //                              reinterpret_cast<void*>(code_hook_trampoline),
    //                              static_cast<void*>(this), 1, 0);
    //    if (err == UC_ERR_OK) {
    //        tmp_code_hook_handle = hh;
    //        tmp_code_hook = reinterpret_cast<void*>(1);  // mark as registered
    //        PLOG_DEBUG << "[hook] enable_code_hook: registered handle=0x" << std::hex << hh;
    //    } else {
    //        PLOG_DEBUG << "[hook] enable_code_hook: FAILED err=" << static_cast<int>(err);
    //    }
    //}
}

// Python winemu.py:206
// def disable_code_hook(self):
//     """Remove the transient code hook (ONLY the temporary hook, not all hooks)."""
void WindowsEmulator::disable_code_hook() {
    if (tmp_code_hook) {
        tmp_code_hook->disable();
    }
}

// Python winemu.py:377
// def _set_emu_hooks(self):
//     """Unmap reserved memory space so we can handle events (e.g. import APIs, entry point returns, etc.)"""
void WindowsEmulator::_set_emu_hooks() {
    if (!emu_hooks_set) {
        // Unmap the reserved region so that sentinel addresses trigger
        // UC_MEM_FETCH_UNMAPPED again for the next API call.
        try {
            mem_unmap(EMU_RETURN_ADDR, EMU_RESERVE_SIZE);
            emu_hooks_set = true;
            PLOG_DEBUG << "[emu-hooks] SET: unmapped 0x" << std::hex << EMU_RETURN_ADDR
                        << " size=0x" << EMU_RESERVE_SIZE << std::dec;
        } catch (const std::exception& ex) {
            // If unmap fails, the region is already unmapped  that's fine.
            // Only set emu_hooks_set if the unmap actually worked.
            PLOG_DEBUG << "[emu-hooks] SET: unmap failed (already unmapped?): " << ex.what();
            emu_hooks_set = true;  // still mark as set  the region IS unmapped
        }
    }
}

void WindowsEmulator::_unset_emu_hooks() {
    if (emu_hooks_set) {
        // Map the reserved region with RWX so Unicorn can fetch the sentinel
        // instruction.  If the region is already mapped (e.g. by a tmp_map),
        // mem_map will fail gracefully  we log and do NOT corrupt emu_hooks_set.
        try {
            mem_map(EMU_RESERVE_SIZE, EMU_RETURN_ADDR, PERM_MEM_RWX, "emu.reserved");
            emu_hooks_set = false;
            PLOG_DEBUG << "[emu-hooks] UNSET: mapped 0x" << std::hex << EMU_RETURN_ADDR
                        << " size=0x" << EMU_RESERVE_SIZE << std::dec;
        } catch (const std::exception& ex) {
            PLOG_DEBUG << "[emu-hooks] UNSET: map FAILED (keeping emu_hooks_set=true): "
                        << ex.what();
        }
    }
}

// Python winemu.py:218
// def set_mem_tracing_hooks(self):
//     """Install memory tracing hooks for analysis."""
void WindowsEmulator::set_mem_tracing_hooks() {
    if (!config_.analysis.memory_tracing) {
        return;
    }

    if (mem_trace_hooks.empty()) {
        //_register_code_hook(reinterpret_cast<void*>(code_trace_trampoline), 1, 0);
        //_register_mem_hook(UC_HOOK_MEM_READ, reinterpret_cast<void*>(mem_read_trampoline));
        //_register_mem_hook(UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(mem_write_trampoline));
        //mem_trace_hooks.push_back(reinterpret_cast<void*>(1));
        mem_trace_hooks.push_back(add_code_hook(code_trace_trampoline));
        mem_trace_hooks.push_back(add_mem_read_hook(mem_read_trampoline));
        mem_trace_hooks.push_back(add_mem_write_hook(mem_write_trampoline));

    }
}

// Python winemu.py:210
// def _module_access_hook(self, emu, addr, size):
//     """Code hook fired for access to module API addresses; resolves symbol and dispatches handler."""
bool WindowsEmulator::_module_access_hook(void* emu, uint64_t addr, size_t size) {
    (void)emu; (void)size; 
    std::string sym = get_symbol_from_address(addr);
    if (!sym.empty()) {
        size_t dot = sym.find('.');
        if (dot != std::string::npos) {
            std::string dll = sym.substr(0, dot);
            std::string name = sym.substr(dot + 1);
            handle_import_func(dll, name);
            return true;
        } else {
            // Fallback for flat names
            handle_import_func("", sym);
            return true;
        }
    }
    return false;
}

//  Code hook core 
// Python winemu.py:2031
// def _hook_code_core(self, emu, addr, size):
//     """Transient code hook for deferred work: SEH dispatch, run lifecycle,
//     temp map cleanup, and import data queue processing. Enabled on demand
//     and disables itself once the pending work is drained."""

bool WindowsEmulator::_hook_code_core(void* emu, uint64_t addr, size_t size) {
    PLOG_DEBUG << "[code-core] fired at 0x" << std::hex << addr
                << " curr_exception=" << curr_exception_code
                << " restart=" << restart_curr_run
                << " run_complete=" << run_complete
                << " return_hook=0x" << return_hook << std::dec;

    // SEH dispatch
    if (curr_exception_code != 0) {
        dispatch_seh(curr_exception_code);
        curr_exception_code = 0;
        disable_code_hook();
        return true;
    }

    // Restart current run
    if (restart_curr_run) {
        set_pc(curr_run->start_addr);
        restart_curr_run = false;
        return false;
    }

    // Run complete / return hook hit
    if (addr == return_hook || run_complete) {
        PLOG_DEBUG << "[code-core] RUN COMPLETE";
        on_run_complete();
        return false;
    }

    // Clean up temporary maps
    for (auto& [base, sz] : tmp_maps) {
        mem_unmap(base, sz);
    }
    tmp_maps.clear();

    // Process import data queue
    if (!impdata_queue.empty()) {
        auto imp = impdata_queue.front();
        impdata_queue.erase(impdata_queue.begin());
        auto& mod = std::get<0>(imp);
        auto& sym = std::get<1>(imp);
        auto val = std::get<2>(imp);
        handle_import_data(mod, sym, val);
        return true;
    }

    // At a sentinel address (in the reserved range): DON'T unmap the page.
    // Unmapping here would cause an infinite FETCH_UNMAPPED  map  hook  unmap
    // loop because the instruction at the sentinel hasn't executed yet.
    // The sentinel page will be unmapped in the NEXT _hook_code_core call
    // that fires at the return address (after the RET/nop executes).
    bool at_sentinel = (addr >= EMU_RESERVED && addr <= (EMU_RESERVED + EMU_RESERVE_SIZE));
    if (at_sentinel) {
        PLOG_DEBUG << "[code-core] at sentinel (0x" << std::hex << addr
                    << "), skipping _set_emu_hooks" << std::dec;
        disable_code_hook();
        return true;
    }

    // At the return address (not a sentinel): safe to unmap.
    _set_emu_hooks();
    disable_code_hook();
    PLOG_DEBUG << "[code-core] at return addr, hooks reset";
    return true;
}

//  Memory 
// Python winemu.py:251
// def cast(self, obj, bytez):
//     """Create a formatted structure from bytes"""

EmuStruct* WindowsEmulator::cast(EmuStruct* obj,
                                  const std::vector<uint8_t>& bytez) {
    if (!obj) throw WindowsEmuError("Invalid object for cast");
    obj->from_bytes(bytez);
    return obj;
}

// Python winemu.py:478
// def mem_cast(self, obj, addr):
//     """Turn bytes from an emulated memory pointer into an object"""
EmuStruct* WindowsEmulator::mem_cast(EmuStruct* obj, uint64_t addr) {
    size_t sz = obj->sizeof_obj();
    auto data = mem_read(addr, sz);
    return cast(obj, data);
}

// Python winemu.py:486
// def mem_purge(self):
//     """Unmap all memory chunks"""
void WindowsEmulator::mem_purge() {
    purge_memory();
}

// Python winemu.py:492
// def setup_user_shared_data(self):
//     """Setup the shared user data section that is often used to share data
//     between user mode and kernel mode"""
// Python winemu.py:1139  default setup (overridden in subclasses)
void WindowsEmulator::setup(size_t stack_commit, bool first_time_setup) { /* default: no-op, overridden by Win32Emulator */ (void)stack_commit; (void)first_time_setup; }

// Python winemu.py:548  base class on_run_complete (Python has this on WindowsEmulator)
void WindowsEmulator::on_run_complete() {
    PLOG_DEBUG << "[lifecycle] on_run_complete() called, stack trace:";
    auto trace = get_stack_trace();
    for (auto& line : trace) PLOG_DEBUG << "  " << line;
    run_complete = true;
}

// Python win32.py:603
// def exit_process(self):
//     self.enable_code_hook()
//     self.run_complete = True
void WindowsEmulator::exit_process() {
    enable_code_hook();
    on_run_complete();
}

void WindowsEmulator::setup_user_shared_data() {
    constexpr uint64_t KUSER_SHARED_X86  = 0xFFDF0000;
    constexpr uint64_t KUSER_SHARED_AMD64 = 0xFFFFF78000000000ULL;
    constexpr uint64_t KUSER_READONLY     = 0x7FFE0000;

    if (arch_ == speakeasy::arch::ARCH_X86) {
        mem_map(page_size_, KUSER_SHARED_X86, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    } else {
        mem_map(page_size_, KUSER_SHARED_AMD64, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    }
    mem_map(page_size_, KUSER_READONLY, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    _populate_user_shared_data(KUSER_READONLY);
}

// Python winemu.py:507
// def _populate_user_shared_data(self, base):
//     """Populate the KUSER_SHARED_DATA page with system time and version info."""
void WindowsEmulator::_populate_user_shared_data(uint64_t base) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto dur = now.time_since_epoch();
    auto ns100 = duration_cast<nanoseconds>(dur).count() / 100 + 116444736000000000LL;

    std::vector<uint8_t> data(0x400, 0);

    // InterruptTime at offset 0x008
    write_le(data, 0x008, static_cast<uint32_t>(ns100 & 0xFFFFFFFF), 4);
    write_le(data, 0x00C, static_cast<uint32_t>(ns100 >> 32), 4);
    write_le(data, 0x010, static_cast<uint32_t>(ns100 >> 32), 4);

    // SystemTime at offset 0x014
    write_le(data, 0x014, static_cast<uint32_t>(ns100 & 0xFFFFFFFF), 4);
    write_le(data, 0x018, static_cast<uint32_t>(ns100 >> 32), 4);
    write_le(data, 0x01C, static_cast<uint32_t>(ns100 >> 32), 4);

    // OS version at offset 0x260
    write_le(data, 0x260, 6, 4);  // NtMajorVersion
    write_le(data, 0x264, 1, 4);  // NtMinorVersion
    write_le(data, 0x268, 7601, 4);  // NtBuildNumber

    mem_write(base, data);
}

// Python winemu.py:676
// def _setup_gdt(self, arch):
//     """Set up the GDT so we can access segment registers correctly.
//     This will be done a little differently depending on architecture"""
std::tuple<uint64_t, uint64_t> WindowsEmulator::_setup_gdt(int arch) {
    constexpr size_t GDT_SIZE = 0x1000;
    constexpr size_t SEG_SIZE = 0x1000;
    constexpr size_t ENTRY_SIZE = 0x8;

    // Allocate GDT memory first so addresses are available for the lambda
    uint64_t gdt_base = 0;
    uint64_t gdt_addr = 0;
    uint64_t gdt_size = 0;
    std::tie(gdt_addr, gdt_size) = get_valid_ranges(GDT_SIZE);
    gdt_base = gdt_addr;
    mem_map(gdt_size, gdt_base, PERM_MEM_RW, "emu.gdt");

    uint64_t seg_addr = 0;
    uint64_t seg_size = 0;
    std::tie(seg_addr, seg_size) = get_valid_ranges(SEG_SIZE);
    mem_map(seg_size, seg_addr, PERM_MEM_RW, "emu.segment.gdt");

    // Helper to build an 8-byte GDT entry from index, base, access bits, and limit
    auto make_entry = [&](int index, uint64_t base, uint8_t access, uint64_t limit = 0xFFFFF000) {
        access = access | (GDT_ACCESS_BITS::PresentBit | GDT_ACCESS_BITS::DirectionConformingBit);
        uint64_t entry = 0;
        entry |= (0xFFFFULL & limit);                         // bits 0-15: limit[15:0]
        entry |= ((0xFFFFFFULL & base) << 16);                // bits 16-39: base[23:0]
        entry |= ((uint64_t)(0xFF & access) << 40);           // bits 40-47: access byte
        entry |= ((uint64_t)(0xFF & (limit >> 16)) << 48);    // bits 48-51: limit[19:16]
        entry |= ((uint64_t)(0xFF & GDT_ACCESS_BITS::ProtMode32) << 52);  // bits 52-55: flags
        entry |= ((uint64_t)(0xFF & (base >> 24)) << 56);     // bits 56-63: base[31:24]

        std::vector<uint8_t> entry_bytes(8);
        for (int i = 0; i < 8; i++) {
            entry_bytes[i] = static_cast<uint8_t>((entry >> (i * 8)) & 0xFF);
        }
        uint64_t offset = static_cast<uint64_t>(index) * ENTRY_SIZE;
        mem_write(gdt_addr + offset, entry_bytes);
    };

    auto create_selector = [](int index, uint8_t flags) -> uint64_t {
        return static_cast<uint64_t>(flags | (index << 3));
    };

    // Entry 16: Data/Ring3 (DS)
    {
        uint8_t access = GDT_ACCESS_BITS::Data | GDT_ACCESS_BITS::DataWritable | GDT_ACCESS_BITS::Ring3;
        make_entry(16, 0, access);
    }
    // Entry 17: Code/Ring3 (CS)
    {
        uint8_t access = GDT_ACCESS_BITS::Code | GDT_ACCESS_BITS::CodeReadable | GDT_ACCESS_BITS::Ring3;
        make_entry(17, 0, access);
    }
    // Entry 18: Data/Ring0 (SS)
    {
        uint8_t access = GDT_ACCESS_BITS::Data | GDT_ACCESS_BITS::DataWritable | GDT_ACCESS_BITS::Ring0;
        make_entry(18, 0, access);
    }

    // Write GDTR base address and segment selectors
    if (emu_eng_) {
        uint64_t gdtr_base = gdt_base;
        emu_eng_->reg_write_gdt_idt(speakeasy::arch::REG_GDTR, gdtr_base, 31 * ENTRY_SIZE - 1);
        // DS selector (index 16, Ring3)
        emu_eng_->reg_write(speakeasy::arch::REG_DS, create_selector(16, GDT_FLAGS::Ring3));
        // CS selector (index 17, Ring3)
        emu_eng_->reg_write(speakeasy::arch::REG_CS, create_selector(17, GDT_FLAGS::Ring3));
        // SS selector (index 18, Ring0)
        emu_eng_->reg_write(speakeasy::arch::REG_SS, create_selector(18, GDT_FLAGS::Ring0));
    }

    // Architecture-specific FS/GS segments
    uint64_t fs_base = 0;
    uint64_t gs_base = 0;

    if (speakeasy::arch::ARCH_X86 == arch) {
        // FS segment needed for PEB access at fs:[0x30]
        uint64_t fs_range = 0;
        uint64_t fs_sz = 0;
        std::tie(fs_range, fs_sz) = get_valid_ranges(SEG_SIZE);
        fs_base = fs_range;
        mem_map(fs_sz, fs_base, PERM_MEM_RW, "emu.segment.fs");

        uint8_t access = GDT_ACCESS_BITS::Data | GDT_ACCESS_BITS::DataWritable | GDT_ACCESS_BITS::Ring3;
        make_entry(19, fs_base, access);

        if (emu_eng_) {
            uint64_t fs_sel = create_selector(19, GDT_FLAGS::Ring3);
            emu_eng_->reg_write(speakeasy::arch::REG_FS, fs_sel);
        }
    } else if (speakeasy::arch::ARCH_AMD64 == arch) {
        // GS Segment needed for PEB access at gs:[0x60]
        uint64_t gs_range = 0;
        uint64_t gs_sz = 0;
        std::tie(gs_range, gs_sz) = get_valid_ranges(SEG_SIZE);
        gs_base = gs_range;
        mem_map(gs_sz, gs_base, PERM_MEM_RW, "emu.segment.gs");

        uint8_t access = GDT_ACCESS_BITS::Data | GDT_ACCESS_BITS::DataWritable | GDT_ACCESS_BITS::Ring3;
        make_entry(15, gs_base, access, SEG_SIZE);

        if (emu_eng_) {
            uint64_t gs_sel = create_selector(15, GDT_FLAGS::Ring3);
            emu_eng_->reg_write(speakeasy::arch::REG_GS, gs_sel);
        }
    }

    fs_addr = fs_base;
    gs_addr = gs_base;
    return {fs_addr, gs_addr};
}

//  Memory exception handlers 
// Python winemu.py:1960
// def _handle_invalid_read(self, emu, address, size, value):
//     """Hook each invalid memory read event that occurs."""

bool WindowsEmulator::_handle_invalid_read(void* emu, uint64_t address,
                                            size_t size, uint64_t value) {
    // Check if address is in a known module
    auto mod = get_mod_from_addr(address);
    if (mod) return true;

    if (address >= EMU_RESERVED && address <= (EMU_RESERVED + EMU_RESERVE_SIZE)) {
        _unset_emu_hooks();
        return true;
    }

    if (dispatch_handlers) {
        bool rv = dispatch_seh(0xC0000005 /* STATUS_ACCESS_VIOLATION */, address);
        if (rv) return true;
    }

    // Fake a page mapping at the faulting address
    uint64_t fakeout = address & 0xFFFFFFFFFFFFF000ULL;
    mem_map(page_size_, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size_});
    on_run_complete();
    return true;
}

// Python winemu.py:1988
// def _handle_prot_fetch(self, emu, address, size, value):
//     """Called when non-executable code is emulated."""
bool WindowsEmulator::_handle_prot_fetch(void* emu, uint64_t address,
                                          size_t size, uint64_t value) {
    (void)emu; (void)size; (void)value;
    std::string sym = get_symbol_from_address(address);
    if (!sym.empty()) {
        return true;  // Symbol found  let caller handle import resolution
    }
    return true;
}

// Python winemu.py:2008
// def _handle_invalid_write(self, emu, address, size, value):
//     """Called when non-writable address is written to."""
bool WindowsEmulator::_handle_invalid_write(void* emu, uint64_t address,
                                             size_t size, uint64_t value) {
    if (address >= EMU_RESERVED && address <= (EMU_RESERVED + EMU_RESERVE_SIZE))
        return true;

    if (dispatch_handlers) {
        bool rv = dispatch_seh(0xC0000005, address);
        if (rv) return true;
    }

    uint64_t fakeout = address & 0xFFFFFFFFFFFFF000ULL;
    mem_map(page_size_, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size_});
    on_run_complete();
    return true;
}

//  File 
// Python winemu.py:267
// def file_open(self, path, create=False, truncate=False):
//     """Open a file in the emulated filesystem"""
void* WindowsEmulator::file_open(const std::string& path, bool create) {
    if (fileman) {
        uint32_t h = fileman->file_open(path, create);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
    return nullptr;
}

// Python winemu.py:273
// def pipe_open(self, path, mode, num_instances, out_size, in_size):
//     """Open an emulated named pipe"""
void* WindowsEmulator::pipe_open(const std::string& path, const std::string& mode,
                                  int num_instances, size_t out_size, size_t in_size) {
    if (fileman) {
        uint32_t h = fileman->pipe_open(path, mode, num_instances, out_size, in_size);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
    return nullptr;
}

// Python winemu.py:279
// def does_file_exist(self, path):
//     """Test if a file handler for a specified emulated file exists"""
bool WindowsEmulator::does_file_exist(const std::string& path) {
    return fileman ? fileman->does_file_exist(path) : false;
}

// Python winemu.py:351
// def reg_open_key(self, path, create=False):
//     """Open or create a registry key in the emulation space"""
uint32_t WindowsEmulator::reg_open_key(const std::string& path, bool create) {
    if (regman) {
        return regman->open_key(path, create);
    }
    return 0;
}

// Python winemu.py:363
// def reg_get_key(self, handle=0, path=""):
//     """Get registry key by path or handle"""
std::shared_ptr<RegKey> WindowsEmulator::reg_get_key(int handle, const std::string& path) {
    if (!regman) return nullptr;
    std::shared_ptr<RegKey> key;
    if (handle != 0)
        return regman->get_key_from_handle(static_cast<uint32_t>(handle));
    else if (!path.empty())
        return regman->get_key_from_path(path);
    else
        return nullptr;
}

// Python winemu.py:371
// def reg_create_key(self, path):
//     """Create a registry key"""
std::shared_ptr<RegKey> WindowsEmulator::reg_create_key(const std::string& path) {
    if (regman) {
        return regman->create_key(path);
    }
    return nullptr;
}

// Python winemu.py:2713
// def create_event(self, name=""):
//     """Create a kernel event object"""
std::tuple<int, std::shared_ptr<Event>> WindowsEmulator::create_event(const std::string& name) {
    validate_object_services("event creation");
    std::shared_ptr<Event> evt = new_object<Event>();
    evt->set_obj_name(name);
    uint64_t hnd = om->get_handle(evt);
    return { hnd, evt };
}

// Python winemu.py:2730
// def create_mutant(self, name=""):
//     """Create a kernel mutant object"""
std::tuple<int, std::shared_ptr<Mutant>> WindowsEmulator::create_mutant(const std::string& name) {
    validate_object_services("mutant creation");

    std::shared_ptr<Mutant> mtx = new_object<Mutant>();
    mtx->set_obj_name(name);
    uint64_t hnd = om->get_handle(mtx);
    return { hnd, mtx };
}

// Python winemu.py:392
// def _exec_next_run(self):
//     """Execute the next run from the emulation queue"""
std::shared_ptr<Run> WindowsEmulator::_exec_next_run() {
    if (run_queue.empty()) {
        on_emu_complete();
        return nullptr;
    }

    auto run = run_queue.front();
    run_queue.erase(run_queue.begin());

    run_complete = false;
    _seh_last_fault = {0, std::nullopt};
    _seh_repeat_count = 0;

    // reset_stack done by base class
    return _prepare_run_context(run);
}

// Python winemu.py:408
// def call(self, addr, params=[]):
//     """Start emulating at the specified address"""
void WindowsEmulator::call(uint64_t addr, const std::vector<std::string>& params) {

    auto run = std::make_shared<Run>();
    run->type = "call_0x" + std::to_string(addr);
    run->start_addr = addr;
    // run->args = params;

    if (run_queue.empty()) {
        add_run(run);
        start();
    } else {
        add_run(run);
    }
}

// Python winemu.py:424
// def _prepare_run_context(self, run):
//     """Prepare CPU and memory state for the given run without starting emulation."""
std::shared_ptr<Run> WindowsEmulator::_prepare_run_context(std::shared_ptr<Run> run) {
    curr_run = run;

    PLOG_DEBUG << "* exec: " << run->type;

    if (profiler_) {
        profiler_->add_run(run);
    }

    runs.push_back(curr_run);

    // Set up stack for return and args
    uint64_t stk_ptr = get_stack_ptr();
    set_func_args(stk_ptr, return_hook, run->args_values);
    stk_ptr = get_stack_ptr();

    std::shared_ptr<MemMap> stk_map = get_address_map(stk_ptr);
    curr_run->stack.base = stk_map->get_base();
    curr_run->stack.size = stk_map->get_size();


    if (run->process_context) {
        auto proc_sp = run->process_context;
        if (run->process_context != get_current_process()) {
            alloc_peb(proc_sp);
        }
        set_current_process(proc_sp);
    }

    if (run->thread) {
        set_current_thread(run->thread);
    }
    else if (!kernel_mode) {
        auto thread = std::make_shared<Thread>(this, stack_base_);
        om->add_object(thread);
        if(curr_process_) {
            thread->set_process(curr_process_);
            curr_process_->threads.push_back(thread);
        }
        run->thread = thread;
        set_current_thread(thread);
    }

    if (!kernel_mode) {
        auto thread = get_current_thread();
        if (thread) {
            init_teb(thread, curr_process_->peb);
            init_tls(thread);
        }
    }

    // Reset SEH state
    _seh_last_fault = {0, std::nullopt};
    _seh_repeat_count = 0;

    // Unmap reserved region if entry point is there
    if (run->start_addr >= EMU_RESERVED &&
        run->start_addr <= EMU_RESERVED_END) {
        try {
            mem_unmap(EMU_RESERVED, EMU_RESERVE_SIZE);
        }
        catch (...) {
        }
        emu_hooks_set = true;
    }

    set_pc(run->start_addr);
    return run;
}

// Python winemu.py:543
// def start(self, addr=None, size=None):
//     """Begin emulation executing each run in the specified run queue"""
void WindowsEmulator::start() {
    if (run_queue.empty()) return;

    auto run = run_queue.front();
    run_queue.erase(run_queue.begin());

    run_complete = false;
    set_hooks();
    _set_emu_hooks();
    _prepare_run_context(run);

    // Get timeout from config
    uint64_t timeout_usec = 0;
    if (config_.timeout > 0) {
        timeout_usec = static_cast<uint64_t>(config_.timeout) * 1000000ULL;
    }

    // Start profiler timer
    if (profiler_) {
        profiler_->set_start_time();
    }

    // Python: uc_emu_start(addr, timeout, count=self.config.max_instructions)
    // where max_instructions defaults to -1 (unlimited).
    // Use a large count instead of 0 because Unicorn 2.x may return UC_ERR_MAP
    // with count=0 when the hook chain modifies memory mappings.
    int max_instr = config_.max_instructions;
    //if (max_instr < 0) max_instr = 50000;  // finite limit, > Python antidbg's ~844 instructions

    while (true) {
        try {
            // Set current module
            if (curr_run) {
                curr_mod = get_mod_from_addr(curr_run->start_addr);
            }

            // Begin emulation via engine (synchronous)
            if (emu_eng_ && curr_run) {
                uc_err err = emu_eng_->start(curr_run->start_addr, timeout_usec,
                                             static_cast<size_t>(max_instr));
                PLOG_DEBUG << "[engine] uc_emu_start returned err=" << static_cast<int>(err)
                            << " run_complete=" << run_complete
                            << " curr_pc=0x" << std::hex << get_pc()
                            << " instr_cnt=" << std::dec << curr_run->instr_cnt;
                if (err != UC_ERR_OK) {
                    // UC_ERR_FETCH_PROT (14): sentinel page was mapped RW but
                    // not executable. do_call_return already set PC to the
                    // to the return address  just restart emulation from there.
                    if ((err == UC_ERR_FETCH_UNMAPPED || err == UC_ERR_FETCH_PROT
                         || err == UC_ERR_MAP)
                        && !run_complete && curr_run) {
                        PLOG_DEBUG << "[engine] FETCH_UNMAPPED after API dispatch, "
                                    << "restarting from pc=0x" << std::hex << get_pc() << std::dec;
                        curr_run->start_addr = get_pc();
                        continue;
                    }

                    // Log details for UC_ERR_EXCEPTION and other unexpected errors
                    if (err == UC_ERR_EXCEPTION) {
                        record_error_event("* CPU exception at 0x" + hex_str(get_pc())
                                  + " (insn count " + std::to_string(curr_run->instr_cnt) + ")");
                    } else {
                        record_error_event("* Unicorn engine error " + std::to_string(static_cast<int>(err))
                                  + " at 0x" + hex_str(get_pc()));
                    }

                    // Check for timeout after execution
                    if (profiler_ && timeout_usec > 0 &&
                        profiler_->get_run_time() > static_cast<double>(config_.timeout)) {
                        record_error_event("* Timeout of " + std::to_string(config_.timeout) + " sec(s) reached.");
                    } else {
                        // Non-OK result: try next run via on_run_complete
                        on_run_complete();
                        if (run_queue.empty()) break;
                        auto next = run_queue.front();
                        run_queue.erase(run_queue.begin());
                        _prepare_run_context(next);
                        continue;
                    }
                }

                // Check timeout after successful emulation
                if (profiler_ && timeout_usec > 0 &&
                    profiler_->get_run_time() > static_cast<double>(config_.timeout)) {
                    record_error_event("* Timeout of " + std::to_string(config_.timeout) + " sec(s) reached.");
                }
            }
        } catch (const std::exception& e) {
            // Exception during emulation
            (void)e;
            // Treat as run error
            on_run_complete();
            if (run_queue.empty()) break;
            auto next = run_queue.front();
            run_queue.erase(run_queue.begin());
            _prepare_run_context(next);
            continue;
        }
        break;
    }

    on_emu_complete();
}

// Python winemu.py:536
// def resume(self, addr, count=-1):
//     """Resume emulation at the specified address."""
void WindowsEmulator::resume(uint64_t addr, int count) {
    if (emu_eng_) {
        emu_eng_->start(addr, 0, static_cast<size_t>(count));
    }
}

//  Run access 
// Python winemu.py:609
// def get_current_run(self):
//     """Get the current run that is being emulated"""
std::shared_ptr<Run> WindowsEmulator::get_current_run() { return curr_run; }
// Python winemu.py:615
// def get_current_module(self):
//     """Get the currently running module"""
std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::get_current_module() { return curr_mod; }
// Python winemu.py:621
// def get_dropped_files(self):
//     """Get all files written by the sample from the file manager"""
std::vector<std::shared_ptr<File>> WindowsEmulator::get_dropped_files() { 
    if(fileman)
        return fileman->get_dropped_files();
    else
        return {};
 }

//  Process / thread 
// Python winemu.py:635
std::vector<std::shared_ptr<Process>>& WindowsEmulator::get_processes() {
    if(processes_.size() <= 1)
        init_processes(config_.processes);
    return processes_;
}

std::shared_ptr<Process> WindowsEmulator::find_process(void* proc_ptr) {
    if (!proc_ptr) return nullptr;
    for (const auto& proc : processes_) {
        if (proc.get() == proc_ptr) {
            return proc;
        }
    }
    for (const auto& proc : child_processes_) {
        if (proc.get() == proc_ptr) {
            return proc;
        }
    }
    return nullptr;
}
// Python winemu.py:643
// def kill_process(self, proc):
//     """Terminate a process (i.e. remove it from the known process list)"""
void WindowsEmulator::kill_process(std::shared_ptr<Process> proc) {
    if (proc) {
        proc->modules.clear();
        proc->threads.clear();
    }
    run_complete = true;
}

//  Environment 
// Python winemu.py:1142
// def get_system_root(self):
//     """Get the path of the "SYSTEMROOT" environment variable"""
std::string WindowsEmulator::get_system_root() {
    auto it = env_.find("systemroot");
    std::string root = (it != env_.end()) ? it->second : "C:\\WINDOWS\\system32";
    if (!root.empty() && root.back() != '\\') root += '\\';
    return root;
}

// Python winemu.py:1151
// def get_windows_dir(self):
//     """Get the path of the "WINDIR" environment variable"""

std::string WindowsEmulator::get_windows_dir() {
    auto it = env_.find("windir");
    std::string dir = (it != env_.end()) ? it->second : "C:\\WINDOWS";
    if (!dir.empty() && dir.back() != '\\') dir += '\\';
    return dir;
}

// Python winemu.py:1160
// def get_cd(self):
//     """Get the path of the current directory"""

std::string WindowsEmulator::get_cd() {
    if (cd.empty()) {
        auto it = env_.find("cd");
        cd = (it != env_.end()) ? it->second : "C:\\WINDOWS\\system32";
        if (!cd.empty() && cd.back() != '\\') cd += '\\';
    }
    return cd;
}

// Python winemu.py:1170
// def set_cd(self, cd):
//     """Sets the current directory path"""

void WindowsEmulator::set_cd(const std::string& path) { cd = path; }

std::map<std::string, std::string> WindowsEmulator::get_env() { return env_; }

// Python winemu.py:1179
// def set_env(self, var, val):
//     """Set an environment variable (key lowercased)."""

void WindowsEmulator::set_env(const std::string& var, const std::string& val) {
    env_[speakeasy::to_lower(var)] = val;
}

// Python winemu.py:1213
// def search_path(self, file_name):
//     """Search the emulated filesystem for a file. Currently returns cd + filename."""

std::string WindowsEmulator::search_path(const std::string& file_name) {
    if (file_name.find('\\') != std::string::npos) return file_name;
    std::string fp = get_cd();
    if (!fp.empty() && fp.back() != '\\') fp += '\\';
    return fp + file_name;
}

//  Object management 

// Python winemu.py:1182
// def get_object_from_addr(self, addr):
//     """Get an object from its memory address."""

std::shared_ptr<KernelObject> WindowsEmulator::get_object_from_addr(uint64_t addr) {
    validate_object_services("object lookup by address");
    return om->get_object_from_addr(addr);
}

// Python winemu.py:1186
// def get_object_from_id(self, id):
//     """Get an object from its unique id."""

std::shared_ptr<KernelObject> WindowsEmulator::get_object_from_id(int id) {
    validate_object_services("object lookup by id");
    if (!om) return nullptr;
    return om->get_object_from_id(id);
}

// Python winemu.py:1190
// def get_object_from_name(self, name):
//     """Get an object from its name."""

std::shared_ptr<KernelObject> WindowsEmulator::get_object_from_name(const std::string& name) {
    validate_object_services("object lookup by name");
    if (!om) return nullptr;
    return om->get_object_from_name(name);
}

// Python winemu.py:1194
// def get_object_from_handle(self, handle):
//     """Get an object from its handle."""

std::shared_ptr<KernelObject> WindowsEmulator::get_object_from_handle(uint64_t handle) {
    validate_object_services("object lookup by handle");
    // Try ObjectManager first
    auto ko = om->get_object_from_handle(handle);
    if (ko) {
        return ko;
    }
    // Fallback to FileManager
    if (fileman) {
        return fileman->get_object_from_handle(static_cast<uint32_t>(handle));
    }
    return nullptr;
}

// Python winemu.py:1203
// def get_object_handle(self, obj):
//     """Get the handle for a given object."""

int WindowsEmulator::get_object_handle(std::shared_ptr<KernelObject> obj) {
    validate_object_services("object handle lookup");
    if (!om || !obj) return 0;
    // obj is a KernelObject* (or subclass)  cast and delegate
    return om->get_handle(obj);
}

// Python winemu.py:1209
// def add_object(self, obj):
//     """Register an object with the ObjectManager."""

void WindowsEmulator::add_object(std::shared_ptr<KernelObject> obj) {
    validate_object_services("object registration");
    if (!om || !obj) return;
    // obj is a KernelObject* (or subclass)  cast and delegate
    om->add_object(obj);
}

// Python winemu.py:1222
// def new_object(self, otype):
//     """Create a new object of the given type."""

template<typename T> std::shared_ptr<T> WindowsEmulator::new_object() {
    validate_object_services("object creation");
    if (!om) return nullptr;
    // Use the explicitly instantiated template for KernelObject
    return om->new_object<T>();
}

//  PE / module helpers 

// Python winemu.py:847
// def get_mod_from_addr(self, addr):
//     """Get a module from an address within it."""

std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::get_mod_from_addr(uint64_t addr) {
    if (curr_mod) {
        auto pe = curr_mod;
        uint64_t base = pe->base;
        if (addr >= base && addr < base + pe->image_size)
            return curr_mod;
    }
    for (auto m : modules_) {
        auto pe = m;
        uint64_t base = pe->base;
        if (addr >= base && addr < base + pe->image_size)
            return m;
    }
    return nullptr;
}

// Python winemu.py:860
// def _alloc_sentinel(self):
//     """Allocate a sentinel value for import table hooking."""

uint64_t WindowsEmulator::_alloc_sentinel() {
    static uint64_t _next_sentinel = IMPORT_HOOK_ADDR;
    uint64_t addr = _next_sentinel;
    _next_sentinel += static_cast<uint64_t>(ptr_size_ > 0 ? ptr_size_ : 4);
    return addr;
}

// Python winemu.py:979
// def get_mod_by_name(self, name):
//     """Find a loaded module by name (case-insensitive)."""

std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::get_mod_by_name(const std::string& name) {
    std::string nl = speakeasy::to_lower(name);

    for (auto pe : modules_) {
        fs::path full_path = speakeasy::parse_nt_path(pe->emu_path);

        // 1. Get the filename (equivalent to ntpath.basename)
        fs::path mod_name = full_path.filename();

        // 2. Strip the final extension (equivalent to os.path.splitext[0])
        std::string base_name = mod_name.stem().string();

        if (speakeasy::to_lower(mod_name.string()) == nl || speakeasy::to_lower(base_name) == nl)
            return pe;
    }
    return nullptr;
}

// Python winemu.py:990
// def get_peb_modules(self):
//     """Get modules that are visible in the PEB."""

std::vector<std::shared_ptr<speakeasy::RuntimeModule>> WindowsEmulator::get_peb_modules() {
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> result;
    for (auto m : modules_) {
        result.push_back(m);  // All modules visible in PEB by default
    }
    return result;
}

//  PE initialization 

// Python winemu.py:760
// def init_peb(self, user_mods, proc=None):
//     """Initialize the Process Environment Block"""

void WindowsEmulator::init_peb(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& user_mods, std::shared_ptr<Process> proc) {
    std::shared_ptr<Process> process = proc ? proc : curr_process_;
    if (!process) return;

    if (process->get_peb()) {
        uint64_t peb_val = process->get_peb()->get_address();
        std::vector<uint8_t> peb_bytes;
        int ptr_sz = get_ptr_size();
        for (int i = 0; i < ptr_sz; ++i) {
            peb_bytes.push_back(static_cast<uint8_t>((peb_val >> (i * 8)) & 0xFF));
        }
        uint64_t peb_pointer_addr = (ptr_sz == 4) ? fs_addr + 0x30 : gs_addr + 0x60;
        mem_write(peb_pointer_addr, peb_bytes);
    }

    if (!user_mods.empty()) {
        process->init_peb(user_mods);
    } else {
        auto peb_mods = get_peb_modules();
        process->init_peb(peb_mods);
    }
}

// Python winemu.py:771
// def init_teb(self, thread, peb):
//     """Initialize the Thread Information Block"""

void WindowsEmulator::init_teb(std::shared_ptr<Thread> thread, std::shared_ptr<PEB> peb) {
    if (!thread) return;
    uint64_t peb_addr_val = peb ? peb->get_address() : 0;
    if (ptr_size_ == 4) {
        thread->init_teb(fs_addr, peb_addr_val);
    } else {
        thread->init_teb(gs_addr, peb_addr_val);
    }
}

// Python winemu.py:780
// def init_tls(self, thread):
//     """Initialize implicit thread local storage. Meant to be called after init_teb."""

void WindowsEmulator::init_tls(std::shared_ptr<Thread> thread) {
    if (!thread || !curr_run) return;
    auto mod = get_mod_from_addr(curr_run->start_addr);
    if (mod) {
        auto pe = mod;
        std::string modname = pe->get_base_name();
        // TLS directory is stored in PeFile metadata during PeLoader::parse_pe
        // For now, init TLS with empty directory (callbacks are already in tls_callbacks_)
        thread->init_tls(0, modname);
    }
}

// Python winemu.py:809
// def load_pe(self, path=None, data=None, imp_id=winemu.IMPORT_HOOK_ADDR):
//     """Parse a PE that will be used during emulation. PE type and architecture
//     are automatically determined."""

std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::load_pe(const std::string& path,
                                const std::vector<uint8_t>& data,
                                uint64_t imp_id) {
    // Use PeLoader to parse the PE file
    speakeasy::PeLoader loader(path, data);
    auto img = loader.make_image();
    if(imp_id)
        img->base = imp_id;  // Override base for sentinel tracking
    auto result = load_image(img);
    return result;
}

// Python winemu.py:993
// def load_image(self, image):
//     """Load a parsed PE image into emulated memory, set up imports/exports, sections."""

std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::load_image(std::shared_ptr<speakeasy::LoadedImage> img) {
    // Python reference: winemu.py lines 993-1137
    if (!img) return nullptr;

    //if (img->regions.empty())
    //    return nullptr;

    bool valid_arch = (img->arch == 32 || img->arch == 64);
    //  Determine architecture (Python 998-1004) 
    if (!arch_) {
        arch_ = valid_arch ? img->arch : speakeasy::arch::ARCH_X86;
        set_ptr_size(arch_);
    }

    //  Initialize emulation engine if needed (Python 1006-1008)
    // Python: `if self.emu_eng and not self.emu_eng.emu:`
    //  only calls init_engine when the engine wrapper exists but no UC instance yet.
    if (!emu_eng_) {
        emu_eng_ = std::make_shared<EmuEngine>();
    }
    if (emu_eng_ && !emu_eng_->get_engine()) {
        int eng_arch = valid_arch ? img->arch : speakeasy::arch::ARCH_X86;
        int mode = (img->arch == 64) ? speakeasy::arch::BITS_64 : speakeasy::arch::BITS_32;
        emu_eng_->init_engine(eng_arch, mode);
    }
    if (!ptr_size_) 
        ptr_size_ = 4;

    if (!disasm_eng_) {
        cs_mode mode = (get_arch() == 64) ? CS_MODE_64 : CS_MODE_32;

        if (cs_open(CS_ARCH_X86, mode, &disasm_eng_) != CS_ERR_OK) {
            // TODO: log error
        }

        cs_option(disasm_eng_, CS_OPT_DETAIL, CS_OPT_OFF);
    }
    
    //  Initialize API handler (Python 1019-1022)
    if (!api) {
        api = std::make_shared<WindowsApi>(this);
    }

    advance_bootstrap_phase(BootstrapPhase::ENGINE_API_READY);
    bootstrap_object_services();

    //  Map image regions (Python 1027-1040) 
    // single_region_pe: only one region, base matches, image_size > region data
    bool single_region_pe = (!img->regions.empty()
                             && img->regions.size() == 1
                             && img->regions[0].base == img->base
                             && img->image_size > img->regions[0].data.size());

    for (auto& region : img->regions) {
        uint64_t base = region.base;
        size_t size;
        if (single_region_pe) {
            size = static_cast<size_t>(img->image_size);
        } else {
            size = region.data.size();
        }
        if (size == 0) continue;

        std::string tag = "emu.module." + (img->name.empty() ? "unnamed" : img->name);
        if (base == 0) {
            base = mem_map(static_cast<uint64_t>(size), 0, PERM_MEM_RWX, tag);
            img->base = base;
        } else {
            mem_map(static_cast<uint64_t>(size), base, PERM_MEM_RWX, tag);
        }
        if (!region.data.empty()) {
            mem_write(base, region.data);
        }
    }

    //// Map raw buffer if no regions (shellcode, etc.)
    //if (img->regions.empty() && !img->mapped_image.empty()) {
    //    size_t map_size = img->mapped_image.size();
    //    if (img->base == 0) {
    //        img->base = mem_map(static_cast<uint64_t>(map_size), 0, PERM_MEM_RWX,
    //                            "emu.module." + img->name);
    //    } else {
    //        mem_map(static_cast<uint64_t>(map_size), img->base, PERM_MEM_RWX,
    //                "emu.module." + img->name);
    //    }
    //    mem_write(img->base, img->mapped_image);
    //}

    //  Patch IAT with sentinel values for import hooking (Python 1042-1050) 

    for (auto& imp : img->imports) {
        uint64_t sentinel = _alloc_sentinel();
        import_table[sentinel] = {normalize_mod_name(imp.dll_name), imp.func_name};
        uint64_t iat_addr = imp.iat_address;
        std::vector<uint8_t> sent_bytes(ptr_size_);
        for (int i = 0; i < ptr_size_; ++i)
            sent_bytes[i] = static_cast<uint8_t>((sentinel >> (i * 8)) & 0xFF);
        try { mem_write(iat_addr, sent_bytes); } catch (...) {}
    }

    // Also patch from PE header (catches injected PEs that bypass the loader's import table)
    //ensure_pe_import_hooks(img->base);

    //  Apply PE section memory protection (Python 1052-1077) 
    // Python condition: isinstance(image.loader, PeLoader) and image.sections
    bool has_pe_loader = (dynamic_cast<speakeasy::PeLoader*>(img->loader) != nullptr);
    if (has_pe_loader && !img->sections.empty()) {
        uint64_t base = img->base;
        // Protect headers (before first section) as READ only
        uint32_t first_section_rva = img->sections[0].virtual_address;
        if (first_section_rva > 0) {
            uint64_t aligned_headers = (static_cast<uint64_t>(base + first_section_rva) + page_size_ - 1) 
                                        & ~(static_cast<uint64_t>(page_size_) - 1);
            try {
                mem_protect(base, aligned_headers - base, PERM_MEM_READ);
            } catch (...) {}
        }

        // Merge per-page permissions (multiple sections can share a page)
        std::map<uint64_t, int> page_perms;
        for (auto& sect : img->sections) {
            uint64_t section_addr = base + sect.virtual_address;
            uint64_t aligned_addr = section_addr & ~(static_cast<uint64_t>(page_size_) - 1);
            uint64_t end_addr = section_addr + sect.virtual_size;
            uint64_t aligned_end = (end_addr + page_size_ - 1) & ~(static_cast<uint64_t>(page_size_) - 1);

            for (uint64_t page_base = aligned_addr; page_base < aligned_end; page_base += page_size_) {
                int existing = 0;
                auto it = page_perms.find(page_base);
                if (it != page_perms.end()) existing = it->second;
                page_perms[page_base] = existing | static_cast<int>(sect.perms);
            }
        }

        for (auto& [page_base, perms] : page_perms) {
            try {
                mem_protect(page_base, static_cast<uint64_t>(page_size_), perms);
            } catch (...) {}
        }
    }

    //  Create RuntimeModule (Python 1079-1081) 
    std::shared_ptr<speakeasy::RuntimeModule> mod = std::make_shared<speakeasy::RuntimeModule>(img);
    if (img->base != 0 && mod->base != img->base)
        mod->base = img->base;

    //  Determine module type (Python 1083) 
    bool is_pe = (dynamic_cast<speakeasy::PeLoader*>(img->loader) != nullptr);
    bool is_shellcode = (img->module_type == "shellcode");
    bool is_primary = is_pe || is_shellcode;

    //  Normalize module name for API lookup (Python 1085-1086) 
    std::string mod_base_name;
    if (!img->emu_path.empty()) {
        auto pos = img->emu_path.find_last_of("/\\");
        mod_base_name = (pos != std::string::npos) ? img->emu_path.substr(pos + 1) : img->emu_path;
    } else {
        mod_base_name = img->name;
    }
    std::string mod_base_name_no_ext = normalize_mod_name(mod_base_name);

    //  Process exports: build symbol table and register hooks (Python 1088-1109) 
    bool has_api_exports = false;
    if (api) {
        std::shared_ptr<ApiHandler> handler = nullptr;
        ApiEntry func_info = InvalidApiInfo;

        for (auto& exp : img->exports) {
            if (exp.name.empty()) continue;
            // Use normalized name first, then try raw name (Python 1093-1095)
            std::tie(handler, func_info) = api->get_export_func_handler(mod_base_name_no_ext, exp.name);
            // normalize_import_miss for API handler resolution (Python:1094-1095)
            if (!func_info.handler) {
                std::tie(handler, func_info) = normalize_import_miss(mod_base_name_no_ext, exp.name);
            }
            // C++ uses different return types; the first lookup via get_export_func_handler is sufficient
            if (func_info.handler) {
                symbols[exp.address] = {mod_base_name_no_ext, exp.name};
                has_api_exports = true;
            }
            // Data export hooks for non-primary modules (Python 1099-1103)
            if (!is_primary) {
                auto [data_mod, data_hndlr] = api->get_data_export_handler(mod_base_name_no_ext, exp.name);
                if (data_hndlr.func && !config_.analysis.memory_tracing) {
                    add_mem_read_hook(mem_read_trampoline, exp.address, exp.address);
                    add_mem_write_hook(mem_write_trampoline, exp.address, exp.address);
                }
            }
        }

        // Module access hook for non-primary API modules (Python 1105-1109)
        if (!is_primary && has_api_exports && !img->regions.empty() && !config_.analysis.memory_tracing) {
            auto& first_region = img->regions[0];
            uint64_t mod_start = first_region.base ? first_region.base : img->base;
            uint64_t mod_end = mod_start + first_region.data.size();
            add_code_hook(module_access_trampoline, mod_start, mod_end);
        }

        // Process data imports (Python 1111-1118)
        for (auto& imp : img->imports) {
            auto [data_mod, eh] = api->get_data_export_handler(imp.dll_name, imp.func_name);
            if (eh.func) {
                uint64_t data_ptr = handle_import_data(imp.dll_name, imp.func_name);
                std::string sym = imp.dll_name + "." + imp.func_name;
                global_data[imp.iat_address] = {sym, data_ptr};
                if (data_ptr != 0) {
                    std::vector<uint8_t> ptr_bytes(ptr_size_);
                    for (int i = 0; i < ptr_size_; ++i) {
                        ptr_bytes[i] = static_cast<uint8_t>((data_ptr >> (i * 8)) & 0xFF);
                    }
                    try { mem_write(imp.iat_address, ptr_bytes); } catch (...) {}
                }
            }
        }
    }

    //  String profiling for primary modules (Python 1120-1124) 
    if (is_primary && profiler_ && config_.analysis.strings && !img->regions.empty()) {
        auto& raw = img->regions[0].data;
        if (!raw.empty()) {
            auto ansi_strs = get_ansi_strings(raw);
            auto uni_strs = get_unicode_strings(raw);
            std::vector<std::string> ansi_only, uni_only;
            for (auto& [offset, s] : ansi_strs) ansi_only.push_back(s);
            for (auto& [offset, s] : uni_strs) uni_only.push_back(s);
            profiler_->set_strings("ansi", ansi_only);
            profiler_->set_strings("unicode", uni_only);
        }
    }

    //  Register module (Python 1126) 
    modules_.push_back(mod);

    //  Allocate stack for primary image (Python 1128-1130)
    // Python: self.config.stack_size or image.stack_size  config takes precedence
    if (is_primary && stack_base_ == 0 && img->stack_size > 0) {
        size_t stack_size = (config_.stack_size > 0) ? static_cast<size_t>(config_.stack_size)
                                                      : static_cast<size_t>(img->stack_size);
        auto [sb, sp] = alloc_stack(stack_size);
        stack_base_ = sb;
    }

    //  Run one-time setup (Python 1132-1135) 
    // Python winemu.py:1132-1135  setup() internally calls advance_bootstrap_phase(FULL_SETUP_READY).
    // C++ setup() does not, so we advance here at the same logical point in the call chain.
    if (!_setup_done) {
        _setup_done = true;
        setup();
        advance_bootstrap_phase(BootstrapPhase::FULL_SETUP_READY);
    }

    return mod;
}

void WindowsEmulator::ensure_pe_import_hooks(uint64_t base_addr) {
    // Python reference: winemu.py lines 865-977
    int psz = get_ptr_size();
    if (psz == 0) psz = 4;
    bool is64 = (get_arch() == speakeasy::arch::ARCH_AMD64);

    //  Read DOS header  verify MZ 
    auto dos_hdr = mem_read(base_addr, 0x40);
    if (dos_hdr.size() < 0x40 || dos_hdr[0] != 'M' || dos_hdr[1] != 'Z')
        return;

    //  Read PE offset (e_lfanew) 
    uint32_t e_lfanew = 0;
    for (int i = 0; i < 4; ++i)
        e_lfanew |= static_cast<uint32_t>(dos_hdr[0x3C + i]) << (i * 8);
    uint64_t pe_sig_off = base_addr + e_lfanew;

    //  Read PE header  verify signature 
    auto pe_hdr = mem_read(pe_sig_off, 0x18);
    if (pe_hdr.size() < 4 || pe_hdr[0] != 'P' || pe_hdr[1] != 'E')
        return;

    //  Read Optional Header  get import directory 
    // Optional Header starts at pe_sig_off + 0x18 (after Signature + FileHeader)
    uint64_t opt_off = pe_sig_off + 0x18;
    uint32_t import_dir_rva = 0, import_dir_size = 0;

    if (is64) {
        // PE32+: IMAGE_OPTIONAL_HEADER64  import dir at offset 0x70 in opt hdr
        auto opt = mem_read(opt_off, 0x70 + 16 * 8);
        if (opt.size() < 0x80) return;
        import_dir_rva = opt[0x70] | (static_cast<uint32_t>(opt[0x71]) << 8) |
                        (static_cast<uint32_t>(opt[0x72]) << 16) | (static_cast<uint32_t>(opt[0x73]) << 24);
        import_dir_size = opt[0x74] | (static_cast<uint32_t>(opt[0x75]) << 8) |
                         (static_cast<uint32_t>(opt[0x76]) << 16) | (static_cast<uint32_t>(opt[0x77]) << 24);
    } else {
        // PE32: IMAGE_OPTIONAL_HEADER32  import dir at offset 0x68 in opt hdr
        auto opt = mem_read(opt_off, 0x60 + 16 * 8);
        if (opt.size() < 0x70) return;
        import_dir_rva = opt[0x68] | (static_cast<uint32_t>(opt[0x69]) << 8) |
                        (static_cast<uint32_t>(opt[0x6A]) << 16) | (static_cast<uint32_t>(opt[0x6B]) << 24);
        import_dir_size = opt[0x6C] | (static_cast<uint32_t>(opt[0x6D]) << 8) |
                         (static_cast<uint32_t>(opt[0x6E]) << 16) | (static_cast<uint32_t>(opt[0x6F]) << 24);
    }

    if (!import_dir_rva || !import_dir_size) return;

    //  Walk IMAGE_IMPORT_DESCRIPTOR array 
    uint64_t import_dir_va = base_addr + import_dir_rva;
    const size_t desc_size = 20;  // sizeof(IMAGE_IMPORT_DESCRIPTOR)
    int n_descriptors = 0, n_fixups = 0;

    for (;;) {
        uint64_t desc_off = import_dir_va + n_descriptors * desc_size;
        auto desc = mem_read(desc_off, desc_size);
        if (desc.size() < desc_size) break;

        // struct IMAGE_IMPORT_DESCRIPTOR:
        //   +0: ILT RVA (OriginalFirstThunk)
        //   +8: TimeDateStamp
        //  +12: ForwarderChain
        //  +16: Name RVA
        //  +20: IAT RVA (FirstThunk)
        uint32_t ilt_rva  = desc[0] | (static_cast<uint32_t>(desc[1]) << 8) |
                           (static_cast<uint32_t>(desc[2]) << 16) | (static_cast<uint32_t>(desc[3]) << 24);
        uint32_t name_rva = desc[12] | (static_cast<uint32_t>(desc[13]) << 8) |
                           (static_cast<uint32_t>(desc[14]) << 16) | (static_cast<uint32_t>(desc[15]) << 24);
        uint32_t iat_rva  = desc[16] | (static_cast<uint32_t>(desc[17]) << 8) |
                           (static_cast<uint32_t>(desc[18]) << 16) | (static_cast<uint32_t>(desc[19]) << 24);

        if (!name_rva && !iat_rva) break;
        n_descriptors++;

        //  Read DLL name 
        auto dll_bytes = mem_read(base_addr + name_rva, 256);
        std::string dll_name;
        {
            size_t null_pos = 0;
            for (; null_pos < dll_bytes.size() && dll_bytes[null_pos] != 0; ++null_pos);
            if (null_pos > 0)
                dll_name.assign(reinterpret_cast<const char*>(dll_bytes.data()), null_pos);
        }
        if (dll_name.empty()) continue;

        //  Walk thunk entries 
        uint32_t thunk_rva = ilt_rva ? ilt_rva : iat_rva;
        int idx = 0;

        for (;;) {
            uint64_t thunk_va = base_addr + thunk_rva + idx * psz;
            uint64_t iat_va   = base_addr + iat_rva   + idx * psz;
            idx++;

            auto thunk_data = mem_read(thunk_va, static_cast<size_t>(psz));
            if (thunk_data.size() < static_cast<size_t>(psz)) break;

            uint64_t thunk_val = 0;
            for (int i = 0; i < psz; ++i)
                thunk_val |= static_cast<uint64_t>(thunk_data[i]) << (i * 8);
            if (thunk_val == 0) break;

            //  Check if already patched 
            auto iat_data = mem_read(iat_va, static_cast<size_t>(psz));
            uint64_t iat_val = 0;
            for (int i = 0; i < psz; ++i)
                iat_val |= static_cast<uint64_t>(iat_data[i]) << (i * 8);

            if (import_table.count(iat_val)) continue;

            //  Resolve function name 
            bool is_ordinal = (is64 ? ((thunk_val >> 63) & 1) : ((thunk_val >> 31) & 1));
            std::string func_name;

            if (is_ordinal) {
                uint16_t ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
                func_name = "ordinal_" + std::to_string(ordinal);
            } else {
                uint64_t hint_name_rva = thunk_val & 0x7FFFFFFFULL;
                auto hint_data = mem_read(base_addr + hint_name_rva, 256);
                if (hint_data.size() > 2) {
                    // hint_data[0..1] = hint (2 bytes), rest = NUL-terminated string
                    size_t null_pos = 2;
                    for (; null_pos < hint_data.size() && hint_data[null_pos] != 0; ++null_pos);
                    if (null_pos > 2)
                        func_name.assign(reinterpret_cast<const char*>(hint_data.data() + 2), null_pos - 2);
                }
            }
            if (func_name.empty()) continue;

            //  Allocate sentinel & patch IAT 
            uint64_t sentinel = _alloc_sentinel();
            import_table[sentinel] = {normalize_mod_name(dll_name), func_name};

            std::vector<uint8_t> sent_bytes(psz);
            for (int i = 0; i < psz; ++i)
                sent_bytes[i] = static_cast<uint8_t>((sentinel >> (i * 8)) & 0xFF);
            mem_write(iat_va, sent_bytes);
            n_fixups++;
        }
    }
}

// Python winemu.py:652
// def get_current_thread(self):
//     """Get the current thread that is emulating"""

std::shared_ptr<Thread> WindowsEmulator::get_current_thread() { return curr_thread; }
std::shared_ptr<Process> WindowsEmulator::get_current_process() { return curr_process_; }
// Python winemu.py:664
// def set_current_process(self, process):
//     """Set the current process that is emulating"""

void WindowsEmulator::set_current_process(std::shared_ptr<Process> process) { curr_process_ = process; }
// Python winemu.py:670
// def set_current_thread(self, thread):
//     """Set the current thread"""

void WindowsEmulator::set_current_thread(std::shared_ptr<Thread> thread) { curr_thread = thread; }

// Python winemu.py:1226
// def create_process(self, path=None, cmdline=None, image=None, child=False):
//     """Create a process object that will exist in the emulator"""
std::shared_ptr<Process> WindowsEmulator::create_process(const std::string& path,
                                       const std::string& cmdline,
    std::shared_ptr<speakeasy::RuntimeModule> image, bool child) {
    validate_object_services("process creation");

    // Determine file path from cmdline if path not given
    std::string file_path = path;
    if (file_path.empty() && !cmdline.empty()) {
        file_path = cmdline;
        // Strip quotes from first token
        auto sp = file_path.find(' ');
        if (sp != std::string::npos) file_path = file_path.substr(0, sp);
        if (file_path.size() >= 2 && file_path.front() == '"' && file_path.back() == '"')
            file_path = file_path.substr(1, file_path.size() - 2);
    }

    auto p = std::make_shared<Process>(this);

    if (!image) {
        // Try to get PE data from emulated filesystem
        auto mod_data = get_module_data_from_emu_file(file_path);
        if (!mod_data.empty()) {
            // Load PE from raw data
            try {
                speakeasy::PeLoader loader(file_path, mod_data);
                auto img = loader.make_image();
                auto rtmod = load_image(img);
                p->pe = rtmod;
            } catch (...) {
                p->pe = nullptr;
            }
        } else {
            // Fall back to loading by name
            p->pe = load_module_by_name(file_path, path);
        }
    } else {
        p->pe = image;
    }

    p->path = file_path;
    p->cmdline = cmdline;

    // Create an initial thread for the process
    auto t = std::make_shared<Thread>(this);
    p->threads.push_back(t);

    if (child) {
        child_processes_.push_back(p);
    } else {
        processes_.push_back(p);
    }

    return p;
}

// Python winemu.py:1293
// def create_thread(self, addr, ctx, proc_obj, thread_type="thread", is_suspended=False):
//     """Create a thread object that will exist in the emulator"""
std::shared_ptr<Thread> WindowsEmulator::create_thread(uint64_t addr, void* ctx, std::shared_ptr<Process> proc_obj,
                                      const std::string& thread_type, bool is_suspended) {
    validate_object_services("thread creation");

    if (run_queue.size() >= static_cast<size_t>(max_runs)) {
        return nullptr;
    }

    auto thread = std::make_shared<Thread>(this);
    thread->set_process(proc_obj);

    auto run = std::make_shared<Run>();
    run->type = thread_type;
    run->start_addr = addr;
    run->instr_cnt = 0;
    run->args = {reinterpret_cast<const char*>(&ctx), reinterpret_cast<const char*>(&ctx) + sizeof(ctx)};
    run->process_context = proc_obj;
    run->thread = thread;

    if (!is_suspended) {
        run_queue.push_back(run);
    } else {
        suspended_runs.push_back(run);
    }

    return thread;
}

//  Module loading 


// Python winemu.py:2180
// def get_native_module_path(self, mod_name=""):
//     """Get the full filesystem path of a default decoy that is supplied by speakeasy"""
std::string WindowsEmulator::get_native_module_path(const std::string& mod_name) {
    std::string name = speakeasy::to_lower(mod_name);

    auto get_fp = [](const std::string& dir_path, const std::string& target_name) -> std::string {
        std::string norm_dir = normalize_package_path(dir_path);
        fs::path p(norm_dir);
        if (!fs::exists(p) || !fs::is_directory(p)) return "";

        for (const auto& entry : fs::directory_iterator(p)) {
            if (!entry.is_regular_file()) continue;
            std::string fn = speakeasy::to_lower(entry.path().filename().string());
            std::string base = fn;
            auto dot = base.find_last_of('.');
            if (dot != std::string::npos) base = base.substr(0, dot);
            if (base == target_name) return entry.path().string();
        }
        return "";
    };

    const char* dirs_1 = (arch_ == speakeasy::arch::ARCH_AMD64) ? "amd64" : "x86";
    std::string mod_dir = (arch_ == speakeasy::arch::ARCH_AMD64) ? config_.modules.module_directory_x64 : config_.modules.module_directory_x86;

    std::string fp = get_fp(mod_dir, name);
    if (fp.empty()) {
        std::string fallback_dir = std::string("$ROOT$/winenv/decoys/") + dirs_1;
        fp = get_fp(fallback_dir, name);
    }
    return fp;
}


// Python winemu.py:2212
// def load_library(self, mod_name):
//     """Load a library (DLL) by name. Returns its base address or 0."""
void* WindowsEmulator::load_library(const std::string& mod_name) {
    std::string lib = normalize_mod_name(mod_name);

    // Check if already loaded
    auto existing = get_mod_by_name(lib);
    if (existing) {
        return reinterpret_cast<void*>(existing->base);
    }

    if (!modules_always_exist) return nullptr;

    auto mod = load_module_by_name(lib);
    if (!mod) return nullptr;

    // Add to current process PEB if available
    auto proc = get_current_process();
    if (proc && proc->peb_ldr_data) {
        proc->add_module_to_peb(mod);
    }

    return reinterpret_cast<void*>(mod->base);
}


// Python winemu.py:2231
// def load_module_by_name(self, name, emu_path=None, base=None):
//     """Load a module by name using the appropriate loader.
//     Priority: native PE file -> API handler (JIT PE) -> placeholder stub."""
std::shared_ptr<speakeasy::RuntimeModule> WindowsEmulator::load_module_by_name(const std::string& name,
                                            const std::string& emu_path,
                                            uint64_t base) {
    if (base == 0) base = 0x6F000000;

    std::string ep = emu_path;
    if (ep.empty()) {
        ep = cd.empty() ? "C:\\Windows\\system32\\" : cd;
        if (!ep.empty() && ep.back() != '\\' && ep.back() != '/') {
            ep += "\\";
        }
        ep += name + ".dll";
    }

    std::string native_path = get_native_module_path(name);
    std::shared_ptr<speakeasy::LoadedImage> img = nullptr;

    // Priority 1: Native PE file on disk
    if (!native_path.empty()) {
        try {
            speakeasy::PeLoader loader(native_path, std::vector<uint8_t>{}, static_cast<int>(base), ep);
            img = loader.make_image();
        } catch (...) {
            // Fall through if native PE parsing failed
        }
    }

    // Priority 2: API handler (JIT PE synthetic image)
    if (!img) {
        auto handler = api ? api->load_api_handler(name) : nullptr;
        if (handler) {
            // Special case: ntdll also loads ntoskrnl handler for Zw/Nt stubs
            if (name == "ntdll" && api) {
                auto nt_handler = api->load_api_handler("ntoskrnl");
                if (nt_handler) {
                    // Attach nt_handler to the ntdll handler if supported in C++
                    handler->set_nt_handler(nt_handler);
                }
            }

            speakeasy::ApiModuleLoader api_loader(name, handler, get_arch(), base, ep);
            try {
                img = api_loader.make_image();
            } catch (...) {}
        }
    }

    // Priority 3: Fallback PE file (default_exe template)
    if (!img) {
        std::string fallback_path = get_native_module_path("default_exe");
        if (!fallback_path.empty()) {
            try {
                speakeasy::PeLoader loader(fallback_path, std::vector<uint8_t>{}, static_cast<int>(base), ep);
                img = loader.make_image();
            } catch (...) {}
        }
    }

    // Priority 4: Decoy placeholder stub for PEB visibility
    if (!img) {
        try {
            speakeasy::DecoyLoader decoy(name, base, ep, 0x1000);
            img = decoy.make_image();
        } catch (...) {}
    }

    if (img) {
        img->name = name;
        img->emu_path = ep;
        img->is_dll = true;
        img->module_type = "dll";
        return load_image(img);
    }

    return nullptr;
}


// Python winemu.py:2278
// def get_module_data_from_emu_file(self, file_path):
//     """Get raw PE data from a file inside the emulated filesystem."""
std::vector<uint8_t> WindowsEmulator::get_module_data_from_emu_file(
    const std::string& file_path) {
    if (!fileman || !does_file_exist(file_path)) return {};

    auto mod_file = fileman->get_file_from_path(file_path);
    if (!mod_file) return {};

    // Get the raw bytes from the file object
    return mod_file->get_data(-1, false);
}


// Python winemu.py:2292
// def init_environment(self, system_modules=None, user_modules=None):
//     """Initialize the emulated system and user module environments."""
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> WindowsEmulator::init_environment(
    const std::vector<std::shared_ptr<speakeasy::Module>>& system_modules,
    const std::vector<std::shared_ptr<speakeasy::Module>>& user_modules) {

    auto sys_mods = _init_module_group(system_modules, 0);
    _init_module_group(user_modules, 0x6F000000);
    return sys_mods;
}


// Python winemu.py:2302
// def init_sys_modules(self, modules_config):
//     """Initialize system modules from the config."""
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> WindowsEmulator::init_sys_modules(
    const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config) {
    return _init_module_group(modules_config, 0);
}


// Python winemu.py:2305
// def init_user_modules(self, modules_config):
//     """Initialize user modules from the config."""
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> WindowsEmulator::init_user_modules(
    const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config) {
    return _init_module_group(modules_config, 0x6F000000);
}


// Python winemu.py:2308
// def _init_module_group(self, modules_config, default_base=None):
//     """Initialize a group of modules from config objects.
//     Python: for modconf in modules_config:
//         modname = getattr(modconf, "name", None) or "unknown"
//         base_addr = getattr(modconf, "base_addr", None) or default_base
//         emu_path = getattr(modconf, "path", None) or (modname + ".dll")
//         images = getattr(modconf, "images", []) or []
//         native_path = self.get_native_module_path(mod_name=modname)
//         Priority: native PE file -> API handler (JIT PE) -> placeholder stub."""
std::vector<std::shared_ptr<speakeasy::RuntimeModule>> WindowsEmulator::_init_module_group(
    const std::vector<std::shared_ptr<speakeasy::Module>>& modules_config, uint64_t default_base) {
    // Python winemu.py:2308-2362  initialize a group of modules from config objects
    // For each module: try native PE file  API handler (synthetic)  decoy placeholder
    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> rtmods;
    
    for (const auto& modconf : modules_config) {
        if (!modconf) continue;
        
        std::string modname = modconf->name.empty() ? "unknown" : modconf->name;
        uint64_t base_addr = modconf->base ? modconf->base : default_base;
        std::string emu_path = modconf->path.empty() ? (modname + ".dll") : modconf->path;
        
        // Priority 1: Native PE file
        std::string native_path = get_native_module_path(modname);
        
        std::shared_ptr<speakeasy::RuntimeModule> rtmod;
        
        if (!native_path.empty()) {
            // PE file exists on disk  PeLoader
            try {
                speakeasy::PeLoader loader(native_path);
                auto img = loader.make_image();
                if (base_addr) img->base = base_addr;
                img->emu_path = emu_path;
                img->name = modname;
                rtmod = load_image(img);
            } catch (...) {
                // PE parsing failed, fall through to API handler / decoy
            }
        }
        
        if (!rtmod) {
            // Priority 2: API handler  ApiModuleLoader (synthetic PE)
            if (api) {
                auto handler = api->load_api_handler(modname);
                if (handler) {
                    // Special case: ntdll also loads ntoskrnl handler for Zw/Nt stubs
                    if (modname == "ntdll") {
                        auto nt_handler = api->load_api_handler("ntoskrnl");
                        if (nt_handler) {
                            // Attach nt_handler to the ntdll handler
                            handler->set_nt_handler(nt_handler);
                        }
                    }
                    
                    speakeasy::ApiModuleLoader api_loader(modname, handler,
                        get_arch(), base_addr ? base_addr : 0, emu_path);
                    auto img = api_loader.make_image();
                    img->name = modname;
                    rtmod = load_image(img);
                }
            }
        }
        
        if (!rtmod) {
            // Priority 3: DecoyLoader  minimal PEB-visible stub
            speakeasy::DecoyLoader decoy(modname, base_addr ? base_addr : 0,
                                         emu_path, modconf->image_size);
            auto img = decoy.make_image();
            img->name = modname;
            rtmod = load_image(img);
        }
        
        if (rtmod) {
            rtmods.push_back(rtmod);
        }
    }
    return rtmods;
}


//  Thread context 


// Python winemu.py:2364
// def get_thread_context(self, thread=None):
//     """Get the current thread CPU context"""
std::shared_ptr<speakeasy::deffs::windows::CONTEXT> WindowsEmulator::get_thread_context32(std::shared_ptr<Thread> thread) {
    std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx = std::make_shared<speakeasy::deffs::windows::CONTEXT>();
    ctx->Edi = reg_read(speakeasy::arch::REG_EDI);
    ctx->Esi = reg_read(speakeasy::arch::REG_ESI);
    ctx->Eax = reg_read(speakeasy::arch::REG_EAX);
    ctx->Ebp = reg_read(speakeasy::arch::REG_EBP);
    ctx->Edx = reg_read(speakeasy::arch::REG_EDX);
    ctx->Ecx = reg_read(speakeasy::arch::REG_ECX);
    ctx->Ebx = reg_read(speakeasy::arch::REG_EBX);
    ctx->Esp = reg_read(speakeasy::arch::REG_ESP);
    ctx->Eip = reg_read(speakeasy::arch::REG_EIP);
    ;
    ctx->EFlags = reg_read(speakeasy::arch::REG_EFLAGS);
    ctx->SegCs = reg_read(speakeasy::arch::REG_CS);
    ctx->SegSs = reg_read(speakeasy::arch::REG_SS);
    ctx->SegDs = reg_read(speakeasy::arch::REG_DS);
    ctx->SegFs = reg_read(speakeasy::arch::REG_FS);
    ctx->SegGs = reg_read(speakeasy::arch::REG_GS);
    ctx->SegEs = reg_read(speakeasy::arch::REG_ES);

    return ctx;
}

std::shared_ptr<speakeasy::deffs::windows::CONTEXT64> WindowsEmulator::get_thread_context64(std::shared_ptr<Thread> thread) {
    //(void)thread;
    //if (!emu_eng_) return nullptr;

    std::shared_ptr<speakeasy::deffs::windows::CONTEXT64> ctx = std::make_shared<speakeasy::deffs::windows::CONTEXT64>();

    ctx->Rax = reg_read(speakeasy::arch::REG_RAX);
    ctx->Rbx = reg_read(speakeasy::arch::REG_RBX);
    ctx->Rcx = reg_read(speakeasy::arch::REG_RCX);
    ctx->Rdx = reg_read(speakeasy::arch::REG_RDX);
    ctx->Rsi = reg_read(speakeasy::arch::REG_RSI);
    ctx->Rdi = reg_read(speakeasy::arch::REG_RDI);
    ctx->Rbp = reg_read(speakeasy::arch::REG_RBP);
    ctx->Rsp = reg_read(speakeasy::arch::REG_RSP);
    ctx->Rip = reg_read(speakeasy::arch::REG_RIP);
    ctx->R8 = reg_read(speakeasy::arch::REG_R8);
    ctx->R9 = reg_read(speakeasy::arch::REG_R9);
    ctx->R10 = reg_read(speakeasy::arch::REG_R10);
    ctx->R11 = reg_read(speakeasy::arch::REG_R11);
    ctx->R12 = reg_read(speakeasy::arch::REG_R12);
    ctx->R13 = reg_read(speakeasy::arch::REG_R13);
    ctx->R14 = reg_read(speakeasy::arch::REG_R14);
    ctx->R15 = reg_read(speakeasy::arch::REG_R15);
    ctx->EFlags = reg_read(speakeasy::arch::REG_EFLAGS);
    ctx->SegCs = reg_read(speakeasy::arch::REG_CS);
    ctx->SegSs = reg_read(speakeasy::arch::REG_SS);
    ctx->SegDs = reg_read(speakeasy::arch::REG_DS);
    ctx->SegFs = reg_read(speakeasy::arch::REG_FS);
    ctx->SegGs = reg_read(speakeasy::arch::REG_GS);
    ctx->SegEs = reg_read(speakeasy::arch::REG_ES);

    return ctx;
}

std::shared_ptr<EmuStruct> WindowsEmulator::get_thread_context(std::shared_ptr<Thread> thread) {
    if (get_arch() == speakeasy::arch::ARCH_X86) {
        return get_thread_context32(thread);
    }
    else if (get_arch() == speakeasy::arch::ARCH_AMD64) {
        return get_thread_context64(thread);
    }
    return nullptr;
}



// Python winemu.py:2418
// def load_thread_context(self, ctx, thread=None):
//     """Set the current thread CPU context"""
void WindowsEmulator::load_thread_context32(std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx, std::shared_ptr<Thread> thread) {
    reg_write(speakeasy::arch::REG_EDI, ctx->Edi);
    reg_write(speakeasy::arch::REG_ESI, ctx->Esi);
    reg_write(speakeasy::arch::REG_EAX, ctx->Eax);
    reg_write(speakeasy::arch::REG_EBP, ctx->Ebp);
    reg_write(speakeasy::arch::REG_EDX, ctx->Edx);
    reg_write(speakeasy::arch::REG_ECX, ctx->Ecx);
    reg_write(speakeasy::arch::REG_EBX, ctx->Ebx);
    reg_write(speakeasy::arch::REG_ESP, ctx->Esp);
    reg_write(speakeasy::arch::REG_EIP, ctx->Eip);
    reg_write(speakeasy::arch::REG_EFLAGS, ctx->EFlags);
    reg_write(speakeasy::arch::REG_CS, ctx->SegCs);
    reg_write(speakeasy::arch::REG_SS, ctx->SegSs);
    reg_write(speakeasy::arch::REG_DS, ctx->SegDs);
    reg_write(speakeasy::arch::REG_FS, ctx->SegFs);
    reg_write(speakeasy::arch::REG_GS, ctx->SegGs);
    reg_write(speakeasy::arch::REG_ES, ctx->SegEs);
}

void WindowsEmulator::load_thread_context64(std::shared_ptr<speakeasy::deffs::windows::CONTEXT64> ctx, std::shared_ptr<Thread> thread) {
    reg_write(speakeasy::arch::REG_RAX, ctx->Rax);
    reg_write(speakeasy::arch::REG_RBX, ctx->Rbx);
    reg_write(speakeasy::arch::REG_RCX, ctx->Rcx);
    reg_write(speakeasy::arch::REG_RDX, ctx->Rdx);
    reg_write(speakeasy::arch::REG_RSI, ctx->Rsi);
    reg_write(speakeasy::arch::REG_RDI, ctx->Rdi);
    reg_write(speakeasy::arch::REG_RBP, ctx->Rbp);
    reg_write(speakeasy::arch::REG_RSP, ctx->Rsp);
    reg_write(speakeasy::arch::REG_RIP, ctx->Rip);
    reg_write(speakeasy::arch::REG_R8, ctx->R8);
    reg_write(speakeasy::arch::REG_R9, ctx->R9);
    reg_write(speakeasy::arch::REG_R10, ctx->R10);
    reg_write(speakeasy::arch::REG_R11, ctx->R11);
    reg_write(speakeasy::arch::REG_R12, ctx->R12);
    reg_write(speakeasy::arch::REG_R13, ctx->R13);
    reg_write(speakeasy::arch::REG_R14, ctx->R14);
    reg_write(speakeasy::arch::REG_R15, ctx->R15);

    reg_write(speakeasy::arch::REG_EFLAGS, ctx->EFlags);
    reg_write(speakeasy::arch::REG_CS, ctx->SegCs);
    reg_write(speakeasy::arch::REG_SS, ctx->SegSs);
    reg_write(speakeasy::arch::REG_DS, ctx->SegDs);
    reg_write(speakeasy::arch::REG_FS, ctx->SegFs);
    reg_write(speakeasy::arch::REG_GS, ctx->SegGs);
    reg_write(speakeasy::arch::REG_ES, ctx->SegEs);
}

void WindowsEmulator::load_thread_context(std::shared_ptr<EmuStruct> ctx, std::shared_ptr<Thread> thread) {
    if (get_arch() == speakeasy::arch::ARCH_X86) {
        return load_thread_context32(std::dynamic_pointer_cast<speakeasy::deffs::windows::CONTEXT>(ctx), thread);
    }
    else if (get_arch() == speakeasy::arch::ARCH_AMD64) {
        return load_thread_context64(std::dynamic_pointer_cast<speakeasy::deffs::windows::CONTEXT64>(ctx), thread);
    }
}


//  SEH 


// Python winemu.py:2662
// def dispatch_seh(self, except_code, faulting_address=None):
//     """Dispatch a structured exception by walking the SEH chain. Falls back
//     to unhandled exception filter if available."""
bool WindowsEmulator::dispatch_seh(uint64_t except_code, std::optional<uint64_t> faulting_address) {
    auto fault_key = std::make_tuple(get_pc(), faulting_address);
    if (fault_key == _seh_last_fault) {
        _seh_repeat_count++;
        if (_seh_repeat_count >= _SEH_MAX_REPEAT) return false;
    } else {
        _seh_last_fault = fault_key;
        _seh_repeat_count = 1;
    }

    bool rv = false;
    if (ptr_size_ == 4) {
        rv = _dispatch_seh_x86(except_code);
    } else {
        // x64: VEH (Vectored Exception Handling)  walk VEH handler list
        for (auto* veh : veh_handlers) {
            uint64_t handler = reinterpret_cast<uint64_t>(veh);
            if (handler == 0 || handler == 0xFFFFFFFFFFFFFFFFULL) continue;
            curr_exception_code = except_code;
            call(handler);
            rv = true;
            break;
        }
    }

    // Python: if not rv and self.unhandled_exception_filter:
    //   Fall back to the unhandled exception filter (SetUnhandledExceptionFilter API)
    if (!rv && unhandled_exception_filter != 0) {
        int psz = ptr_size_;

        // Build EXCEPTION_RECORD
        speakeasy::deffs::windows::EXCEPTION_RECORD<4> record;
        record.ExceptionCode    = except_code;
        record.ExceptionFlags   = 0;
        record.ExceptionAddress = get_pc();
        record.NumberParameters = 0;

        // Build EXCEPTION_POINTERS
        speakeasy::deffs::windows::EXCEPTION_POINTERS<4> eptrs;
        auto p_exp_ptrs = mem_map(eptrs.sizeof_obj(), std::nullopt, PERM_MEM_RWX, "emu.struct.EXCEPTION_POINTERS");
        auto prec = mem_map(record.sizeof_obj(), std::nullopt, PERM_MEM_RWX, "emu.struct.EXCEPTION_RECORD");
        auto _ctx = get_thread_context32();
        auto pctx = mem_map(_ctx->sizeof_obj(), std::nullopt, PERM_MEM_RWX, "emu.struct.EXCEPTION_CONTEXT");

        eptrs.ExceptionRecord = prec;
        eptrs.ContextRecord   = pctx;

        mem_write(p_exp_ptrs, eptrs.get_bytes());
        mem_write(prec, record.get_bytes());
        mem_write(pctx, _ctx->get_bytes());

        // Python: set_func_args(sp, EMU_RETURN_ADDR, p_exp_ptrs)
        //         set_pc(self.unhandled_exception_filter)
        uint64_t sp = get_stack_ptr();
        set_func_args(sp, EMU_RETURN_ADDR, {p_exp_ptrs});
        set_pc(unhandled_exception_filter);
        unhandled_exception_filter = 0;
        rv = true;
    }

    if (rv && faulting_address.has_value()) {
        // Map a page at the faulting address so we can continue execution
        // uint64_t page_addr = faulting_address & ~(page_size_ - 1);
        _map_faulting_page_for_exception(*faulting_address);
    }

    return rv;
}


// Python winemu.py:2478
// def _dispatch_seh_x86(self, except_code):
//     """Get the initial SEH handler when dispatching a CPU exception that occurs during emulation"""
bool WindowsEmulator::_dispatch_seh_x86(uint64_t except_code) {
    // Python winemu.py:2488-2591  _dispatch_seh_x86
    auto thread = get_current_thread();
    if (!thread) return false;

    SEH& seh = thread->get_seh();
    uint64_t exception_list = _get_exception_list();
    int psz = ptr_size_;
    if (exception_list == 0 || exception_list == 0xFFFFFFFF) return false;

    seh.last_exception_code_ = static_cast<int>(except_code);

    // Python: create _EXCEPTION_RECORD
    speakeasy::deffs::windows::EXCEPTION_RECORD<4> record;
    record.ExceptionCode    = except_code;
    record.ExceptionFlags   = 0;
    record.ExceptionAddress = get_pc();
    record.NumberParameters = 0;

    // Python: cast EXCEPTION_REGISTRATION from exception_list
    speakeasy::deffs::windows::EXCEPTION_REGISTRATION<4> ereg;
    speakeasy::deffs::windows::EXCEPTION_POINTERS<4> eptrs;

    mem_cast(&ereg, exception_list);
    uint64_t sp = get_stack_ptr();

    // Python: map exception structures into emulated memory
    auto p_exp_ptrs = mem_map(eptrs.sizeof_obj(), std::nullopt, common::PERM_MEM_RWX, "emu.struct.EXCEPTION_POINTERS");
    auto prec = mem_map(record.sizeof_obj(), std::nullopt, common::PERM_MEM_RWX, "emu.struct.EXCEPTION_RECORD");
    auto _ctx = get_thread_context32();
    auto pctx = mem_map(_ctx->sizeof_obj(), std::nullopt, common::PERM_MEM_RWX, "emu.struct.EXCEPTION_CONTEXT");

    eptrs.ExceptionRecord = prec;
    eptrs.ContextRecord   = pctx;

    // Python: self.mem_write(pctx, _ctx.get_bytes())
    mem_write(pctx, _ctx->get_bytes());
    seh.set_context(_ctx, static_cast<uint64_t>(pctx));

    // Python: self.mem_write(p_exp_ptrs, exp_ptrs.get_bytes())
    //         self.mem_write(prec, record.get_bytes())
    mem_write(p_exp_ptrs, eptrs.get_bytes());
    mem_write(prec, record.get_bytes());

    // Python: write exp_ptrs BEFORE the exception_list on stack (ms_exc convention)
    std::vector<uint8_t> exp_ptr_bytes(static_cast<size_t>(psz), 0);
    write_le(exp_ptr_bytes, 0, p_exp_ptrs, static_cast<size_t>(psz));
    mem_write(exception_list - static_cast<uint64_t>(psz), exp_ptr_bytes);

    // Python: set_func_args(sp, winemu.SEH_RETURN_ADDR, prec, exception_list, pctx, 0)
    set_func_args(sp, SEH_RETURN_ADDR, {prec, exception_list, pctx, 0});

    // Python: logging -- disasm the faulting instruction
    auto run = get_current_run();
    auto regs = get_register_state();
    uint64_t pc = prev_pc;

    std::string instr = "disasm_failed";
    try {
        auto [mnem, op, _] = get_disasm(pc, DISASM_SIZE, false);
        instr = mnem + (op.empty() ? "" : " " + op);
    } catch (...) {}

    std::string pc_module = _resolve_module_offset(pc);
    std::string handler_desc = hex_str(ereg.Handler);
    {
        auto hm = _resolve_module_offset(ereg.Handler);
        if (!hm.empty()) handler_desc += " (" + hm + ")";
    }
    std::string pc_desc = pc_module.empty() ? ("0x" + hex_str(pc)) : pc_module;

    log_debug(hex_str(pc) + ": Exception caught: code=" + hex_str(except_code) +
             " handler=" + handler_desc + " instr=\"" + instr + "\"\n  pc: " + pc_desc);

    // Python: profiler exception event
    if (profiler_ && run) {
        int tick = run->instr_cnt;
        int tid  = curr_thread ? curr_thread->get_tid() : 0;
        auto proc = get_current_process();
        int pid  = proc ? proc->get_pid() : 0;
        std::string fault_addr;
        if (except_code == 0xC0000005) {  // STATUS_ACCESS_VIOLATION
            fault_addr = "0x" + hex_str(prev_pc);
        }
        profiler_->record_exception_event(run, {
            {"tick",    std::to_string(tick)},
            {"tid",     std::to_string(tid)},
            {"pid",     std::to_string(pid)},
            {"pc",      "0x" + hex_str(pc)},
            {"instr",   instr},
            {"code",    "0x" + hex_str(except_code)},
            {"handler", "0x" + hex_str(ereg.Handler)},
            {"pc_desc", pc_desc},
            {"fault_address", fault_addr},
        });
    }

    // Python: EBX clobber to 0xFFFFFFFF (observed in real VMs)
    reg_write(speakeasy::arch::REG_EBX, 0xFFFFFFFF);

    // Python: self.set_pc(entry.Handler)
    if (ereg.Handler == 0 || ereg.Handler == 0xFFFFFFFF) return false;
    set_pc(ereg.Handler);
    return true;
}


// Python winemu.py:2589
// def _continue_seh_x86(self):
//     """Get the next exception handler while processing SEH"""
void WindowsEmulator::_continue_seh_x86() {
    auto thread = get_current_thread();
    if (!thread) {
        on_run_complete();
        return;
    }

    SEH& seh = thread->get_seh();
    uint32_t sp = static_cast<uint32_t>(get_stack_ptr());
    uint32_t ret_val = static_cast<uint32_t>(get_return_val());

    if (seh.handler_ret_val_ == nullptr) {
        seh.handler_ret_val_ = reinterpret_cast<void*>(static_cast<uintptr_t>(ret_val));
    }

    std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx = std::dynamic_pointer_cast<speakeasy::deffs::windows::CONTEXT>(seh.context_);
    if (seh.context_address_ != 0) {
        mem_cast(ctx.get(), seh.context_address_);
    }

    // Always restore thread context
    load_thread_context32(ctx, thread);

    for (auto& frame : seh.frames_) {
        if (!frame.searched) {
            if (frame.scope_records.empty()) continue;
            auto& scope_record = frame.scope_records[0];

            auto record = std::dynamic_pointer_cast<speakeasy::deffs::windows::EH4_SCOPETABLE_RECORD<4>>(scope_record.record);
            auto filter_func = record->FilterFunc;

            if (!scope_record.filter_called && record->FilterFunc != 0) {
                set_func_args(sp, SEH_RETURN_ADDR, {});
                set_pc(filter_func);
                seh.last_func_ = reinterpret_cast<void*>(static_cast<uintptr_t>(filter_func));
                scope_record.filter_called = true;
                return;
            }

            if (ret_val == 1 /* EXCEPTION_EXECUTE_HANDLER */ ||
                filter_func == 0 ||
                filter_func == 0xFFFFFFFF) {
                if (!scope_record.handler_called) {
                    set_pc(record->HandlerAddress);
                    seh.last_func_ = reinterpret_cast<void*>(static_cast<uintptr_t>(record->HandlerAddress));
                    scope_record.handler_called = true;
                    return;
                }
            } else if (ret_val == 0xFFFFFFFF /* EXCEPTION_CONTINUE_EXECUTION */) {
                std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx_to_load = std::dynamic_pointer_cast<speakeasy::deffs::windows::CONTEXT>(seh.context_);
                if (seh.context_address_ != 0) {
                    mem_cast(ctx_to_load.get(), seh.context_address_);
                }
                load_thread_context(ctx_to_load);
                set_pc(ctx_to_load->Eip);
                return;
            } else if (ret_val == 0 /* EXCEPTION_CONTINUE_SEARCH */) {
                // pass
            }

            frame.searched = true;
        }
    }

    if (ret_val == 0 /* EXCEPTION_CONTINUE_SEARCH */ && seh.frames_.empty()) {
        std::shared_ptr<speakeasy::deffs::windows::CONTEXT> ctx_to_load = std::dynamic_pointer_cast<speakeasy::deffs::windows::CONTEXT>(seh.context_);
        uint32_t eip = ctx_to_load->Eip;
        set_pc(eip);
        return;
    }

    //on_run_complete();
    run_complete = true;
}



// Python winemu.py:2707
// def continue_seh(self):
//     """Reset SEH repeat-detection state."""
void WindowsEmulator::continue_seh() {
    _seh_last_fault = {0, std::nullopt};
    _seh_repeat_count = 0;
    if (arch_ == speakeasy::arch::ARCH_X86) {
        _continue_seh_x86();
    }
}

//  API dispatch 


// Python winemu.py:1358
// def get_proc(self, mod_name, func_name):
//     """Get a pointer for a supplied function name, similar to GetProcAddress."""
void* WindowsEmulator::get_proc(const std::string& mod_name, const std::string& func_name) {
    // Python reference: winemu.py lines 1358-1370
    std::string mod_lower = normalize_mod_name(mod_name);
    for (const auto& pair : import_table) {
        if (std::get<0>(pair.second) == mod_lower && std::get<1>(pair.second) == func_name) {
            return reinterpret_cast<void*>(static_cast<uintptr_t>(pair.first));
        }
    }
    uint64_t sentinel = _alloc_sentinel();
    import_table[sentinel] = {mod_lower, func_name};
    return reinterpret_cast<void*>(static_cast<uintptr_t>(sentinel));
}


// Python winemu.py:1561
// def normalize_import_miss(self, dll, name):
//     """This function attempts to fold as many function handlers together as possible."""
std::tuple<std::shared_ptr<ApiHandler>, ApiEntry> WindowsEmulator::normalize_import_miss(
    const std::string& dll, const std::string& name) {
    if (!api) {
        return {nullptr, InvalidApiInfo};
    }

    std::string alt_imp_api = "";
    std::string alt_imp_dll = "";

    // Handle ANSI vs UNICODE functions
    if (!name.empty() && (name.back() == 'A' || name.back() == 'W')) {
        alt_imp_api = name.substr(0, name.size() - 1);
    }

    std::string dll_lower = speakeasy::to_lower(dll);
    if (dll_lower.size() > 4 && dll_lower.substr(dll_lower.size() - 4) == ".dll") {
        dll_lower = dll_lower.substr(0, dll_lower.size() - 4);
    }

    // Handle Zw*/Nt* function overlap
    if (dll_lower.find("ntoskrnl") == 0) {
        if (name.find("Zw") == 0 && name.size() > 2) {
            alt_imp_api = "Nt" + name.substr(2);
        } else if (name.find("Nt") == 0 && name.size() > 2) {
            alt_imp_api = "Zw" + name.substr(2);
        }
    }

    alt_imp_dll = normalize_dll_name(dll_lower);

    // Bridge ntdll funcs to ntoskrnl if supported
    if (dll_lower.find("ntdll") == 0) {
        alt_imp_dll = "ntoskrnl";
        auto res = api->get_export_func_handler(alt_imp_dll, name);
        if (!std::get<1>(res).handler) {
            if (name.find("Zw") == 0 && name.size() > 2) {
                alt_imp_api = "Nt" + name.substr(2);
            } else if (name.find("Nt") == 0 && name.size() > 2) {
                alt_imp_api = "Zw" + name.substr(2);
            }
            if (!alt_imp_api.empty()) {
                res = api->get_export_func_handler(alt_imp_dll, alt_imp_api);
            }
        }
        return res;
    }

    if (!alt_imp_api.empty()) {
        return api->get_export_func_handler(dll, alt_imp_api);
    } else if (!alt_imp_dll.empty()) {
        return api->get_export_func_handler(alt_imp_dll, name);
    }

    return {nullptr, InvalidApiInfo};
}


// Python winemu.py:1639
// def handle_import_func(self, dll, name):
//     """Forward imported functions to the corresponding handler (if any)."""
void WindowsEmulator::handle_import_func(const std::string& dll, const std::string& name) {
    // Python reference: winemu.py lines 1639-1751
    std::string imp_api = dll + "." + name;

    PLOG_DEBUG << "[api-dispatch] handling: " << imp_api;

    uint64_t oret = get_ret_address();
    uint64_t opc  = get_pc();
    uint64_t call_pc = (prev_pc != 0) ? prev_pc : oret;

    // Normalize module name
    std::string dll_norm = speakeasy::to_lower(dll);
    if (dll_norm.size() > 4 && dll_norm.substr(dll_norm.size() - 4) == ".dll")
        dll_norm = dll_norm.substr(0, dll_norm.size() - 4);

    //  Primary handler lookup 
    std::shared_ptr<ApiHandler> handler_mod = nullptr;
    ApiEntry func_info = InvalidApiInfo;

    if (api) {
        std::tie(handler_mod, func_info) = api->get_export_func_handler(dll_norm, name);
    }

    //  Normalization fallback 
    if (!func_info.handler) {
        std::tie(handler_mod, func_info) = normalize_import_miss(dll, name);
    }

    std::vector<std::shared_ptr<ApiHook>> hooks = get_api_hooks(dll, name);

    if (func_info.handler && handler_mod) {
        int conv = speakeasy::arch::CALL_CONV_STDCALL;
        int argc = 4;

        // Re-query handler metadata for argc/conv
        //const ApiEntry info = handler_mod->get_func_handler(name);
        argc = func_info.argc;
        conv = func_info.conv;
        if (!name.empty() && name.find("ordinal_") == 0 && !func_info.name.empty())
            imp_api = dll + "." + func_info.name;

        auto argv = get_func_argv(conv, argc);

        // Gap A: API Hammering Detection
        if (hammer) {
            hammer->handle_import_func(imp_api, conv, argc);
        }

        uint64_t rv = 0;
        bool hook_called = false;

        ApiContext api_ctx;
        api_ctx["func_name"] = name;

        auto func_ptr_func = func_info.handler;
        // Gap B: Invoke User API Hooks
        if (!hooks.empty()) {
            // User hooks use raw uint64_t args (public ApiCallback API).
            // Convert ArgList -> vector<uint64_t> for the callback boundary.
            std::vector<uint64_t> raw_argv;
            raw_argv.reserve(argv.size());
            for (auto& arg : argv)
                raw_argv.push_back(static_cast<uint64_t>(arg));

            // Original handler wrapped as callback
            ApiCallback orig = [this, handler_mod, func_ptr_func, api_ctx](void* emu, const std::string& api_name, void* orig_ptr, std::vector<uint64_t> args) -> bool {
                (void)emu; (void)api_name; (void)orig_ptr;
                // Convert back to ArgList for internal dispatch
                ArgList inner_argv;
                inner_argv.reserve(args.size());
                for (auto v : args) inner_argv.push_back(v);
                void* rv_ptr = api->call_api_func(handler_mod, func_ptr_func, inner_argv, (void *)(&api_ctx));
                uint64_t sub_rv = reinterpret_cast<uintptr_t>(rv_ptr);
                return sub_rv != 0;
            };

            for (auto& hook : hooks) {
                if (hook && hook->is_enabled()) {
                    auto cb = hook->get_cb();
                    if (cb) {
                        rv = cb(this, imp_api, reinterpret_cast<void*>(&orig), raw_argv);
                        hook_called = true;
                    }
                }
            }
        }

        if (!hook_called && api) {
            // Save callee-saved registers (x86 ABI: EBX, ESI, EDI, EBP).
            // C++ API handlers are real functions that the compiler may clobber,
            // but emulated code expects them preserved across calls.
            int arch = get_arch();
            uint64_t saved_ebx = 0, saved_esi = 0, saved_edi = 0, saved_ebp = 0;
            if (arch == speakeasy::arch::ARCH_X86) {
                saved_ebx = reg_read(speakeasy::arch::REG_EBX);
                saved_esi = reg_read(speakeasy::arch::REG_ESI);
                saved_edi = reg_read(speakeasy::arch::REG_EDI);
                saved_ebp = reg_read(speakeasy::arch::REG_EBP);
            }
            try {
                void* rv_ptr = api->call_api_func(handler_mod, func_ptr_func, argv, &api_ctx);
                rv = reinterpret_cast<uintptr_t>(rv_ptr);
            } catch (...) {
                on_run_complete();
                return;
            }
            // Restore callee-saved registers
            if (arch == speakeasy::arch::ARCH_X86) {
                reg_write(speakeasy::arch::REG_EBX, saved_ebx);
                reg_write(speakeasy::arch::REG_ESI, saved_esi);
                reg_write(speakeasy::arch::REG_EDI, saved_edi);
                reg_write(speakeasy::arch::REG_EBP, saved_ebp);
            }
        }

        uint64_t ret = get_ret_address();
        uint64_t pc = get_pc();

        // Gap C: Dynamic Code Hooks
        auto mm = get_address_map(ret);
        if (mm && mm->get_tag().find("virtualalloc") != std::string::npos) {
            _fire_dyn_code_hooks(ret);
        }

        log_api(call_pc, imp_api, rv, argv);

        PLOG_DEBUG << "[api-dispatch] post-call: run_complete=" << run_complete
                    << " ret=0x" << std::hex << ret << " oret=0x" << oret
                    << " pc=0x" << pc << " opc=0x" << opc << std::dec;

        if (!run_complete && ret == oret && pc == opc) {
            PLOG_DEBUG << "[api-dispatch] calling do_call_return(argc=" << argc
                        << " ret_addr=0x" << std::hex << ret << " rv=0x" << rv << ")" << std::dec;
            do_call_return(argc, ret, rv, conv);
            PLOG_DEBUG << "[api-dispatch] do_call_return done, new pc=0x"
                        << std::hex << get_pc() << std::dec;
        } else {
            PLOG_DEBUG << "[api-dispatch] skipping do_call_return (ret!=oret || pc!=opc)";
        }

        // Gap E: Max API Count Enforcement
        if (curr_run && curr_run->get_api_count() > config_.max_api_count) {
            // log_info("* Maximum number of API calls reached. Stopping current run.");
            PLOG_INFO << "* Maximum number of API calls reached ." << config_.max_api_count << " Stopping current run.";
            curr_run->error["error"] = "max_api_count";
            curr_run->error["pc"] = hex_str(get_pc());
            curr_run->error["count"] = config_.max_api_count;
            curr_run->error["last_api"] = imp_api;
            on_run_complete();
        }
        else if (!run_complete) {
            /*
            # Re-enable the code hook so the next instruction can unmap the
            # sentinel range again. Otherwise adjacent sentinel calls may
            # execute bytes in EMU_RESERVED instead of trapping as imports.
            */
            enable_code_hook();
        }
        return;
    }

    // Gap D: Unsupported API Hooking & config fallbacks
    if (!hooks.empty()) {
        auto hook = hooks.back(); // FIFO highest priority / last registered
        int hook_conv = hook->get_call_conv();
        int hook_argc = hook->get_argc();

        auto argv = get_func_argv(hook_conv, hook_argc);
        if (hammer) {
            hammer->handle_import_func(imp_api, hook_conv, hook_argc);
        }

        auto cb = hook->get_cb();
        // ApiCallback takes raw uint64_t args; convert ArgList -> vector<uint64_t>
        std::vector<uint64_t> raw_hook_argv;
        raw_hook_argv.reserve(argv.size());
        for (auto& arg : argv)
            raw_hook_argv.push_back(static_cast<uint64_t>(arg));
        uint64_t rv = cb ? cb(this, imp_api, nullptr, raw_hook_argv) : 0;

        uint64_t ret = get_ret_address();
        log_api(call_pc, imp_api, rv, argv);
        do_call_return(hook_argc, ret, rv, hook_conv);
        if (!run_complete) {
            enable_code_hook();
        }
        return;
    } 
    else if (config_.modules.functions_always_exist) {
        int conv = speakeasy::arch::CALL_CONV_STDCALL;
        int argc = 4;
        auto argv = get_func_argv(conv, argc);
        uint64_t rv = 1;
        uint64_t ret = get_ret_address();
        log_api(call_pc, imp_api, rv, argv);
        do_call_return(argc, ret, rv, conv);
        if (!run_complete) {
            enable_code_hook();
        }
        return;
    }

    // Unregistered / Unsupported fallback
    record_error_event("Unsupported API: " + imp_api + " (ret: 0x" + hex_str(oret) + ")");
    if (curr_run) {
        curr_run->error["error"] = "unsupported_api";
        curr_run->error["pc"] = hex_str(get_pc());
        curr_run->error["api_name"] = imp_api;
    }
    on_run_complete();
}


// Python winemu.py:1372
// def handle_import_data(self, mod_name, sym, data_ptr=0):
//     """Data that is imported (e.g. KeTickCount) is handled with an initializer function."""
uint64_t WindowsEmulator::handle_import_data(const std::string& mod, const std::string& sym,
                                          uint64_t data_ptr) {
    // TODO: Python reference: winemu.py lines 1372-1387
    if (!api) return 0;

    // Try data export handler first
    auto [data_mod, data_func] = api->get_data_export_handler(mod, sym);
    if (data_func.func) {
        if (!data_ptr) {
            data_ptr = mem_map(ptr_size_, std::nullopt, 4, "api.import_data");
        }
        api->call_data_func(data_mod, data_func.func, data_ptr);
        return data_ptr;
    }
    // Fallback: try func export handler (returns a procedure address)
    auto [func_mod, func_ptr] = api->get_export_func_handler(mod, sym);
    if (func_ptr.handler) {
        // Get procedure address (sentinel) for this module+function
        get_proc(mod, sym);
    }
    return data_ptr;
}


static std::string repr(const std::string& s) {
    std::string res = "'";
    for (char c : s) {
        if (c == '\'') res += "\\'";
        else if (c == '\\') res += "\\\\";
        else if (c == '\n') res += "\\n";
        else if (c == '\r') res += "\\r";
        else if (c == '\t') res += "\\t";
        else res += c;
    }
    res += "'";
    return res;
}

std::optional<std::string> WindowsEmulator::read_string_heuristic(uint64_t addr) {
    if (addr < 0x10000) {
        return std::nullopt;
    }
    if (!is_address_valid(addr)) {
        return std::nullopt;
    }
    auto mm = get_address_map(addr);
    if (!mm || mm->is_free()) {
        return std::nullopt;
    }

    uint64_t limit = 256;
    uint64_t end = mm->get_base() + mm->get_size();
    if (addr + limit > end) {
        limit = end - addr;
    }
    if (limit == 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> buf = mem_read(addr, limit);
    if (buf.empty()) {
        return std::nullopt;
    }

    // Try ANSI: printable chars until null
    size_t ansi_len = 0;
    bool ansi_printable = false;
    for (size_t i = 0; i < buf.size(); ++i) {
        if (buf[i] == 0) {
            ansi_printable = (ansi_len > 0);
            break;
        }
        char c = static_cast<char>(buf[i]);
        if ((c >= 0x20 && c <= 0x7E) || c == '\r' || c == '\n' || c == '\t') {
            ansi_len = i + 1;
        } else if (c == '\0') {
            break;
        } else {
            ansi_len = 0; // non-printable  invalidate ANSI
            break;
        }
    }

    // Try UTF-16LE: ASCII chars with high-byte=0, null-terminated
    size_t unicode_len = 0;
    bool unicode_valid = false;
    for (size_t i = 0; i + 1 < buf.size(); i += 2) {
        uint16_t w = buf[i] | (static_cast<uint16_t>(buf[i+1]) << 8);
        if (w == 0) {
            unicode_valid = (unicode_len > 0);
            break;
        }
        // ASCII in UTF-16LE: high byte is 0, low byte is printable
        if (buf[i+1] != 0) break; // non-ASCII high byte  not simple UTF-16LE ASCII
        char c = static_cast<char>(buf[i]);
        if ((c >= 0x20 && c <= 0x7E) || c == '\r' || c == '\n' || c == '\t') {
            unicode_len = i / 2 + 1;
        } else {
            break; // non-printable  stop
        }
    }

    // Prefer UTF-16LE when it finds a LONGER string than ANSI.
    // This fixes "Qt5QWindowIcon" in UTF-16LE where ANSI sees "Q\0"  "Q"
    // but UTF-16LE correctly sees "Qt5QWindowIcon\0\0".
    if (unicode_valid && unicode_len > 0 && unicode_len > ansi_len) {
        std::string utf8_str;
        utf8_str.reserve(unicode_len);
        for (size_t i = 0; i < unicode_len; ++i) {
            utf8_str += static_cast<char>(buf[2*i]);
        }
        return utf8_str;
    }

    // Fallback to ANSI if valid
    if (ansi_printable && ansi_len > 0) {
        return std::string(buf.begin(), buf.begin() + ansi_len);
    }

    return std::nullopt;
}

// Python winemu.py:1614
// def log_api(self, pc, imp_api, rv, argv):
//     """Log an API call with its arguments and return value."""
void WindowsEmulator::log_api(uint64_t pc, const std::string& api,
                               uint64_t rv, const ArgList& argv) {
    std::string call_str = api + "(";

    for (size_t i = 0; i < argv.size(); ++i) {
        auto& arg = argv[i];
        if (arg.is_string()) {
            std::string escaped_str;
            for (char c : arg.as_string()) {
                if (c == '\n') escaped_str += "\\n";
                else if (c == '\r') escaped_str += "\\r";
                else if (c == '\t') escaped_str += "\\t";
                else if (c == '"') escaped_str += "\\\"";
                else if (c == '\\') escaped_str += "\\\\";
                else escaped_str += c;
            }
            call_str += "\"" + escaped_str + "\"";
        } else if (arg.is_blob()) {
            call_str += "{blob:" + std::to_string(arg.as_blob().size()) + "}";
        } else {
            uint64_t raw = static_cast<uint64_t>(arg);
            std::optional<std::string> s = read_string_heuristic(raw);
            if (s.has_value()) {
                std::string escaped_str;
                for (char c : s.value()) {
                    if (c == '\n') escaped_str += "\\n";
                    else if (c == '\r') escaped_str += "\\r";
                    else if (c == '\t') escaped_str += "\\t";
                    else if (c == '"') escaped_str += "\\\"";
                    else if (c == '\\') escaped_str += "\\\\";
                    else escaped_str += c;
                }
                call_str += "\"" + escaped_str + "\"";
            } else {
                std::stringstream hex_s;
                hex_s << "0x" << std::hex << raw;
                call_str += hex_s.str();
            }
        }
        if (i + 1 < argv.size()) call_str += ", ";
    }
    call_str += ")";

    std::stringstream pc_stream;
    pc_stream << "0x" << std::hex << pc;

    std::stringstream rv_stream;
    rv_stream << "0x" << std::hex << rv;

    PLOG_DEBUG << pc_stream.str() << ": " << repr(call_str) << " -> " << rv_stream.str();

    if (profiler_) {
        speakeasy::events::TracePosition pos;
        pos.pc = static_cast<int>(pc);
        pos.tick = static_cast<int>(inst_count_);
        auto proc = get_current_process();
        pos.pid = proc ? proc->get_pid() : 0;
        pos.tid = curr_thread ? curr_thread->get_id() : 0;
        profiler_->record_api_event(curr_run, pos, api, rv, argv);
    }
}


// Python winemu.py:1336
// def add_callback(self, mod_name, func_name):
//     """Adds a callback to the emulation callback list."""
uint64_t WindowsEmulator::add_callback(const std::string& mod_name, const std::string& func_name) {
    static uint64_t next_callback_addr = 0x102000;  // EMU_CALLBACK_RESERVE
    for (const auto& cb : callbacks) {
        if (std::get<1>(cb) == mod_name && std::get<2>(cb) == func_name) {
            return std::get<0>(cb);
        }
    }
    uint64_t addr = next_callback_addr++;
    callbacks.push_back({addr, mod_name, func_name});
    return addr;
}


// Python winemu.py:1821
// def get_symbol_from_address(self, address):
//     """If the supplied address is related to a known symbol, look it up here."""
std::string WindowsEmulator::get_symbol_from_address(uint64_t address) {
    auto it = symbols.find(address);
    if (it != symbols.end()) {
        return std::get<0>(it->second) + "." + std::get<1>(it->second);
    }
    return "";
}


// Python winemu.py:1604
// def read_unicode_string(self, addr):
//     """Read string data from a UNICODE_STRING object located at the specified address"""
std::vector<uint8_t> WindowsEmulator::read_unicode_string(uint64_t addr) {
    std::vector<uint8_t> result;
    for (int i = 0; i < 512; ++i) {
        auto bytes = mem_read(addr + i * 2, 2);
        if (bytes.size() < 2) break;
        uint16_t ch = bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8);
        if (ch == 0) break;
        result.push_back(bytes[0]);
        result.push_back(bytes[1]);
    }
    // Add null terminator
    result.push_back(0);
    result.push_back(0);
    return result;
}


// Python winemu.py:1814
// def restart_run(self, run):
//     """Restart the current run"""
void WindowsEmulator::restart_run(void* run) {
    (void)run;
    restart_curr_run = true;
}

//  Memory hooks (additional) 


// Python winemu.py:1831
// def _hook_mem_read(self, emu, access, address, size, value):
//     """Hook each memory read event that occurs. This hook is used to lookup symbols
//     and modules that are read from during emulation."""
bool WindowsEmulator::_hook_mem_read(void* emu, int access, uint64_t addr,
                                      size_t size, uint64_t value) {
    (void)emu; (void)access; (void)value;
    if (!curr_run) return false;

    try {
        // Check for symbol at this address
        std::string symbol = get_symbol_from_address(addr);
        if (!symbol.empty()) {
            // Track symbol access
            std::string key = hex_str(addr);
            auto it = curr_run->sym_access.find(key);
            if (it == curr_run->sym_access.end()) {
                MemAccess mac(addr, 0, symbol);
                it = curr_run->sym_access.emplace(key, mac).first;
            }
            it->second.reads++;
            return true;
        }

        // Check read_cache for fast path
        for (uint64_t cached_base : curr_run->read_cache) {
            if (cached_base != 0) {
                auto mac_it = curr_run->mem_access.find(hex_str(cached_base));
                if (mac_it != curr_run->mem_access.end()) {
                    if (addr >= mac_it->second.base &&
                        addr <= mac_it->second.base + mac_it->second.size - 1) {
                        mac_it->second.reads++;
                        return true;
                    }
                }
            }
        }

        // Check if addr is within a module section
        auto mod = get_mod_from_addr(addr);
        if (mod) {
            auto pe = mod;
            auto sects = pe->sections;
            for (auto& sect : sects) {
                uint64_t base = pe->base;
                uint64_t sect_base = base + sect.virtual_address;
                if (addr >= sect_base && addr < sect_base + sect.virtual_size) {
                    std::string mkey = hex_str(sect_base);
                    auto mac_it = curr_run->mem_access.find(mkey);
                    if (mac_it == curr_run->mem_access.end()) {
                        MemAccess mac(sect_base, sect.virtual_size);
                        mac_it = curr_run->mem_access.emplace(mkey, mac).first;
                    }
                    // Add to read_cache
                    if (curr_run->read_cache.size() >= 4)
                        curr_run->read_cache.pop_back();
                    curr_run->read_cache.push_front(sect_base);
                    mac_it->second.reads++;
                    return true;
                }
            }
        }

        // Generic memory map lookup
        std::shared_ptr<MemMap> mmap = get_address_map(addr);
        if (!mmap) return false;

        std::string mkey = hex_str(mmap->get_base());
        auto mac_it = curr_run->mem_access.find(mkey);
        if (mac_it == curr_run->mem_access.end()) {
            MemAccess mac(mmap->get_base(), page_size_);
            mac_it = curr_run->mem_access.emplace(mkey, mac).first;
        }
        // Add to read_cache
        if (curr_run->read_cache.size() >= 4)
            curr_run->read_cache.pop_back();
        curr_run->read_cache.push_front(mac_it->second.base);
        mac_it->second.reads++;

        return true;
    } catch (...) {
        return false;
    }
}


// Python winemu.py:1907
// def _hook_mem_write(self, emu, access, address, size, value):
//     """Hook each memory write event that occurs. This hook is used to track
//     memory modifications to interesting memory locations."""
bool WindowsEmulator::_hook_mem_write(void* emu, int access, uint64_t addr,
                                       size_t size, uint64_t value) {
    (void)emu; (void)access; (void)value;
    if (!curr_run) return false;

    try {
        // Check for symbol at this address
        std::string symbol = get_symbol_from_address(addr);
        if (!symbol.empty()) {
            std::string key = hex_str(addr);
            auto it = curr_run->sym_access.find(key);
            if (it == curr_run->sym_access.end()) {
                MemAccess mac(addr, 0, symbol);
                it = curr_run->sym_access.emplace(key, mac).first;
            }
            it->second.writes++;
            return true;
        }

        // Check write_cache for fast path
        for (uint64_t cached_base : curr_run->write_cache) {
            if (cached_base != 0) {
                auto mac_it = curr_run->mem_access.find(hex_str(cached_base));
                if (mac_it != curr_run->mem_access.end()) {
                    if (addr >= mac_it->second.base &&
                        addr <= mac_it->second.base + mac_it->second.size - 1) {
                        mac_it->second.writes++;
                        return true;
                    }
                }
            }
        }

        // Check if addr is within a module section
        auto mod = get_mod_from_addr(addr);
        if (mod) {
            auto pe = mod;
            auto sects = pe->sections;
            for (auto& sect : sects) {
                uint64_t base = pe->base;
                uint64_t sect_base = base + sect.virtual_address;
                if (addr >= sect_base && addr < sect_base + sect.virtual_size) {
                    std::string mkey = hex_str(sect_base);
                    auto mac_it = curr_run->mem_access.find(mkey);
                    if (mac_it == curr_run->mem_access.end()) {
                        MemAccess mac(sect_base, sect.virtual_size);
                        mac_it = curr_run->mem_access.emplace(mkey, mac).first;
                    }
                    // Add to write_cache
                    if (curr_run->write_cache.size() >= 4)
                        curr_run->write_cache.pop_back();
                    curr_run->write_cache.push_front(sect_base);
                    mac_it->second.writes++;
                    return true;
                }
            }
        }

        // Generic memory map lookup
        std::shared_ptr<MemMap> mmap = get_address_map(addr);
        if (!mmap) return false;

        std::string mkey = hex_str(mmap->get_base());
        auto mac_it = curr_run->mem_access.find(mkey);
        if (mac_it == curr_run->mem_access.end()) {
            MemAccess mac(mmap->get_base(), mmap->get_size());
            mac_it = curr_run->mem_access.emplace(mkey, mac).first;
        }
        // Add to write_cache
        if (curr_run->write_cache.size() >= 4)
            curr_run->write_cache.pop_back();
        curr_run->write_cache.push_front(mac_it->second.base);
        mac_it->second.writes++;

        return true;
    } catch (...) {
        return false;
    }
}


// Python winemu.py:1752
// def _hook_mem_unmapped(self, emu, access, address, size, value):
//     """High level function used to catch all invalid memory accesses that occur during emulation"""
bool WindowsEmulator::_hook_mem_unmapped(void* emu, int access, uint64_t addr,
                                          size_t size, uint64_t value) {
    (void)emu; (void)size; (void)value;
    if (!curr_run) return false;

    PLOG_DEBUG << "mem_unmapped: access=" << access << " addr=0x" << std::hex << addr
               << " size=0x" << size << std::dec;

    try {
        access = emu_eng_->mem_access[access];

        // Ensure code hook is active for deferred work
        if (!tmp_code_hook) {
            tmp_code_hook = add_code_hook(code_hook_trampoline);
        }
        enable_code_hook();

        PLOG_DEBUG << "mem_unmapped: mapped_access=" << access << " ("
                    << (access == INVALID_MEM_EXEC ? "FETCH" :
                        access == INVALID_MEM_READ ? "READ" :
                        access == INVALID_MEM_WRITE ? "WRITE" :
                        access == INVAL_PERM_MEM_EXEC ? "FETCH_PROT" :
                        access == INVAL_PERM_MEM_WRITE ? "WRITE_PROT" : "OTHER")
                    << ") addr=0x" << std::hex << addr << std::dec;

        if (access == INVALID_MEM_EXEC) {
            // SEH return - continue SEH and unset emu hooks
            if (addr == SEH_RETURN_ADDR) {
                continue_seh();
                _unset_emu_hooks();
                return true;
            }
            // API callback handler  Python winemu.py:1773-1789
            if (addr == API_CALLBACK_HANDLER_ADDR) {
                if (!curr_run->api_callbacks.empty()) {
                    auto [pc, func, args] = curr_run->api_callbacks.front();
                    curr_run->api_callbacks.erase(curr_run->api_callbacks.begin());
                    // Python: pc, orig_func, args = run.api_callbacks.pop(0)
                    //         self.do_call_return(len(args), pc)
                    func();  // invoke the callback
                    do_call_return(static_cast<int>(args.size()), pc,
                                   std::optional<uint64_t>());
                    _unset_emu_hooks();
                }
                return true;
            }
            return _handle_invalid_fetch(emu, addr, size, value);
        } else if (access == INVALID_MEM_READ) {
            return _handle_invalid_read(emu, addr, size, value);
        } else if (access == INVAL_PERM_MEM_EXEC) {
            return _handle_prot_fetch(emu, addr, size, value);
        } else if (access == INVALID_MEM_WRITE) {
            uint64_t fakeout = addr & ~(page_size_ - 1);
            mem_map(page_size_, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);
            tmp_maps.push_back({fakeout, page_size_});
            return _handle_invalid_write(emu, addr, size, value);
        } else if (access == INVAL_PERM_MEM_WRITE) {
            return _handle_prot_write(emu, addr, size, value);
        }

        return false;
    } catch (...) {
        if (curr_run) {
            curr_run->error["error"] = "Invalid memory exception";
        }
        on_emu_complete();
        return false;
    }
}


// Python winemu.py:1389
// def _handle_invalid_fetch(self, emu, address, size, value):
//     """Called when an attempt to emulate an instruction from an invalid address"""
bool WindowsEmulator::_handle_invalid_fetch(void* emu, uint64_t addr,
                                             size_t size, uint64_t value) {
    (void)emu; (void)size; (void)value;
    if (addr == return_hook || addr == exit_hook) {
        _unset_emu_hooks();
        return true;
    }

    if (!curr_mod) {
        curr_mod = get_mod_from_addr(get_pc());
    }

    // Python winemu.py:1400-1413 -- lookup address in import table
    auto imp_it = import_table.find(addr);
    if (imp_it != import_table.end()) {
        auto mod_name = std::get<0>(imp_it->second);
        auto func_name = std::get<1>(imp_it->second);
        _unset_emu_hooks();
        // Dispatch the API only if this run is still active.  If the
        // API handler called on_run_complete(), the run is done and
        // re-dispatching would cause an infinite FETCH_UNMAPPED loop.
        if (!run_complete && get_pc() == addr) {
            handle_import_func(mod_name, func_name);
        }
        return true;
    }

    // Is the address a callback func ptr?
    for (const auto& [c_addr, c_mod, c_fn] : callbacks) {
        if (c_addr == addr) {
            _unset_emu_hooks();
            handle_import_func(c_mod, c_fn);
            return true;
        }
    }

    // Are there any SEH handlers registered?
    if (config_.exceptions.dispatch_handlers) {
        bool rv = dispatch_seh(0xC0000005, addr);
        if (rv) return true;
    }

    uint64_t fakeout = addr & ~(page_size_ - 1);
    mem_map(page_size_, fakeout, PERM_MEM_RWX, "emu.page.tmp", 0, false);

    curr_run->error["error"] = get_error_info("invalid_fetch", addr);
    tmp_maps.push_back({fakeout, page_size_});
    on_run_complete();
    return true;
}


// Python winemu.py:1802
// def _handle_prot_write(self, emu, address, size, value):
//     """Handle protection violation on write access by mapping a fake page and logging error."""
bool WindowsEmulator::_handle_prot_write(void* emu, uint64_t addr,
                                          size_t size, uint64_t value) {
    (void)emu; (void)size; (void)value;
    uint64_t fakeout = addr & ~(page_size_ - 1);
    mem_map(page_size_, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    curr_run->error["error"] = get_error_info("invalid_protect_write", addr);
    tmp_maps.push_back({fakeout, page_size_});
    on_run_complete();
    return true;
}

//  Code hooks (additional) 


// Python winemu.py:2097
// def _hook_code_tracing(self, emu, addr, size):
//     """Persistent code hook for memory tracing: instruction counting,
//     symbol execution tracking, and per-region execution tracking."""
bool WindowsEmulator::_hook_code_tracing(void* emu, uint64_t addr, size_t size) {
    (void)emu;
    if (!curr_run) return true;

    try {
        // Check for symbol at this address
        std::string symbol = get_symbol_from_address(addr);
        if (!symbol.empty()) {
            auto dot = symbol.find('.');
            std::string mod_name = (dot != std::string::npos) ? symbol.substr(0, dot) : symbol;
            std::string fn_name  = (dot != std::string::npos) ? symbol.substr(dot + 1) : "";

            // Track symbol execution
            std::string key = hex_str(addr);
            auto it = curr_run->sym_access.find(key);
            if (it == curr_run->sym_access.end()) {
                MemAccess mac(addr, 0, symbol);
                it = curr_run->sym_access.emplace(key, mac).first;
            }
            it->second.execs++;

            // Dispatch to import handler
            if (!mod_name.empty() && !fn_name.empty()) {
                handle_import_func(mod_name, fn_name);
            }
            return true;
        }

        // Update prev PC and instruction count
        prev_pc = addr;
        curr_run->instr_cnt++;

        // Check exec_cache for fast path
        for (uint64_t cached_base : curr_run->exec_cache) {
            if (cached_base != 0) {
                auto mac_it = curr_run->mem_access.find(hex_str(cached_base));
                if (mac_it != curr_run->mem_access.end()) {
                    if (addr >= mac_it->second.base &&
                        addr <= mac_it->second.base + mac_it->second.size - 1) {
                        mac_it->second.execs++;
                        return true;
                    }
                }
            }
        }

        // Check if addr is within a module section
        auto mod = get_mod_from_addr(addr);
        if (mod) {
            auto pe = mod;
            auto sects = pe->sections;
            for (auto& sect : sects) {
                uint64_t base = pe->base;
                uint64_t sect_base = base + sect.virtual_address;
                if (addr >= sect_base && addr < sect_base + sect.virtual_size) {
                    std::string mkey = hex_str(sect_base);
                    auto mac_it = curr_run->mem_access.find(mkey);
                    if (mac_it == curr_run->mem_access.end()) {
                        MemAccess mac(sect_base, sect.virtual_size);
                        mac_it = curr_run->mem_access.emplace(mkey, mac).first;
                    }
                    // Add to exec_cache
                    if (curr_run->exec_cache.size() >= 4)
                        curr_run->exec_cache.pop_back();
                    curr_run->exec_cache.push_front(sect_base);
                    mac_it->second.execs++;
                    return true;
                }
            }
        }

        // Generic memory map lookup
        std::shared_ptr<MemMap> mmap = get_address_map(addr);
        if (!mmap) return false;

        std::string mkey = hex_str(mmap->get_base());
        auto mac_it = curr_run->mem_access.find(mkey);
        if (mac_it == curr_run->mem_access.end()) {
            MemAccess mac(mmap->get_base(), page_size_);
            mac_it = curr_run->mem_access.emplace(mkey, mac).first;
        }
        // Add to exec_cache
        if (curr_run->exec_cache.size() >= 4)
            curr_run->exec_cache.pop_back();
        curr_run->exec_cache.push_front(mac_it->second.base);
        mac_it->second.execs++;

        return true;
    } catch (...) {
        if (curr_run) {
            curr_run->error["error"] = "Exception during code hook (tracing)";
        }
        on_emu_complete();
        return false;
    }
}


// Python winemu.py:2083
// def _hook_code_coverage(self, emu, addr, size):
//     """Persistent code hook that records every executed address for coverage."""
bool WindowsEmulator::_hook_code_coverage(void* emu, uint64_t addr, size_t size) {
    (void)emu; (void)size;
    if (!curr_run) return true;
    try {
        curr_run->coverage.insert(addr);
        return true;
    } catch (...) {
        return false;
    }
}


// Python winemu.py:2166
// def _hook_code_debug(self, emu, addr, size):
//     """Persistent code hook that prints disassembly and register state
//     for every instruction when debug mode is enabled."""
bool WindowsEmulator::_hook_code_debug(void* emu, uint64_t addr, size_t size) {
    (void)emu;
    try {
        auto [mnem, op, instr] = get_disasm(addr, size);
        std::string regs_str;
        if (get_arch() == speakeasy::arch::ARCH_AMD64) {
            const char* reg_names[] = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9"};
            for (auto* rn : reg_names) {
                uint64_t val = reg_read(rn);
                char buf[64];
                snprintf(buf, sizeof(buf), "%s=0x%llx", rn,
                         static_cast<unsigned long long>(val));
                if (!regs_str.empty()) regs_str += " : ";
                regs_str += buf;
            }
        } else {
            const char* reg_names[] = {"eax","ebx","ecx","edx","esi","edi","ebp","esp"};
            for (auto* rn : reg_names) {
                uint64_t val = reg_read(rn);
                char buf[64];
                snprintf(buf, sizeof(buf), "%s=0x%llx", rn,
                         static_cast<unsigned long long>(val));
                if (!regs_str.empty()) regs_str += " : ";
                regs_str += buf;
            }
        }
        PLOG_DEBUG << std::hex << "0x" << static_cast<unsigned long long>(addr) << ": " << instr << ", " << regs_str << std::dec;
        return true;
    } catch (...) {
        return true;
    }
}


// Python winemu.py:232
// def set_coverage_hooks(self):
//     """Install coverage tracking code hook if enabled in config."""
void WindowsEmulator::set_coverage_hooks() {
    if (!config_.analysis.coverage) return;

    PLOG_DEBUG << "Installing code coverage hook";
    coverage_hook = add_code_hook(code_coverage_trampoline);
}


// Python winemu.py:242
// def set_debug_hooks(self):
//     """Install debug code hook if enabled."""
void WindowsEmulator::set_debug_hooks() {
    if (!debug) return;

    PLOG_DEBUG << "Installing code debug hook";
    debug_hook = add_code_hook(code_debug_trampoline);
}


// Python winemu.py:1322
// def resume_thread(self, thread):
//     """Resume a previously suspended thread"""
void WindowsEmulator::resume_thread(std::shared_ptr<Thread> thread) {
    (void)thread;
    resume(0);  // Resume emulation at current PC
}

std::shared_ptr<Thread> WindowsEmulator::find_thread(int handle_or_id) {
    for (const auto& proc : processes_) {
        for (const auto& t : proc->threads) {
            if (t->get_id() == handle_or_id || get_object_handle(t) == handle_or_id) {
                return t;
            }
        }
    }
    for (const auto& proc : child_processes_) {
        for (const auto& t : proc->threads) {
            if (t->get_id() == handle_or_id || get_object_handle(t) == handle_or_id) {
                return t;
            }
        }
    }
    return nullptr;
}

std::shared_ptr<Thread> WindowsEmulator::find_thread_by_ptr(void* thread_ptr) {
    if (!thread_ptr) return nullptr;
    for (const auto& proc : processes_) {
        for (const auto& t : proc->threads) {
            if (t.get() == thread_ptr) {
                return t;
            }
        }
    }
    for (const auto& proc : child_processes_) {
        for (const auto& t : proc->threads) {
            if (t.get() == thread_ptr) {
                return t;
            }
        }
    }
    return nullptr;
}


// Python winemu.py:1333
// def get_process_peb(self, process):
//     """Get the PEB for a given process."""
void* WindowsEmulator::get_process_peb(void* process) {
    auto proc_sp = process ? find_process(process) : curr_process_;
    if (proc_sp && proc_sp->get_peb()) {
        return reinterpret_cast<void*>(static_cast<uintptr_t>(proc_sp->get_peb()->get_address()));
    }
    return nullptr;
}

//  Error / context 


// Python winemu.py:1511
// def get_error_info(self, desc, address, traceback=None, access_type=None):
//     """Collect emulator state information in the event of an error."""
std::string WindowsEmulator::get_error_info(const std::string& msg, uint64_t pc,
                                             const std::string& trace) {
    std::string result;

    // Build module + offset info for PC
    std::string pc_module = _resolve_module_offset(pc);
    auto addr_region = _resolve_region_info(pc);
    std::string region_str = addr_region ? addr_region->tag : "none";

    // Get register state
    auto regs = get_register_state();

    // Get current instruction disassembly
    std::string instr;
    try {
        auto [mnem, op, full] = get_disasm(pc, DISASM_SIZE);
        instr = full;
    } catch (...) {
        instr = "disasm_failed";
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
        "Error: %s\n"
        "  PC: 0x%llx\n"
        "  Module: %s\n"
        "  Region: %s\n"
        "  Instr: %s\n"
        "  Trace: %s\n",
        msg.c_str(),
        static_cast<unsigned long long>(pc),
        pc_module.empty() ? "none" : pc_module.c_str(),
        region_str.c_str(),
        instr.c_str(),
        trace.empty() ? "none" : trace.c_str());
    result += buf;

    // Append register state
    result += "  Registers:\n";
    for (auto& [reg, val] : regs) {
        snprintf(buf, sizeof(buf), "    %s = %s\n", reg.c_str(), val.c_str());
        result += buf;
    }

    return result;
}


// Python winemu.py:1439
// def _resolve_module_offset(self, addr: int) -> str | None:
//     """Return module+0xoffset string for an address inside a loaded module, or None."""
std::string WindowsEmulator::_resolve_module_offset(uint64_t addr) {
    auto mod = get_mod_from_addr(addr);
    if (mod) {
        uint64_t offset = addr - mod->base;
        std::string name = mod->name;
        if (name.empty()) name = mod->emu_path;
        if (name.empty()) name = "unknown";
        return name + "+" + hex_str(offset);
    }
    return "";
}

// Python winemu.py:1448
// def _resolve_region_info(self, addr: int) -> RegionInfo | None:
//     """Return a RegionInfo for the region containing addr, or None if unmapped."""
std::shared_ptr<speakeasy::RegionInfo> WindowsEmulator::_resolve_region_info(uint64_t addr) {
    for (auto& mem_map_ptr : maps_) {
        if (mem_map_ptr && mem_map_ptr->get_base() <= addr && addr <= (mem_map_ptr->get_base() + mem_map_ptr->get_size() - 1)) {
            auto ri = std::make_shared<speakeasy::RegionInfo>();
            ri->tag = mem_map_ptr->get_tag().empty() ? "unknown" : mem_map_ptr->get_tag();
            ri->base = mem_map_ptr->get_base();
            ri->size = mem_map_ptr->get_size();
            ri->prot = ""; // Placeholder for protection string if needed
            return ri;
        }
    }
    return nullptr;
}

// Python winemu.py:1456
// def _find_nearby_regions(self, addr: int, count: int = 2) -> list[RegionInfo]:
//     """Return up to `count` nearest memory regions to an unmapped address."""
std::vector<speakeasy::RegionInfo> WindowsEmulator::_find_nearby_regions(uint64_t addr, int count) {
    std::vector<std::pair<uint64_t, speakeasy::RegionInfo>> distances;
    for (auto& mem_map_ptr : maps_) {
        uint64_t base = mem_map_ptr->get_base();
        uint64_t size = mem_map_ptr->get_size();
        uint64_t end = base + size - 1;
        uint64_t dist = 0;
        if (addr < base) {
            dist = base - addr;
        } else if (addr > end) {
            dist = addr - end;
        } else {
            continue;
        }
        speakeasy::RegionInfo ri;
        ri.tag = mem_map_ptr->get_tag().empty() ? "unknown" : mem_map_ptr->get_tag();
        ri.base = base;
        ri.size = size;
        ri.prot = "";
        distances.push_back({dist, ri});
    }
    std::sort(distances.begin(), distances.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    std::vector<speakeasy::RegionInfo> results;
    for (int i = 0; i < count && i < static_cast<int>(distances.size()); ++i) {
        results.push_back(distances[i].second);
    }
    return results;
}

// Python winemu.py:1475
std::string WindowsEmulator::_build_context_summary(const std::string& desc, uint64_t pc, uint64_t address,
                                                   const std::string& access_type,
                                                   const std::string& pc_module,
                                                   std::shared_ptr<speakeasy::RegionInfo> address_region,
                                                   const std::vector<speakeasy::RegionInfo>& nearby_regions) {
    std::string result;
    std::string access_str = access_type.empty() ? desc : access_type;
    if (address != pc) {
        result += access_str + " of " + (address_region ? "" : "unmapped ") + hex_str(address);
    } else {
        result += access_str + " at " + hex_str(address);
    }
    if (!pc_module.empty()) {
        result += " from " + pc_module;
    } else {
        result += " from pc=" + hex_str(pc);
    }
    if (address_region) {
        result += " in " + address_region->tag + " [" + hex_str(address_region->base) + "-" + hex_str(address_region->base + address_region->size - 1) + "]";
    } else if (!nearby_regions.empty()) {
        const auto& nearest = nearby_regions[0];
        result += "; nearest: " + nearest.tag + " [" + hex_str(nearest.base) + "-" + hex_str(nearest.base + nearest.size - 1) + "]";
    }
    return result;
}


//  Hardware interrupts 


// Python winemu.py:2742
// def _hook_interrupt(self, emu, intnum):
//     """Called when software interrupts occur (INT3, INT0, INT1, INT0x29, etc.)"""
bool WindowsEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu;
    uint64_t exception_list = _get_exception_list();

    PLOG_DEBUG << "interrupt: intnum=0x" << std::hex << intnum;
    // Dispatch SEH for recognized interrupt codes
    if (exception_list != 0 && config_.exceptions.dispatch_handlers) {
        // Catch software breakpoint interrupts
        if (intnum == 3 || intnum == 0x2D) {
            curr_exception_code = 0x80000003; // STATUS_BREAKPOINT
            prev_pc = get_pc();
            enable_code_hook();
            return true;
        }
        // Catch divide-by-zero exceptions
        if (intnum == 0) {
            PLOG_DEBUG << "interrupt: div zero";
            curr_exception_code = 0xC0000094; // STATUS_INTEGER_DIVIDE_BY_ZERO
            prev_pc = get_pc();
            enable_code_hook();
            return true;
        }
        // Catch single step exceptions
        if (intnum == 1) {
            curr_exception_code = 0x80000004; // STATUS_SINGLE_STEP
            prev_pc = get_pc();
            enable_code_hook();
            uint64_t eflags = reg_read(speakeasy::arch::REG_EFLAGS);
            eflags &= 0xFFFFFEFF; // Remove the trap flag (TF)
            reg_write(speakeasy::arch::REG_EFLAGS, eflags);
            return true;
        }
    }

    // Handle __fastfail interrupt introduced in Windows 8
    if (intnum == 0x29) {
        uint64_t ecx = reg_read(speakeasy::arch::REG_ECX);
        if (ecx == 6) { // Cookie security init failed — resume at return address
            auto hook_ptr = std::make_shared<std::shared_ptr<CodeHook>>();
            *hook_ptr = add_code_hook([this, hook_ptr](void*, uint64_t, uint32_t, void*) -> bool {
                uint64_t ret = pop_stack();
                set_pc(ret);
                (*hook_ptr)->disable();
                return true;
            });
            return true;
        }
    }

    // Unhandled interrupt — log error and restart run
    uint64_t pc = get_pc();
    //PLOG_DEBUG << "interrupt: intnum=0x" << std::hex << intnum;
    PLOG_ERROR << "0x" << std::hex << pc << ": Unhandled interrupt: intnum=0x" << intnum;
    if (curr_run) {
        curr_run->error["type"] = "unhandled_interrupt";
        curr_run->error["pc"] = hex_str(pc, false);
        curr_run->error["interrupt_num"] = std::to_string(intnum);
    }
    restart_curr_run = true;
    on_run_complete();
    return false;
}

//  Run control extension 


// Python winemu.py:386
// def add_run(self, run):
//     """Add a run to the emulation run queue"""
void WindowsEmulator::add_run(std::shared_ptr<Run> run) {
    run_queue.push_back(run);
}

//  Bootstrap / reference counting 


// Python winemu.py:2723
// def dec_ref(self, obj):
//     """Dereference an object"""
int WindowsEmulator::dec_ref(void* obj) {
    if (obj) {
        auto* ko = static_cast<KernelObject*>(obj);
        ko->ref_cnt--;
        return ko->ref_cnt;
    }
    return 0;
}

//  File management wrappers 


// Python winemu.py:291
// def file_get(self, handle):
//     """Get a file object from a handle"""
void* WindowsEmulator::file_get(int handle) {
    if (!fileman) return nullptr;
    auto file = fileman->get_file_from_handle(static_cast<uint32_t>(handle));
    return file ? file.get() : nullptr;
}


// Python winemu.py:297
// def file_delete(self, path):
//     """Delete a file"""
bool WindowsEmulator::file_delete(const std::string& path) {
    if (!fileman) return false;
    return fileman->delete_file(path);
}


// Python winemu.py:303
// def pipe_get(self, handle):
//     """Get a pipe object from a handle"""
void* WindowsEmulator::pipe_get(int handle) {
    if (!fileman) return nullptr;
    auto pipe = fileman->get_pipe_from_handle(static_cast<uint32_t>(handle));
    return pipe ? pipe.get() : nullptr;
}


// Python winemu.py:285
// def file_create_mapping(self, hfile, name, size, prot):
//     """Create a memory mapping for an emulated file"""
uint32_t WindowsEmulator::file_create_mapping(void* hfile, const std::string& name,
                                            size_t size, int prot) {
    if (fileman) {
        uint32_t handle = fileman->file_create_mapping(
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hfile)), name, size, prot);
        return handle;
    }
    return 0;
}

//  Manager accessors 


// Python winemu.py:309
// def get_file_manager(self):
//     """Get the file emulation manager"""
std::shared_ptr<FileManager> WindowsEmulator::get_file_manager() { return fileman; }

// Python winemu.py:315
// def get_network_manager(self):
//     """Get the network emulation manager"""
std::shared_ptr<NetworkManager> WindowsEmulator::get_network_manager() { return netman; }

// Python winemu.py:321
// def get_crypt_manager(self):
//     """Get the crypto manager"""
std::shared_ptr<CryptoManager> WindowsEmulator::get_crypt_manager()   { return cryptman; }

// Python winemu.py:327
// def get_drive_manager(self):
//     """Get the drive manager"""
std::shared_ptr<DriveManager> WindowsEmulator::get_drive_manager()   { return driveman; }

//  Registry wrappers 


// Python winemu.py:357
// def reg_get_subkeys(self, hkey):
//     """Get subkeys for a given registry key"""
std::vector<std::string> WindowsEmulator::reg_get_subkeys(std::shared_ptr<RegKey> hkey) {
    if (!regman || !hkey) return {};

    return regman->get_subkeys(hkey);
}


// Python winemu.py:333
// def dev_ioctl(self, arch, dev, ioctl, inbuf):
//     """Dispatch a device I/O control request to the I/O manager."""
std::pair<uint32_t, std::vector<uint8_t>> WindowsEmulator::dev_ioctl(int arch, Device* dev, uint32_t ioctl_code, const std::vector<uint8_t>& inbuf) {
    // Dispatch to kernel-mode IRP handler via IoManager
    return ioman->dev_ioctl(arch, dev, ioctl_code, inbuf);
}

// _get_exception_list was accidentally removed  re-adding

// Python winemu.py:2467
// def _get_exception_list(self):
//     """Retrieves the exception handler list for the current thread"""
uint64_t WindowsEmulator::_get_exception_list() {
    auto t = get_current_thread();
    if (!t) {
        return 0;
    }
    if (ptr_size_ == 4) {
        auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<4>*>(t->get_teb()->get_object());
        return teb_struct ? teb_struct->NtTib.ExceptionList : 0;
    }
    else {
        auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<8>*>(t->get_teb()->get_object());
        return teb_struct ? teb_struct->NtTib.ExceptionList : 0;
    }
}

// Python winemu.py:2652
// def _map_faulting_page_for_exception(self, faulting_address):
//     """Map a single page at faulting_address with RW permissions for SEH recovery"""
void WindowsEmulator::_map_faulting_page_for_exception(uint64_t faulting_address) {
    uint64_t fakeout = faulting_address & ~(page_size_ - 1);
    // Check if already mapped
    for (const auto& region : get_mem_regions()) {
        uint64_t base = std::get<0>(region);
        uint64_t end = std::get<1>(region);
        if (base <= fakeout && fakeout <= end)
            return;
    }
    mem_map(page_size_, fakeout, PERM_MEM_RW, "emu.seh.fault_page");
    tmp_maps.push_back({fakeout, page_size_});
}

std::tuple<uint64_t, uint64_t> WindowsEmulator::get_reserved_ranges() {
    return {EMU_RESERVED, EMU_RESERVED + EMU_RESERVE_SIZE};
}
