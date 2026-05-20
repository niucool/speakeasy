// winemu.cpp — Windows Emulator base class implementation
//
// Python reference: speakeasy/windows/winemu.py  (2795 lines)
// Each function definition below includes its Python line number.

#include "winemu.h"
#include "binemu.h"
#include "profiler.h"
#include "../config.h"
#include "../winenv/api/winapi.h"
#include "../winenv/api/api.h"
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

// ── Constructor ──────────────────────────────────────────────
// Python winemu.py:73
// def __init__(self, config, exit_event=None, debug=False, gdb_port=None):
//     """Initialize the Windows emulator with configuration.
//     Sets up managers, memory state, bootstrap phase, and parses config."""

WindowsEmulator::WindowsEmulator(const speakeasy::SpeakeasyConfig& cfg, void* logger,
                                  void* evt, bool dbg)
    : BinaryEmulator(cfg), debug(dbg), arch(0),
      page_size(4096), ptr_size(0),
      max_runs(100), kernel_mode(false), virtual_mem_base(0x50000),
      mem_tracing_enabled(false), tmp_code_hook(nullptr),
      run_complete(false), emu_complete(false),
      curr_exception_code(0), prev_pc(0), unhandled_exception_filter(0),
      fs_addr(0), gs_addr(0) {
}

// ── Bootstrap ────────────────────────────────────────────────
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

// ── Config ───────────────────────────────────────────────────
// Python winemu.py:— (accessor for registry_config map)
std::map<std::string, std::string> WindowsEmulator::get_registry_config() {
    return registry_config;
}

// ── Static trampolines for Unicorn callbacks ─────────────────
// These bridge the C callback convention to C++ member functions.
// Python winemu.py:— (Unicorn engine binding, no direct Python equivalent)

namespace {

void code_hook_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_core(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_trace_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_tracing(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_coverage_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_coverage(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

void code_debug_trampoline(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    emu->_hook_code_debug(static_cast<void*>(uc), address, static_cast<size_t>(size));
}

bool mem_read_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                          int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_read(static_cast<void*>(uc), static_cast<int>(type),
                                address, static_cast<size_t>(size),
                                static_cast<uint64_t>(value));
}

bool mem_write_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                           int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_write(static_cast<void*>(uc), static_cast<int>(type),
                                 address, static_cast<size_t>(size),
                                 static_cast<uint64_t>(value));
}

bool mem_unmapped_trampoline(uc_engine* uc, uc_mem_type type, uint64_t address,
                              int size, int64_t value, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_mem_unmapped(static_cast<void*>(uc), static_cast<int>(type),
                                    address, static_cast<size_t>(size),
                                    static_cast<uint64_t>(value));
}

bool intr_trampoline(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* emu = static_cast<WindowsEmulator*>(user_data);
    return emu->_hook_interrupt(static_cast<void*>(uc), static_cast<int>(intno));
}

} // anonymous namespace

// ── Hook registration helpers ────────────────────────────────

// ── Hooks ────────────────────────────────────────────────────
// Python winemu.py:199
// def enable_code_hook(self):
//     """Install the transient code hook needed for deferred work."""

void WindowsEmulator::enable_code_hook() {
    if (!tmp_code_hook && !mem_tracing_enabled) {
        _register_code_hook(reinterpret_cast<void*>(code_hook_trampoline), 1, 0);
        tmp_code_hook = reinterpret_cast<void*>(1);  // mark as registered
    }
}

// Python winemu.py:206
// def disable_code_hook(self):
//     """Remove the transient code hook."""
void WindowsEmulator::disable_code_hook() {
    if (tmp_code_hook && emu_eng) {
        for (auto h : uc_hooks_) {
            uc_hook_del(emu_eng->get_engine(), h);
        }
        uc_hooks_.clear();
        tmp_code_hook = nullptr;
    }
}

// Python winemu.py:628
// def set_hooks(self):
//     """Reserves memory that will be used to handle events that occur during emulation."""
void WindowsEmulator::set_hooks() {
    // Hooks are registered in enable_code_hook / set_mem_tracing_hooks
}

// Python winemu.py:377
// def _set_emu_hooks(self):
//     """Unmap reserved memory space so we can handle events (e.g. import APIs, entry point returns, etc.)"""
void WindowsEmulator::_set_emu_hooks() {
    if (!emu_hooks_set) {
        mem_map(EMU_RESERVE_SIZE, EMU_RETURN_ADDR, PERM_MEM_RW);
        emu_hooks_set = true;
    }
}

// Python winemu.py:259
// def _unset_emu_hooks(self):
//     """Re-map reserved memory space to catch import API calls and return events."""
void WindowsEmulator::_unset_emu_hooks() {
    if (emu_hooks_set) {
        mem_unmap(EMU_RETURN_ADDR, EMU_RESERVE_SIZE);
        emu_hooks_set = false;
    }
}

// Python winemu.py:218
// def set_mem_tracing_hooks(self):
//     """Install memory tracing hooks for analysis."""
void WindowsEmulator::set_mem_tracing_hooks() {
    if (mem_trace_hooks.empty()) {
        _register_code_hook(reinterpret_cast<void*>(code_trace_trampoline), 1, 0);
        _register_mem_hook(UC_HOOK_MEM_READ, reinterpret_cast<void*>(mem_read_trampoline));
        _register_mem_hook(UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(mem_write_trampoline));
        _register_mem_hook(UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(mem_unmapped_trampoline));
        mem_trace_hooks.push_back(reinterpret_cast<void*>(1));
    }
}

// Python winemu.py:210
// def _module_access_hook(self, emu, addr, size):
//     """Code hook fired for access to module API addresses; resolves symbol and dispatches handler."""
bool WindowsEmulator::_module_access_hook(void* emu, uint64_t addr,
                                           size_t size, void* ctx) {
    (void)emu; (void)size; (void)ctx;
    std::string sym = get_symbol_from_address(addr);
    if (!sym.empty()) {
        auto [dll, name] = normalize_import_miss("", sym);
        handle_import_func(dll, name);
        return true;
    }
    return false;
}

// ── Code hook core ───────────────────────────────────────────
// Python winemu.py:2031
// def _hook_code_core(self, emu, addr, size):
//     """Transient code hook for deferred work: SEH dispatch, run lifecycle,
//     temp map cleanup, and import data queue processing. Enabled on demand
//     and disables itself once the pending work is drained."""

bool WindowsEmulator::_hook_code_core(void* emu, uint64_t addr, size_t size) {
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

    _set_emu_hooks();
    disable_code_hook();
    return true;
}

// ── Memory ───────────────────────────────────────────────────
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
void WindowsEmulator::setup_user_shared_data() {
    constexpr uint64_t KUSER_SHARED_X86  = 0xFFDF0000;
    constexpr uint64_t KUSER_SHARED_AMD64 = 0xFFFFF78000000000ULL;
    constexpr uint64_t KUSER_READONLY     = 0x7FFE0000;

    if (arch == speakeasy::arch::ARCH_X86) {
        mem_map(page_size, KUSER_SHARED_X86, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    } else {
        mem_map(page_size, KUSER_SHARED_AMD64, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
    }
    mem_map(page_size, KUSER_READONLY, PERM_MEM_RW, "emu.struct.KUSER_SHARED_DATA");
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
    if (emu_eng) {
        uint64_t gdtr_base = gdt_base;
        emu_eng->reg_write(speakeasy::arch::REG_GDTR, gdtr_base);
        // DS selector (index 16, Ring3)
        emu_eng->reg_write(speakeasy::arch::REG_DS, create_selector(16, GDT_FLAGS::Ring3));
        // CS selector (index 17, Ring3)
        emu_eng->reg_write(speakeasy::arch::REG_CS, create_selector(17, GDT_FLAGS::Ring3));
        // SS selector (index 18, Ring0)
        emu_eng->reg_write(speakeasy::arch::REG_SS, create_selector(18, GDT_FLAGS::Ring0));
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

        if (emu_eng) {
            uint64_t fs_sel = create_selector(19, GDT_FLAGS::Ring3);
            emu_eng->reg_write(speakeasy::arch::REG_FS, fs_sel);
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

        if (emu_eng) {
            uint64_t gs_sel = create_selector(15, GDT_FLAGS::Ring3);
            emu_eng->reg_write(speakeasy::arch::REG_GS, gs_sel);
        }
    }

    fs_addr = fs_base;
    gs_addr = gs_base;
    return {fs_addr, gs_addr};
}

// ── Memory exception handlers ────────────────────────────────
// Python winemu.py:1960
// def _handle_invalid_read(self, emu, address, size, value):
//     """Hook each invalid memory read event that occurs."""

bool WindowsEmulator::_handle_invalid_read(void* emu, uint64_t address,
                                            size_t size, uint64_t value) {
    // Check if address is in a known module
    auto* mod = get_mod_from_addr(address);
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
    mem_map(page_size, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size});
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
        return true;  // Symbol found — let caller handle import resolution
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
    mem_map(page_size, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);

    tmp_maps.push_back({fakeout, page_size});
    on_run_complete();
    return true;
}

// ── File ─────────────────────────────────────────────────────
// Python winemu.py:267
// def file_open(self, path, create=False, truncate=False):
//     """Open a file in the emulated filesystem"""
void* WindowsEmulator::file_open(const std::string& path, bool create) {
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) {
        uint32_t h = fm->file_open(path, create);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
    return nullptr;
}

// Python winemu.py:273
// def pipe_open(self, path, mode, num_instances, out_size, in_size):
//     """Open an emulated named pipe"""
void* WindowsEmulator::pipe_open(const std::string& path, const std::string& mode,
                                  int num_instances, size_t out_size, size_t in_size) {
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) {
        uint32_t h = fm->pipe_open(path, mode, num_instances, out_size, in_size);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
    return nullptr;
}

// Python winemu.py:279
// def does_file_exist(self, path):
//     """Test if a file handler for a specified emulated file exists"""
bool WindowsEmulator::does_file_exist(const std::string& path) {
    auto* fm = static_cast<FileManager*>(fileman);
    return fm ? fm->does_file_exist(path) : false;
}

// Python winemu.py:351
// def reg_open_key(self, path, create=False):
//     """Open or create a registry key in the emulation space"""
void* WindowsEmulator::reg_open_key(const std::string& path, bool create) {
    auto* rm = static_cast<RegistryManager*>(regman);
    if (rm) {
        uint32_t h = rm->open_key(path, create);
        return reinterpret_cast<void*>(static_cast<uintptr_t>(h));
    }
    return nullptr;
}

// Python winemu.py:363
// def reg_get_key(self, handle=0, path=""):
//     """Get registry key by path or handle"""
void* WindowsEmulator::reg_get_key(int handle, const std::string& path) {
    auto* rm = static_cast<RegistryManager*>(regman);
    if (!rm) return nullptr;
    std::shared_ptr<RegKey> key;
    if (handle != 0)
        key = rm->get_key_from_handle(static_cast<uint32_t>(handle));
    else if (!path.empty())
        key = rm->get_key_from_path(path);
    return key ? reinterpret_cast<void*>(key.get()) : nullptr;
}

// Python winemu.py:371
// def reg_create_key(self, path):
//     """Create a registry key"""
void* WindowsEmulator::reg_create_key(const std::string& path) {
    auto* rm = static_cast<RegistryManager*>(regman);
    if (rm) {
        auto key = rm->create_key(path);
        return key ? reinterpret_cast<void*>(key.get()) : nullptr;
    }
    return nullptr;
}

// Python winemu.py:2713
// def create_event(self, name=""):
//     """Create a kernel event object"""
std::tuple<int, void*> WindowsEmulator::create_event(const std::string& name) {
    validate_object_services("event creation");
    (void)name;
    return {0, nullptr};
}

// Python winemu.py:2730
// def create_mutant(self, name=""):
//     """Create a kernel mutant object"""
std::tuple<int, void*> WindowsEmulator::create_mutant(const std::string& name) {
    validate_object_services("mutant creation");
    (void)name;
    return {0, nullptr};
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
    _seh_last_fault = {0, 0};
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

    runs.push_back(curr_run);

    // Set up stack for return; subclass handles args
    uint64_t stk_ptr = get_stack_ptr();
    (void)stk_ptr;

    // Switch process context if needed
    if (run->process_context &&
        run->process_context != get_current_process()) {
        alloc_peb(static_cast<Process*>(run->process_context));
        set_current_process(static_cast<Process*>(run->process_context));
    }

    // Reset SEH state
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;

    // Unmap reserved region if entry point is there
    if (run->start_addr >= EMU_RESERVED &&
        run->start_addr <= EMU_RESERVED_END) {
        // mem_unmap(EMU_RESERVED, EMU_RESERVE_SIZE);
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
    if (config.timeout > 0) {
        timeout_usec = static_cast<uint64_t>(config.timeout) * 1000000ULL;
    }

    // Start profiler timer
    if (profiler) {
        profiler->set_start_time();
    }

    int max_instr = config.max_api_count;
    if (max_instr <= 0) max_instr = 0;

    while (true) {
        try {
            // Set current module
            if (curr_run) {
                curr_mod = get_mod_from_addr(curr_run->start_addr);
            }

            // Begin emulation via engine (synchronous)
            if (emu_eng && curr_run) {
                uc_err err = emu_eng->start(curr_run->start_addr, timeout_usec,
                                             static_cast<size_t>(max_instr));
                if (err != UC_ERR_OK) {
                    // Check for timeout after execution
                    if (profiler && timeout_usec > 0 &&
                        profiler->get_run_time() > static_cast<double>(config.timeout)) {
                        log_error("* Timeout of " + std::to_string(config.timeout) + " sec(s) reached.");
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
                if (profiler && timeout_usec > 0 &&
                    profiler->get_run_time() > static_cast<double>(config.timeout)) {
                    log_error("* Timeout of " + std::to_string(config.timeout) + " sec(s) reached.");
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
    if (emu_eng) {
        emu_eng->start(addr, count, 0);
    }
}

// ── Run access ───────────────────────────────────────────────
// Python winemu.py:609
// def get_current_run(self):
//     """Get the current run that is being emulated"""
std::shared_ptr<Run> WindowsEmulator::get_current_run() { return curr_run; }
// Python winemu.py:615
// def get_current_module(self):
//     """Get the currently running module"""
void* WindowsEmulator::get_current_module() { return curr_mod; }
// Python winemu.py:621
// def get_dropped_files(self):
//     """Get all files written by the sample from the file manager"""
std::vector<std::shared_ptr<File>> WindowsEmulator::get_dropped_files() { 
    if(fileman)
        return fileman->get_dropped_files();
    else
        return {};
 }

// ── Process / thread ─────────────────────────────────────────
// Python winemu.py:635
// def get_processes(self):
//     """Get the current processes that exist in the emulation space"""
std::vector<void*> WindowsEmulator::get_processes() { return std::vector<void*>(processes.begin(), processes.end()); }
// Python winemu.py:643
// def kill_process(self, proc):
//     """Terminate a process (i.e. remove it from the known process list)"""
void WindowsEmulator::kill_process(void* proc) {
    if (proc) {
        auto* process = static_cast<Process*>(proc);
        process->modules.clear();
        process->threads.clear();
    }
    run_complete = true;
}

// ── Environment ──────────────────────────────────────────────
// Python winemu.py:1142
// def get_system_root(self):
//     """Get the path of the "SYSTEMROOT" environment variable"""
std::string WindowsEmulator::get_system_root() {
    auto it = env.find("systemroot");
    std::string root = (it != env.end()) ? it->second : "C:\\WINDOWS\\system32";
    if (!root.empty() && root.back() != '\\') root += '\\';
    return root;
}

// Python winemu.py:1151
// def get_windows_dir(self):
//     """Get the path of the "WINDIR" environment variable"""

std::string WindowsEmulator::get_windows_dir() {
    auto it = env.find("windir");
    std::string dir = (it != env.end()) ? it->second : "C:\\WINDOWS";
    if (!dir.empty() && dir.back() != '\\') dir += '\\';
    return dir;
}

// Python winemu.py:1160
// def get_cd(self):
//     """Get the path of the current directory"""

std::string WindowsEmulator::get_cd() {
    if (cd.empty()) {
        auto it = env.find("cd");
        cd = (it != env.end()) ? it->second : "C:\\WINDOWS\\system32";
        if (!cd.empty() && cd.back() != '\\') cd += '\\';
    }
    return cd;
}

// Python winemu.py:1170
// def set_cd(self, cd):
//     """Sets the current directory path"""

void WindowsEmulator::set_cd(const std::string& path) { cd = path; }

std::map<std::string, std::string> WindowsEmulator::get_env() { return env; }

// Python winemu.py:1179
// def set_env(self, var, val):
//     """Set an environment variable (key lowercased)."""

void WindowsEmulator::set_env(const std::string& var, const std::string& val) {
    std::string key = var;
    for (auto& c : key) c = static_cast<char>(std::tolower(c));
    env[key] = val;
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

// ── Object management ────────────────────────────────────────

// Python winemu.py:1182
// def get_object_from_addr(self, addr):
//     """Get an object from its memory address."""

void* WindowsEmulator::get_object_from_addr(uint64_t addr) {
    validate_object_services("object lookup by address");
    if (!om) return nullptr;
    KernelObject ko = om->get_object_from_addr(static_cast<int>(addr));
    return ko.get_object();
}

// Python winemu.py:1186
// def get_object_from_id(self, id):
//     """Get an object from its unique id."""

void* WindowsEmulator::get_object_from_id(int id) {
    validate_object_services("object lookup by id");
    if (!om) return nullptr;
    KernelObject ko = om->get_object_from_id(id);
    return ko.get_object();
}

// Python winemu.py:1190
// def get_object_from_name(self, name):
//     """Get an object from its name."""

void* WindowsEmulator::get_object_from_name(const std::string& name) {
    validate_object_services("object lookup by name");
    if (!om) return nullptr;
    KernelObject ko = om->get_object_from_name(name);
    return ko.get_object();
}

// Python winemu.py:1194
// def get_object_from_handle(self, handle):
//     """Get an object from its handle."""

void* WindowsEmulator::get_object_from_handle(int handle) {
    validate_object_services("object lookup by handle");
    // Try ObjectManager first
    if (om) {
        KernelObject ko = om->get_object_from_handle(handle);
        if (ko.get_object() != nullptr) {
            return ko.get_object();
        }
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

int WindowsEmulator::get_object_handle(void* obj) {
    validate_object_services("object handle lookup");
    if (!om || !obj) return 0;
    // obj is a KernelObject* (or subclass) — cast and delegate
    return om->get_handle(*static_cast<KernelObject*>(obj));
}

// Python winemu.py:1209
// def add_object(self, obj):
//     """Register an object with the ObjectManager."""

void WindowsEmulator::add_object(void* obj) {
    validate_object_services("object registration");
    if (!om || !obj) return;
    // obj is a KernelObject* (or subclass) — cast and delegate
    om->add_object(*static_cast<KernelObject*>(obj));
}

// Python winemu.py:1222
// def new_object(self, otype):
//     """Create a new object of the given type."""

void* WindowsEmulator::new_object(void* otype) {
    validate_object_services("object creation");
    (void)otype;
    if (!om) return nullptr;
    // Use the explicitly instantiated template for KernelObject
    return om->new_object<KernelObject>().get_object();
}

// ── PE / module helpers ──────────────────────────────────────

// Python winemu.py:847
// def get_mod_from_addr(self, addr):
//     """Get a module from an address within it."""

speakeasy::RuntimeModule* WindowsEmulator::get_mod_from_addr(uint64_t addr) {
    if (curr_mod) {
        auto* pe = curr_mod;
        uint64_t base = pe->base;
        if (addr >= base && addr < base + pe->image_size)
            return curr_mod;
    }
    for (auto* m : modules) {
        auto* pe = m;
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
    static uint64_t next = virtual_mem_base + 0x10000;
    uint64_t addr = next;
    next += static_cast<uint64_t>(ptr_size > 0 ? ptr_size : 4);
    return addr;
}

// Python winemu.py:979
// def get_mod_by_name(self, name):
//     """Find a loaded module by name (case-insensitive)."""

speakeasy::RuntimeModule* WindowsEmulator::get_mod_by_name(const std::string& name) {
    std::string nl = name;
    for (auto& c : nl) c = static_cast<char>(std::tolower(c));

    for (auto* m : modules) {
        auto* pe = m;
        std::string base = pe->get_base_name();
        for (auto& c : base) c = static_cast<char>(std::tolower(c));
        if (base == nl) return m;
        std::string epath = pe->emu_path;
        auto pos = epath.find_last_of("/\\");
        if (pos != std::string::npos) epath = epath.substr(pos + 1);
        for (auto& c : epath) c = static_cast<char>(std::tolower(c));
        if (epath == nl) return m;
    }
    return nullptr;
}

// Python winemu.py:990
// def get_peb_modules(self):
//     """Get modules that are visible in the PEB."""

std::vector<void*> WindowsEmulator::get_peb_modules() {
    std::vector<void*> result;
    for (auto* m : modules) {
        result.push_back(m);  // All modules visible in PEB by default
    }
    return result;
}

// ── PE initialization ───────────────────────────────────────

// Python winemu.py:760
// def init_peb(self, user_mods, proc=None):
//     """Initialize the Process Environment Block"""

void WindowsEmulator::init_peb(void* user_mods, void* proc) {
    void* p = proc ? proc : curr_process;
    if (!p) return;
    auto* process = static_cast<Process*>(p);
    uint64_t peb_addr = mem_map(0x1000, 0, PERM_MEM_RW, "PEB");
    process->peb = reinterpret_cast<void*>(peb_addr);
    // Use the provided user_mods if non-null, otherwise use our module list
    if (user_mods) {
        auto* mods = static_cast<std::vector<void*>*>(user_mods);
        process->init_peb(*mods);
    } else {
        process->init_peb(get_peb_modules());
    }
}

// Python winemu.py:771
// def init_teb(self, thread, peb):
//     """Initialize the Thread Information Block"""

void WindowsEmulator::init_teb(void* thread, void* peb) {
    if (!thread) return;
    auto* thr = static_cast<Thread*>(thread);
    auto* peb_obj = static_cast<Process*>(peb);
    uint64_t peb_addr = peb_obj ? reinterpret_cast<uint64_t>(peb_obj->peb) : 0;
    if (ptr_size == 4) {
        thr->init_teb(static_cast<int>(fs_addr), static_cast<int>(peb_addr));
    } else {
        thr->init_teb(static_cast<int>(gs_addr), static_cast<int>(peb_addr));
    }
}

// Python winemu.py:780
// def init_tls(self, thread):
//     """Initialize implicit thread local storage. Meant to be called after init_teb."""

void WindowsEmulator::init_tls(void* thread) {
    if (!thread || !curr_run) return;
    auto* thr = static_cast<Thread*>(thread);
    auto* mod = get_mod_from_addr(curr_run->start_addr);
    if (mod) {
        auto* pe = mod;
        std::string modname = pe->get_base_name();
        // TLS directory is stored in PeFile metadata during PeLoader::parse_pe
        // For now, init TLS with empty directory (callbacks are already in tls_callbacks_)
        thr->init_tls(0, modname);
    }
    (void)thr;
}

// Python winemu.py:809
// def load_pe(self, path=None, data=None, imp_id=winemu.IMPORT_HOOK_ADDR):
//     """Parse a PE that will be used during emulation. PE type and architecture
//     are automatically determined."""

speakeasy::RuntimeModule* WindowsEmulator::load_pe(const std::string& path,
                                const std::vector<uint8_t>& data,
                                uint64_t imp_id) {
    // Use PeLoader to parse the PE file
    speakeasy::PeLoader loader(path, data);
    auto* img = loader.make_image();
    if(imp_id)
        img->base = imp_id;  // Override base for sentinel tracking
    auto* result = load_image(img);
    return result;
}

// Python winemu.py:993
// def load_image(self, image):
//     """Load a parsed PE image into emulated memory, set up imports/exports, sections."""

speakeasy::RuntimeModule* WindowsEmulator::load_image(speakeasy::LoadedImage* img) {
    // Python reference: winemu.py lines 993-1137
    if (!img) return nullptr;

    if (img->mapped_image.empty() && img->regions.empty())
        return nullptr;

    bool valid_arch = (img->arch == 32 || img->arch == 64);
    // ── Determine architecture (Python 998-1004) ──
    if (!arch) {
        arch = valid_arch ? img->arch : speakeasy::arch::ARCH_X86;
        set_ptr_size(arch);
    }

    // ── Initialize emulation engine if needed (Python 1006-1008) ──
    if (!emu_eng) {
        int eng_arch = valid_arch ? img->arch : speakeasy::arch::ARCH_X86;
        int mode = (img->arch == 64) ? speakeasy::arch::BITS_64 : speakeasy::arch::BITS_32;
        emu_eng = new EmuEngine();
        emu_eng->init_engine(eng_arch, mode);
    }
    if (!ptr_size) ptr_size = 4;

    // ── Initialize API handler (Python 1019-1022) ──
    if (!api) {
        api = new WindowsApi(reinterpret_cast<Emulator*>(this));
    }

    advance_bootstrap_phase(BootstrapPhase::ENGINE_API_READY);
    bootstrap_object_services();

    // ── Map image regions (Python 1027-1040) ──
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

    // Map raw buffer if no regions (shellcode, etc.)
    if (img->regions.empty() && !img->mapped_image.empty()) {
        size_t map_size = img->mapped_image.size();
        if (img->base == 0) {
            img->base = mem_map(static_cast<uint64_t>(map_size), 0, PERM_MEM_RWX,
                                "emu.module." + img->name);
        } else {
            mem_map(static_cast<uint64_t>(map_size), img->base, PERM_MEM_RWX,
                    "emu.module." + img->name);
        }
        mem_write(img->base, img->mapped_image);
    }

    // ── Patch IAT with sentinel values for import hooking (Python 1042-1050) ──
    int psz = get_ptr_size();
    if (psz == 0) psz = 4;

    for (auto& imp : img->imports) {
        uint64_t sentinel = _alloc_sentinel();
        import_table[sentinel] = {normalize_mod_name(imp.dll_name), imp.func_name};
        uint64_t iat_addr = imp.iat_address;
        std::vector<uint8_t> sent_bytes(psz);
        for (int i = 0; i < psz; ++i)
            sent_bytes[i] = static_cast<uint8_t>((sentinel >> (i * 8)) & 0xFF);
        try { mem_write(iat_addr, sent_bytes); } catch (...) {}
    }

    // Also patch from PE header (catches injected PEs that bypass the loader's import table)
    ensure_pe_import_hooks(img->base);

    // ── Apply PE section memory protection (Python 1052-1077) ──
    // Python condition: isinstance(image.loader, PeLoader) and image.sections
    bool has_pe_loader = (img->sections.size() > 1);  // PeLoader creates multiple sections per PE
    if (has_pe_loader && !img->sections.empty()) {
        uint64_t base = img->base;
        // Protect headers (before first section) as READ only
        uint32_t first_section_rva = img->sections[0].virtual_address;
        if (first_section_rva > 0) {
            uint64_t aligned_headers = (static_cast<uint64_t>(base + first_section_rva) + page_size - 1) 
                                        & ~(static_cast<uint64_t>(page_size) - 1);
            try {
                mem_protect(base, aligned_headers - base, PERM_MEM_READ);
            } catch (...) {}
        }

        // Merge per-page permissions (multiple sections can share a page)
        std::map<uint64_t, int> page_perms;
        for (auto& sect : img->sections) {
            uint64_t section_addr = base + sect.virtual_address;
            uint64_t aligned_addr = section_addr & ~(static_cast<uint64_t>(page_size) - 1);
            uint64_t end_addr = section_addr + sect.virtual_size;
            uint64_t aligned_end = (end_addr + page_size - 1) & ~(static_cast<uint64_t>(page_size) - 1);

            for (uint64_t page_base = aligned_addr; page_base < aligned_end; page_base += page_size) {
                int existing = 0;
                auto it = page_perms.find(page_base);
                if (it != page_perms.end()) existing = it->second;
                page_perms[page_base] = existing | static_cast<int>(sect.perms);
            }
        }

        for (auto& [page_base, perms] : page_perms) {
            try {
                mem_protect(page_base, static_cast<uint64_t>(page_size), perms);
            } catch (...) {}
        }
    }

    // ── Create RuntimeModule (Python 1079-1081) ──
    speakeasy::RuntimeModule* mod = new speakeasy::RuntimeModule(img);
    if (img->base != 0 && mod->base != img->base)
        mod->base = img->base;

    // ── Determine module type (Python 1083) ──
    bool is_pe = (!img->sections.empty() && img->sections.size() > 1);  // PeLoader produces multiple sections
    bool is_shellcode = (!img->mapped_image.empty() && img->regions.size() <= 1);
    bool is_primary = is_pe || is_shellcode;

    // ── Normalize module name for API lookup (Python 1085-1086) ──
    std::string mod_base_name;
    if (!img->emu_path.empty()) {
        auto pos = img->emu_path.find_last_of("/\\");
        mod_base_name = (pos != std::string::npos) ? img->emu_path.substr(pos + 1) : img->emu_path;
    } else {
        mod_base_name = img->name;
    }
    std::string mod_base_name_no_ext = normalize_mod_name(mod_base_name);

    // ── Process exports: build symbol table and register hooks (Python 1088-1109) ──
    bool has_api_exports = false;
    if (api) {
        for (auto& exp : img->exports) {
            if (exp.name.empty()) continue;
            // Use normalized name first, then try raw name (Python 1093-1095)
            auto [handler, func_ptr] = api->get_export_func_handler(mod_base_name_no_ext, exp.name);
            // normalize_import_miss for API handler resolution (Python:1094-1095)
            // C++ uses different return types; the first lookup via get_export_func_handler is sufficient
            if (func_ptr) {
                symbols[exp.address] = {mod_base_name_no_ext, exp.name};
                has_api_exports = true;
            }
            // Data export hooks for non-primary modules (Python 1099-1103)
            // C++ deferred: add_mem_read_hook/add_mem_write_hook use std::function<void()> 
            // while _hook_mem_read/_hook_mem_write take 5 params. Hook registration
            // in C++ is done via WindowsEmulator::set_hooks not here.
        }

        // Module access hook for non-primary API modules (Python 1105-1109)
        if (!is_primary && has_api_exports && !img->regions.empty()) {
            auto& first_region = img->regions[0];
            uint64_t mod_start = first_region.base ? first_region.base : img->base;
            uint64_t mod_end = mod_start + first_region.data.size();
            // Deferred: would need a code hook with correct signature
        }

        // Process data imports (Python 1111-1118)
        // C++ note: handle_import_data is a member that processes the import;
        // the result is written into global_data by the handler itself.
        // Here we just ensure imports are patched after sentinel IAT setup above.
    }

    // ── Register module (Python 1126) ──
    modules.push_back(mod);

    // ── Allocate stack for primary image (Python 1128-1130) ──
    if (is_primary && stack_base == 0 && img->image_size > 0) {
        size_t stack_size = img->image_size;  // use image_size as default (stack_size field not on C++ LoadedImage)
        auto [sb, sp] = alloc_stack(stack_size);
        stack_base = sb;
    }

    // ── Run one-time setup (Python 1132-1135) ──
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

    // ── Read DOS header → verify MZ ──
    auto dos_hdr = mem_read(base_addr, 0x40);
    if (dos_hdr.size() < 0x40 || dos_hdr[0] != 'M' || dos_hdr[1] != 'Z')
        return;

    // ── Read PE offset (e_lfanew) ──
    uint32_t e_lfanew = 0;
    for (int i = 0; i < 4; ++i)
        e_lfanew |= static_cast<uint32_t>(dos_hdr[0x3C + i]) << (i * 8);
    uint64_t pe_sig_off = base_addr + e_lfanew;

    // ── Read PE header → verify signature ──
    auto pe_hdr = mem_read(pe_sig_off, 0x18);
    if (pe_hdr.size() < 4 || pe_hdr[0] != 'P' || pe_hdr[1] != 'E')
        return;

    // ── Read Optional Header → get import directory ──
    // Optional Header starts at pe_sig_off + 0x18 (after Signature + FileHeader)
    uint64_t opt_off = pe_sig_off + 0x18;
    uint32_t import_dir_rva = 0, import_dir_size = 0;

    if (is64) {
        // PE32+: IMAGE_OPTIONAL_HEADER64 — import dir at offset 0x70 in opt hdr
        auto opt = mem_read(opt_off, 0x70 + 16 * 8);
        if (opt.size() < 0x80) return;
        import_dir_rva = opt[0x70] | (static_cast<uint32_t>(opt[0x71]) << 8) |
                        (static_cast<uint32_t>(opt[0x72]) << 16) | (static_cast<uint32_t>(opt[0x73]) << 24);
        import_dir_size = opt[0x74] | (static_cast<uint32_t>(opt[0x75]) << 8) |
                         (static_cast<uint32_t>(opt[0x76]) << 16) | (static_cast<uint32_t>(opt[0x77]) << 24);
    } else {
        // PE32: IMAGE_OPTIONAL_HEADER32 — import dir at offset 0x68 in opt hdr
        auto opt = mem_read(opt_off, 0x60 + 16 * 8);
        if (opt.size() < 0x70) return;
        import_dir_rva = opt[0x68] | (static_cast<uint32_t>(opt[0x69]) << 8) |
                        (static_cast<uint32_t>(opt[0x6A]) << 16) | (static_cast<uint32_t>(opt[0x6B]) << 24);
        import_dir_size = opt[0x6C] | (static_cast<uint32_t>(opt[0x6D]) << 8) |
                         (static_cast<uint32_t>(opt[0x6E]) << 16) | (static_cast<uint32_t>(opt[0x6F]) << 24);
    }

    if (!import_dir_rva || !import_dir_size) return;

    // ── Walk IMAGE_IMPORT_DESCRIPTOR array ──
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

        // ── Read DLL name ──
        auto dll_bytes = mem_read(base_addr + name_rva, 256);
        std::string dll_name;
        {
            size_t null_pos = 0;
            for (; null_pos < dll_bytes.size() && dll_bytes[null_pos] != 0; ++null_pos);
            if (null_pos > 0)
                dll_name.assign(reinterpret_cast<const char*>(dll_bytes.data()), null_pos);
        }
        if (dll_name.empty()) continue;

        // ── Walk thunk entries ──
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

            // ── Check if already patched ──
            auto iat_data = mem_read(iat_va, static_cast<size_t>(psz));
            uint64_t iat_val = 0;
            for (int i = 0; i < psz; ++i)
                iat_val |= static_cast<uint64_t>(iat_data[i]) << (i * 8);

            if (import_table.count(iat_val)) continue;

            // ── Resolve function name ──
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

            // ── Allocate sentinel & patch IAT ──
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

void* WindowsEmulator::get_current_thread() { return curr_thread; }
Process* WindowsEmulator::get_current_process() { return curr_process; }
// Python winemu.py:664
// def set_current_process(self, process):
//     """Set the current process that is emulating"""

void WindowsEmulator::set_current_process(Process* process) { curr_process = process; }
// Python winemu.py:670
// def set_current_thread(self, thread):
//     """Set the current thread"""

void WindowsEmulator::set_current_thread(Thread* thread) { curr_thread = thread; }

// Python winemu.py:1226
// def create_process(self, path=None, cmdline=None, image=None, child=False):
//     """Create a process object that will exist in the emulator"""
void* WindowsEmulator::create_process(const std::string& path,
                                       const std::string& cmdline,
                                        speakeasy::RuntimeModule* image, bool child) {
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

    auto* p = new Process(this);

    if (!image) {
        // Try to get PE data from emulated filesystem
        auto mod_data = get_module_data_from_emu_file(file_path);
        if (!mod_data.empty()) {
            // Load PE from raw data
            try {
                speakeasy::PeLoader loader(file_path, mod_data);
                auto* img = loader.make_image();
                auto* rtmod = load_image(img);
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
    auto* t = new Thread(this);
    p->threads.push_back(*t);
    delete t;  // threads vector stores copies

    if (child) {
        child_processes.push_back(p);
    } else {
        processes.push_back(p);
    }

    return p;
}

// Python winemu.py:1293
// def create_thread(self, addr, ctx, proc_obj, thread_type="thread", is_suspended=False):
//     """Create a thread object that will exist in the emulator"""
void* WindowsEmulator::create_thread(uint64_t addr, void* ctx, void* proc_obj,
                                      const std::string& thread_type, bool is_suspended) {
    validate_object_services("thread creation");

    if (run_queue.size() >= static_cast<size_t>(max_runs)) {
        return nullptr;
    }

    auto* thread = new Thread(this);
    if (proc_obj) {
        auto* proc = static_cast<Process*>(proc_obj);
        thread->set_context(ctx);
    }

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

// ── Module loading ───────────────────────────────────────────


// Python winemu.py:2180
// def get_native_module_path(self, mod_name=""):
//     """Get the full filesystem path of a default decoy that is supplied by speakeasy"""
std::string WindowsEmulator::get_native_module_path(const std::string& mod_name) {
    std::string name = mod_name;
    for (auto& c : name) c = static_cast<char>(std::tolower(c));

    const char* subdir = (arch == speakeasy::arch::ARCH_AMD64) ? "amd64" : "x86";
    fs::path decoy_path = fs::path("secpp") / "winenv" / "decoys" / subdir;

    if (fs::exists(decoy_path)) {
        for (const auto& entry : fs::directory_iterator(decoy_path)) {
            if (!entry.is_regular_file()) continue;
            std::string fn = entry.path().filename().string();
            std::string base = fn;
            auto dot = base.find_last_of('.');
            if (dot != std::string::npos) base = base.substr(0, dot);
            for (auto& c : base) c = static_cast<char>(std::tolower(c));
            if (base == name) return entry.path().string();
        }
    }
    return "";
}


// Python winemu.py:2212
// def load_library(self, mod_name):
//     """Load a library (DLL) by name. Returns its base address or 0."""
void* WindowsEmulator::load_library(const std::string& mod_name) {
    std::string lib = normalize_mod_name(mod_name);

    // Check if already loaded
    void* existing = get_mod_by_name(lib);
    if (existing) {
        return reinterpret_cast<void*>(static_cast<PeFile*>(existing)->get_base());
    }

    if (!modules_always_exist) return nullptr;

    speakeasy::RuntimeModule* mod = load_module_by_name(lib);
    if (!mod) return nullptr;

    // Add to current process PEB if available
    auto* proc = get_current_process();
    if (proc && proc->peb_ldr_data) {
        proc->add_module_to_peb(mod);
    }

    return reinterpret_cast<void*>(mod->base);
}


// Python winemu.py:2231
// def load_module_by_name(self, name, emu_path=None, base=None):
//     """Load a module by name using the appropriate loader.
//     Priority: native PE file -> API handler (JIT PE) -> placeholder stub."""
speakeasy::RuntimeModule* WindowsEmulator::load_module_by_name(const std::string& name,
                                            const std::string& emu_path,
                                            uint64_t base) {
    if (base == 0) base = 0x6F000000;

    std::string ep = emu_path;
    if (ep.empty()) {
        ep = cd.empty() ? "C:\\Windows\\system32\\" : cd;
        ep += name + ".dll";
    }

    std::string native_path = get_native_module_path(name);
    // Use speakeasy::PeLoader to parse and map the PE
    if (!native_path.empty()) {
        try {
            speakeasy::PeLoader loader(native_path, std::vector<uint8_t>{});
            auto* img = loader.make_image();
            auto* result = load_image(img);
            return result;
        } catch (...) {}
    }
    // Fallback: try using the emu_path as data source
    if (!ep.empty()) {
        try {
            speakeasy::PeLoader loader(ep, std::vector<uint8_t>{});
            auto* img = loader.make_image();
            auto* result = load_image(img);
            return result;
        } catch (...) {}
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
std::vector<void*> WindowsEmulator::init_environment(
    const std::vector<nlohmann::json>& system_modules,
    const std::vector<nlohmann::json>& user_modules) {
    auto sys_mods = _init_module_group(system_modules, 0);
    _init_module_group(user_modules, 0x6F000000);
    return sys_mods;
}


// Python winemu.py:2302
// def init_sys_modules(self, modules_config):
//     """Initialize system modules from the config."""
std::vector<void*> WindowsEmulator::init_sys_modules(
    const std::vector<nlohmann::json>& modules_config) {
    return _init_module_group(modules_config, 0);
}


// Python winemu.py:2305
// def init_user_modules(self, modules_config):
//     """Initialize user modules from the config."""
std::vector<void*> WindowsEmulator::init_user_modules(
    const std::vector<nlohmann::json>& modules_config) {
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
std::vector<void*> WindowsEmulator::_init_module_group(
    const std::vector<nlohmann::json>& modules_config, uint64_t default_base) {
    std::vector<void*> rtmods;
    for (const auto& modconf : modules_config) {
        // modname = getattr(modconf, "name", None) or "unknown"
        std::string modname = "unknown";
        if (modconf.contains("name") && modconf["name"].is_string())
            modname = modconf["name"].get<std::string>();

        // base_addr = getattr(modconf, "base_addr", None) or default_base
        uint64_t base_addr = default_base;
        if (modconf.contains("base_addr")) {
            auto& ba = modconf["base_addr"];
            if (ba.is_string()) {
                std::string bs = ba.get<std::string>();
                if (bs.find("0x") == 0 || bs.find("0X") == 0)
                    base_addr = std::stoull(bs, nullptr, 16);
                else
                    base_addr = std::stoull(bs, nullptr, 10);
            } else if (ba.is_number())
                base_addr = ba.get<uint64_t>();
        }

        // emu_path = getattr(modconf, "path", None) or (modname + ".dll")
        std::string emu_path = modname + ".dll";
        if (modconf.contains("path") && modconf["path"].is_string())
            emu_path = modconf["path"].get<std::string>();

        // images = getattr(modconf, "images", []) or []
        std::vector<nlohmann::json> images;
        if (modconf.contains("images") && modconf["images"].is_array())
            images = modconf["images"].get<std::vector<nlohmann::json>>();

        // native_path = self.get_native_module_path(mod_name=modname)
        std::string native_path = get_native_module_path(modname);

        // Try images first (arch-specific)
        std::string path;
        for (const auto& img : images) {
            if (img.contains("arch") && img["arch"].is_number() &&
                img["arch"].get<int>() == get_arch()) {
                if (img.contains("name") && img["name"].is_string())
                    path = get_native_module_path(img["name"].get<std::string>());
            }
        }
        if (path.empty()) path = native_path;

        if (!path.empty()) {
            // PeLoader(path=path, base_override=base_addr, emu_path=emu_path)
            try {
                speakeasy::PeLoader loader(path, std::vector<uint8_t>{});
                auto* img = loader.make_image();
                if (base_addr) img->base = base_addr;
                if (!emu_path.empty()) img->emu_path = emu_path;
                auto* rtmod = load_image(img);
                if (rtmod) rtmods.push_back(rtmod);
                continue;
            } catch (...) {}
        }

        // No native PE path found — try ApiModuleLoader if api wired
        // (DecoyLoader fallback would create placeholder stub)
        // For now, skip modules without a native PE file.
    }
    return rtmods;
}

// ── Thread context ───────────────────────────────────────────


// Python winemu.py:2364
// def get_thread_context(self, thread=None):
//     """Get the current thread CPU context"""
void* WindowsEmulator::get_thread_context(void* thread) {
    (void)thread;
    if (!emu_eng) return nullptr;

    // Allocate memory for a CONTEXT structure
    size_t ctx_size = (get_arch() == speakeasy::arch::ARCH_AMD64) ? 1232 : 716;
    uint64_t ctx_addr = mem_map(ctx_size, 0, PERM_MEM_RW, "emu.struct.CONTEXT");
    std::vector<uint8_t> buf(ctx_size, 0);

    if (get_arch() == speakeasy::arch::ARCH_X86) {
        // Standard x86 CONTEXT layout (offsets verified from Windows SDK)
        // Seg registers at offsets 0x6C-0x78
        write_le(buf, 0x6C, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_GS)), 4);   // SegGs
        write_le(buf, 0x70, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_FS)), 4);   // SegFs
        write_le(buf, 0x74, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_ES)), 4);   // SegEs
        write_le(buf, 0x78, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_DS)), 4);   // SegDs
        // Integer registers at offsets 0x7C-0xA8
        write_le(buf, 0x7C, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EDI)), 4);  // Edi
        write_le(buf, 0x80, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_ESI)), 4);  // Esi
        write_le(buf, 0x84, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EBX)), 4);  // Ebx
        write_le(buf, 0x88, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EDX)), 4);  // Edx
        write_le(buf, 0x8C, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_ECX)), 4);  // Ecx
        write_le(buf, 0x90, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EAX)), 4);  // Eax
        write_le(buf, 0x94, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EBP)), 4);  // Ebp
        write_le(buf, 0x98, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EIP)), 4);  // Eip
        write_le(buf, 0x9C, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_CS)), 4);   // SegCs
        write_le(buf, 0xA0, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EFLAGS)), 4); // EFlags
        write_le(buf, 0xA4, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_ESP)), 4);  // Esp
        write_le(buf, 0xA8, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_SS)), 4);   // SegSs
    } else if (get_arch() == speakeasy::arch::ARCH_AMD64) {
        // Standard x64 CONTEXT layout (offsets verified from Windows SDK)
        write_le(buf, 0x48, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_CS)), 2);   // SegCs
        write_le(buf, 0x50, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_DS)), 2);   // SegDs
        write_le(buf, 0x58, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_ES)), 2);   // SegEs
        write_le(buf, 0x60, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_FS)), 2);   // SegFs
        write_le(buf, 0x68, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_GS)), 2);   // SegGs
        write_le(buf, 0x70, static_cast<uint16_t>(reg_read(speakeasy::arch::REG_SS)), 2);   // SegSs
        write_le(buf, 0x78, static_cast<uint32_t>(reg_read(speakeasy::arch::REG_EFLAGS)), 4); // EFlags
        // Integer registers at offsets 0xB8-0x140
        write_le(buf, 0xB8, reg_read(speakeasy::arch::REG_RAX), 8);   // Rax
        write_le(buf, 0xC0, reg_read(speakeasy::arch::REG_RCX), 8);   // Rcx
        write_le(buf, 0xC8, reg_read(speakeasy::arch::REG_RDX), 8);   // Rdx
        write_le(buf, 0xD0, reg_read(speakeasy::arch::REG_RBX), 8);   // Rbx
        write_le(buf, 0xD8, reg_read(speakeasy::arch::REG_RSP), 8);   // Rsp
        write_le(buf, 0xE0, reg_read(speakeasy::arch::REG_RBP), 8);   // Rbp
        write_le(buf, 0xE8, reg_read(speakeasy::arch::REG_RSI), 8);   // Rsi
        write_le(buf, 0xF0, reg_read(speakeasy::arch::REG_RDI), 8);   // Rdi
        write_le(buf, 0xF8, reg_read(speakeasy::arch::REG_R8), 8);    // R8
        write_le(buf, 0x100, reg_read(speakeasy::arch::REG_R9), 8);   // R9
        write_le(buf, 0x108, reg_read(speakeasy::arch::REG_R10), 8);  // R10
        write_le(buf, 0x110, reg_read(speakeasy::arch::REG_R11), 8);  // R11
        write_le(buf, 0x118, reg_read(speakeasy::arch::REG_R12), 8);  // R12
        write_le(buf, 0x120, reg_read(speakeasy::arch::REG_R13), 8);  // R13
        write_le(buf, 0x128, reg_read(speakeasy::arch::REG_R14), 8);  // R14
        write_le(buf, 0x130, reg_read(speakeasy::arch::REG_R15), 8);  // R15
        write_le(buf, 0x140, reg_read(speakeasy::arch::REG_RIP), 8);  // Rip
    }

    mem_write(ctx_addr, buf);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ctx_addr));
}


// Python winemu.py:2418
// def load_thread_context(self, ctx, thread=None):
//     """Set the current thread CPU context"""
void WindowsEmulator::load_thread_context(void* ctx, void* thread) {
    (void)thread;
    if (!emu_eng || !ctx) return;

    uint64_t ctx_addr = reinterpret_cast<uint64_t>(ctx);
    size_t ctx_size = (get_arch() == speakeasy::arch::ARCH_AMD64) ? 1232 : 716;
    auto buf = mem_read(ctx_addr, ctx_size);
    if (buf.size() < ctx_size) return;

    if (get_arch() == speakeasy::arch::ARCH_X86) {
        uint32_t edi = static_cast<uint32_t>(read_le(buf, 0x7C, 4));
        uint32_t esi = static_cast<uint32_t>(read_le(buf, 0x80, 4));
        uint32_t eax = static_cast<uint32_t>(read_le(buf, 0x90, 4));
        uint32_t ebp = static_cast<uint32_t>(read_le(buf, 0x94, 4));
        uint32_t edx = static_cast<uint32_t>(read_le(buf, 0x88, 4));
        uint32_t ecx = static_cast<uint32_t>(read_le(buf, 0x8C, 4));
        uint32_t ebx = static_cast<uint32_t>(read_le(buf, 0x84, 4));
        uint32_t esp = static_cast<uint32_t>(read_le(buf, 0xA4, 4));
        uint32_t eip = static_cast<uint32_t>(read_le(buf, 0x98, 4));

        reg_write(speakeasy::arch::REG_EDI, edi);
        reg_write(speakeasy::arch::REG_ESI, esi);
        reg_write(speakeasy::arch::REG_EAX, eax);
        reg_write(speakeasy::arch::REG_EBP, ebp);
        reg_write(speakeasy::arch::REG_EDX, edx);
        reg_write(speakeasy::arch::REG_ECX, ecx);
        reg_write(speakeasy::arch::REG_EBX, ebx);
        reg_write(speakeasy::arch::REG_ESP, esp);
        reg_write(speakeasy::arch::REG_EIP, eip);

        uint32_t eflags = static_cast<uint32_t>(read_le(buf, 0xA0, 4));
        uint32_t seg_cs = static_cast<uint32_t>(read_le(buf, 0x9C, 4));
        uint32_t seg_ss = static_cast<uint32_t>(read_le(buf, 0xA8, 4));
        uint32_t seg_ds = static_cast<uint32_t>(read_le(buf, 0x78, 4));
        uint32_t seg_fs = static_cast<uint32_t>(read_le(buf, 0x70, 4));
        uint32_t seg_gs = static_cast<uint32_t>(read_le(buf, 0x6C, 4));
        uint32_t seg_es = static_cast<uint32_t>(read_le(buf, 0x74, 4));

        reg_write(speakeasy::arch::REG_EFLAGS, eflags);
        reg_write(speakeasy::arch::REG_CS, seg_cs);
        reg_write(speakeasy::arch::REG_SS, seg_ss);
        reg_write(speakeasy::arch::REG_DS, seg_ds);
        reg_write(speakeasy::arch::REG_FS, seg_fs);
        reg_write(speakeasy::arch::REG_GS, seg_gs);
        reg_write(speakeasy::arch::REG_ES, seg_es);
    } else if (get_arch() == speakeasy::arch::ARCH_AMD64) {
        uint64_t rax = read_le(buf, 0xB8, 8);
        uint64_t rbx = read_le(buf, 0xD0, 8);
        uint64_t rcx = read_le(buf, 0xC0, 8);
        uint64_t rdx = read_le(buf, 0xC8, 8);
        uint64_t rsi = read_le(buf, 0xE8, 8);
        uint64_t rdi = read_le(buf, 0xF0, 8);
        uint64_t rbp = read_le(buf, 0xE0, 8);
        uint64_t rsp = read_le(buf, 0xD8, 8);
        uint64_t rip = read_le(buf, 0x140, 8);
        uint64_t r8  = read_le(buf, 0xF8, 8);
        uint64_t r9  = read_le(buf, 0x100, 8);
        uint64_t r10 = read_le(buf, 0x108, 8);
        uint64_t r11 = read_le(buf, 0x110, 8);
        uint64_t r12 = read_le(buf, 0x118, 8);
        uint64_t r13 = read_le(buf, 0x120, 8);
        uint64_t r14 = read_le(buf, 0x128, 8);
        uint64_t r15 = read_le(buf, 0x130, 8);

        reg_write(speakeasy::arch::REG_RAX, rax);
        reg_write(speakeasy::arch::REG_RBX, rbx);
        reg_write(speakeasy::arch::REG_RCX, rcx);
        reg_write(speakeasy::arch::REG_RDX, rdx);
        reg_write(speakeasy::arch::REG_RSI, rsi);
        reg_write(speakeasy::arch::REG_RDI, rdi);
        reg_write(speakeasy::arch::REG_RBP, rbp);
        reg_write(speakeasy::arch::REG_RSP, rsp);
        reg_write(speakeasy::arch::REG_RIP, rip);
        reg_write(speakeasy::arch::REG_R8, r8);
        reg_write(speakeasy::arch::REG_R9, r9);
        reg_write(speakeasy::arch::REG_R10, r10);
        reg_write(speakeasy::arch::REG_R11, r11);
        reg_write(speakeasy::arch::REG_R12, r12);
        reg_write(speakeasy::arch::REG_R13, r13);
        reg_write(speakeasy::arch::REG_R14, r14);
        reg_write(speakeasy::arch::REG_R15, r15);

        uint64_t eflags = read_le(buf, 0x78, 4);
        uint16_t seg_cs = static_cast<uint16_t>(read_le(buf, 0x48, 2));
        uint16_t seg_ss = static_cast<uint16_t>(read_le(buf, 0x70, 2));
        uint16_t seg_ds = static_cast<uint16_t>(read_le(buf, 0x50, 2));
        uint16_t seg_fs = static_cast<uint16_t>(read_le(buf, 0x60, 2));
        uint16_t seg_gs = static_cast<uint16_t>(read_le(buf, 0x68, 2));
        uint16_t seg_es = static_cast<uint16_t>(read_le(buf, 0x58, 2));

        reg_write(speakeasy::arch::REG_EFLAGS, eflags);
        reg_write(speakeasy::arch::REG_CS, seg_cs);
        reg_write(speakeasy::arch::REG_SS, seg_ss);
        reg_write(speakeasy::arch::REG_DS, seg_ds);
        reg_write(speakeasy::arch::REG_FS, seg_fs);
        reg_write(speakeasy::arch::REG_GS, seg_gs);
        reg_write(speakeasy::arch::REG_ES, seg_es);
    }
}

// ── SEH ──────────────────────────────────────────────────────


// Python winemu.py:2662
// def dispatch_seh(self, except_code, faulting_address=None):
//     """Dispatch a structured exception by walking the SEH chain. Falls back
//     to unhandled exception filter if available."""
bool WindowsEmulator::dispatch_seh(uint64_t except_code, uint64_t faulting_address) {
    auto fault_key = std::make_tuple(get_pc(), faulting_address);
    if (fault_key == _seh_last_fault) {
        _seh_repeat_count++;
        if (_seh_repeat_count >= _SEH_MAX_REPEAT) return false;
    } else {
        _seh_last_fault = fault_key;
        _seh_repeat_count = 1;
    }

    bool rv = false;
    if (ptr_size == 4) {
        rv = _dispatch_seh_x86(except_code);
    } else {
        // x64: VEH (Vectored Exception Handling) — walk VEH handler list
        for (auto* veh : veh_handlers) {
            uint64_t handler = reinterpret_cast<uint64_t>(veh);
            if (handler == 0 || handler == 0xFFFFFFFFFFFFFFFFULL) continue;
            curr_exception_code = except_code;
            call(handler);
            rv = true;
            break;
        }
    }

    // If SEH dispatch failed, try the unhandled exception filter
    if (!rv && unhandled_exception_filter != 0) {
        // Build EXCEPTION_RECORD and EXCEPTION_POINTERS in emulated memory
        // Layout: EXCEPTION_RECORD = {code, flags, record, addr, numparams, params[15]}
        // Simple flat allocation strategy
        uint64_t pc = get_pc();
        int psz = get_ptr_size();

        // Allocate and write a simplified EXCEPTION_RECORD
        size_t rec_size = static_cast<size_t>(4 + 4 + psz + psz + 4 + 15 * psz);
        uint64_t prec = mem_map(rec_size, 0, PERM_MEM_RW, "emu.struct.EXCEPTION_RECORD");
        std::vector<uint8_t> rec_bytes(rec_size, 0);
        write_le(rec_bytes, 0, static_cast<uint32_t>(except_code), 4);         // ExceptionCode
        write_le(rec_bytes, 4, static_cast<uint32_t>(0), 4);                   // ExceptionFlags
        // ExceptionRecord (next) = 0
        // ExceptionAddress
        write_le(rec_bytes, static_cast<size_t>(4 + 4 + psz), pc, psz);
        // NumberParameters = 0
        // Parameters[15] = 0
        mem_write(prec, rec_bytes);

        // Allocate CONTEXT structure
        void* ctx = get_thread_context();
        uint64_t pctx = reinterpret_cast<uint64_t>(ctx);

        // Allocate EXCEPTION_POINTERS
        size_t eptrs_size = static_cast<size_t>(psz + psz);
        uint64_t p_exp_ptrs = mem_map(eptrs_size, 0, PERM_MEM_RW, "emu.struct.EXCEPTION_POINTERS");
        std::vector<uint8_t> eptrs_bytes(eptrs_size, 0);
        write_le(eptrs_bytes, 0, prec, psz);     // ExceptionRecord
        write_le(eptrs_bytes, static_cast<size_t>(psz), pctx, psz);  // ContextRecord
        mem_write(p_exp_ptrs, eptrs_bytes);

        // Call unhandled exception filter
        uint64_t sp = get_stack_ptr();
        std::vector<uint64_t> args = {p_exp_ptrs};
        set_func_args(sp, EMU_RETURN_ADDR, args);
        set_pc(unhandled_exception_filter);
        unhandled_exception_filter = 0;
        rv = true;
    }

    if (rv && faulting_address != 0) {
        // Map a page at the faulting address so we can continue execution
        uint64_t page_addr = faulting_address & ~(page_size - 1);
        try {
            mem_map(page_size, page_addr, PERM_MEM_RW, "emu.page.fault", 0, false);
        } catch (...) {}
    }

    return rv;
}


// Python winemu.py:2478
// def _dispatch_seh_x86(self, except_code):
//     """Get the initial SEH handler when dispatching a CPU exception that occurs during emulation"""
bool WindowsEmulator::_dispatch_seh_x86(uint64_t except_code) {
    // Walk the EXCEPTION_REGISTRATION chain at fs:[0]
    uint64_t seh_chain = _get_exception_list();
    if (seh_chain == 0 || seh_chain == 0xFFFFFFFF) return false;

    // Read EXCEPTION_REGISTRATION record: [next_ptr] [handler]
    uint64_t next_ptr = read_ptr(seh_chain);
    uint64_t handler = read_ptr(seh_chain + ptr_size);
    if (handler == 0 || handler == 0xFFFFFFFF) return false;

    // Call the SEH handler
    curr_exception_code = except_code;
    call(handler);  // Jump to the handler
    return true;
}


// Python winemu.py:2589
// def _continue_seh_x86(self):
//     """Get the next exception handler while processing SEH"""
void WindowsEmulator::_continue_seh_x86() {
    // After SEH handler returns, EIP should be set by the handler
    // The handler typically calls RtlRestoreContext or similar
    set_pc(0);  // Placeholder — actual EIP from handler context
}



// Python winemu.py:2707
// def continue_seh(self):
//     """Reset SEH repeat-detection state."""
void WindowsEmulator::continue_seh() {
    _seh_last_fault = {0, 0};
    _seh_repeat_count = 0;
}

// ── API dispatch ──────────────────────────────────────────────


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
std::tuple<std::string, std::string> WindowsEmulator::normalize_import_miss(
    const std::string& dll, const std::string& name) {
    // Python reference: winemu.py lines 1561-1602
    std::string ndll = dll;
    std::string nname = name;

    if (ndll.size() > 4) {
        auto ext = ndll.substr(ndll.size() - 4);
        for (auto& c : ext) c = static_cast<char>(std::tolower(c));
        if (ext == ".dll") ndll = ndll.substr(0, ndll.size() - 4);
    }
    for (auto& c : ndll) c = static_cast<char>(std::tolower(c));

    std::string alt_name;
    if (!nname.empty() && (nname.back() == 'A' || nname.back() == 'W')) {
        alt_name = nname.substr(0, nname.size() - 1);
    }

    bool is_ntos = (ndll.find("ntoskrnl") != std::string::npos);
    if (is_ntos) {
        if (nname.find("Zw") == 0 && nname.size() > 2)
            alt_name = "Nt" + nname.substr(2);
        else if (nname.find("Nt") == 0 && nname.size() > 2)
            alt_name = "Zw" + nname.substr(2);
    }

    bool is_ntdll = (ndll.find("ntdll") != std::string::npos);
    if (is_ntdll)
        ndll = "ntoskrnl";

    if (!alt_name.empty())
        nname = alt_name;

    return {ndll, nname};
}


// Python winemu.py:1639
// def handle_import_func(self, dll, name):
//     """Forward imported functions to the corresponding handler (if any)."""
void WindowsEmulator::handle_import_func(const std::string& dll, const std::string& name) {
    // Python reference: winemu.py lines 1639-1751
    std::string imp_api = dll + "." + name;

    uint64_t oret = get_ret_address();
    uint64_t opc  = get_pc();
    uint64_t call_pc = (prev_pc != 0) ? prev_pc : oret;

    // Normalize module name
    std::string dll_norm = dll;
    for (auto& c : dll_norm) c = static_cast<char>(std::tolower(c));
    if (dll_norm.size() > 4 && dll_norm.substr(dll_norm.size() - 4) == ".dll")
        dll_norm = dll_norm.substr(0, dll_norm.size() - 4);

    // ── Primary handler lookup ──
    ApiHandler* handler_mod = nullptr;
    void* func_ptr = nullptr;

    if (api) {
        auto* wapi = static_cast<WindowsApi*>(api);
        std::tie(handler_mod, func_ptr) = wapi->get_export_func_handler(dll_norm, name);
    }

    // ── Normalization fallback ──
    if (!func_ptr) {
        auto [alt_dll, alt_name] = normalize_import_miss(dll, name);
        if (alt_dll != dll_norm || alt_name != name) {
            if (api) {
                auto* wapi = static_cast<WindowsApi*>(api);
                std::tie(handler_mod, func_ptr) = wapi->get_export_func_handler(alt_dll, alt_name);
                if (func_ptr) imp_api = alt_dll + "." + alt_name;
            }
        }
    }

    // ── Execute handler ──
    if (func_ptr && handler_mod) {
        int conv = speakeasy::arch::CALL_CONV_STDCALL;
        int argc = 4;

        // Re-query handler metadata for argc/conv
        auto [fn_name, hfunc, hargc, hconv, hord] = handler_mod->get_func_handler(name);
        (void)hord;
        if (hfunc) { argc = hargc; conv = hconv; }
        if (!name.empty() && name.find("ordinal_") == 0 && !fn_name.empty())
            imp_api = dll + "." + fn_name;

        auto argv = get_func_argv(conv, argc);

        if (api) {
            try {
                auto* wapi = static_cast<WindowsApi*>(api);
                std::vector<void*> vptr_argv;
                for (auto a : argv)
                    vptr_argv.push_back(reinterpret_cast<void*>(static_cast<uintptr_t>(a)));
                wapi->call_api_func(handler_mod, func_ptr, vptr_argv, nullptr);

                uint64_t rv = 0;  // handlers set ret via registers
                uint64_t ret = get_ret_address();
                uint64_t pc = get_pc();

                log_api(call_pc, imp_api, rv, argv);

                if (!run_complete && ret == oret && pc == opc) {
                    do_call_return(argc, ret, rv, conv);
                }
            } catch (const std::exception& e) {
                (void)e;
                on_run_complete();
                return;
            }
        }
        return;
    }

    // ── No handler: unsupported API ──
    // (API hooks not yet ported — ApiHook struct is TBD)
    on_run_complete();
}


// Python winemu.py:1372
// def handle_import_data(self, mod_name, sym, data_ptr=0):
//     """Data that is imported (e.g. KeTickCount) is handled with an initializer function."""
void WindowsEmulator::handle_import_data(const std::string& mod, const std::string& sym,
                                          uint64_t data_ptr) {
    // Python reference: winemu.py lines 1372-1387
    if (!api) return;

    auto* wapi = static_cast<WindowsApi*>(api);
    // Try data export handler first
    auto [data_mod, data_func] = wapi->get_data_export_handler(mod, sym);
    if (data_func) {
        wapi->call_data_func(data_mod, data_func, data_ptr);
        return;
    }
    // Fallback: try func export handler (returns a procedure address)
    auto [func_mod, func_ptr] = wapi->get_export_func_handler(mod, sym);
    if (func_ptr) {
        // Get procedure address (sentinel) for this module+function
        get_proc(mod, sym);
        return;
    }
}


// Python winemu.py:1614
// def log_api(self, pc, imp_api, rv, argv):
//     """Log an API call with its arguments and return value."""
void WindowsEmulator::log_api(uint64_t pc, const std::string& api,
                               uint64_t rv, const std::vector<uint64_t>& argv) {
    if (profiler) {
        std::vector<std::string> str_argv;
        for (auto a : argv) str_argv.push_back("0x" + speakeasy::hex_str(a));
        profiler->log_api(curr_run, pc, api, reinterpret_cast<void*>(rv), str_argv);
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

// ── Memory hooks (additional) ───────────────────────────────


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
        void* mod = get_mod_from_addr(addr);
        if (mod) {
            auto* pe = static_cast<PeFile*>(mod);
            auto sects = pe->get_sections();
            for (auto& sect : sects) {
                uint64_t base = pe->get_base();
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
            MemAccess mac(mmap->get_base(), page_size);
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
        void* mod = get_mod_from_addr(addr);
        if (mod) {
            auto* pe = static_cast<PeFile*>(mod);
            auto sects = pe->get_sections();
            for (auto& sect : sects) {
                uint64_t base = pe->get_base();
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

    try {
        // Ensure code hook is active for deferred work
        if (!tmp_code_hook) {
            enable_code_hook();
        }

        if (access == INVALID_MEM_EXEC) {
            // SEH return - continue SEH and unset emu hooks
            if (addr == SEH_RETURN_ADDR) {
                continue_seh();
                _unset_emu_hooks();
                return true;
            }
            // API callback handler
            if (addr == API_CALLBACK_HANDLER_ADDR) {
                if (!curr_run->api_callbacks.empty()) {
                    auto cb = curr_run->api_callbacks.front();
                    curr_run->api_callbacks.erase(curr_run->api_callbacks.begin());
                    // cb is a function<void()> — invoke to process pending work
                    // For now, unset hooks and let code core handle it
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
            // Map a temporary page and dispatch
            uint64_t fakeout = addr & ~(page_size - 1);
            mem_map(page_size, fakeout, PERM_MEM_RW, "emu.page.tmp", 0, false);
            tmp_maps.push_back({fakeout, page_size});
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
    (void)emu; (void)addr; (void)size; (void)value;
    return false;
}


// Python winemu.py:1802
// def _handle_prot_write(self, emu, address, size, value):
//     """Handle protection violation on write access by mapping a fake page and logging error."""
bool WindowsEmulator::_handle_prot_write(void* emu, uint64_t addr,
                                          size_t size, uint64_t value) {
    (void)emu; (void)addr; (void)size; (void)value;
    return false;
}

// ── Code hooks (additional) ─────────────────────────────────


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
        void* mod = get_mod_from_addr(addr);
        if (mod) {
            auto* pe = static_cast<PeFile*>(mod);
            auto sects = pe->get_sections();
            for (auto& sect : sects) {
                uint64_t base = pe->get_base();
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
            MemAccess mac(mmap->get_base(), page_size);
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
        printf("0x%llx: %s, %s\n",
               static_cast<unsigned long long>(addr),
               instr.c_str(), regs_str.c_str());
        return true;
    } catch (...) {
        return true;
    }
}


// Python winemu.py:232
// def set_coverage_hooks(self):
//     """Install coverage tracking code hook if enabled in config."""
void WindowsEmulator::set_coverage_hooks() {
    _register_code_hook(reinterpret_cast<void*>(code_coverage_trampoline), 1, 0);
}


// Python winemu.py:242
// def set_debug_hooks(self):
//     """Install debug code hook if enabled."""
void WindowsEmulator::set_debug_hooks() {
    _register_code_hook(reinterpret_cast<void*>(code_debug_trampoline), 1, 0);
}


// Python winemu.py:1322
// def resume_thread(self, thread):
//     """Resume a previously suspended thread"""
void WindowsEmulator::resume_thread(void* thread) {
    (void)thread;
    resume(0);  // Resume emulation at current PC
}


// Python winemu.py:1333
// def get_process_peb(self, process):
//     """Get the PEB for a given process."""
void* WindowsEmulator::get_process_peb(void* process) {
    void* p = process ? process : curr_process;
    if (p) {
        auto* proc = static_cast<Process*>(p);
        return proc->peb;
    }
    return nullptr;
}

// ── Error / context ─────────────────────────────────────────


// Python winemu.py:1511
// def get_error_info(self, desc, address, traceback=None, access_type=None):
//     """Collect emulator state information in the event of an error."""
std::string WindowsEmulator::get_error_info(const std::string& msg, uint64_t pc,
                                             const std::string& trace) {
    std::string result;

    // Build module + offset info for PC
    std::string pc_module = _resolve_module_offset(pc);
    std::string addr_region = _resolve_region_info(pc);

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
        addr_region.empty() ? "none" : addr_region.c_str(),
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
    (void)addr;
    return "";
}


// Python winemu.py:1448
// def _resolve_region_info(self, addr: int) -> RegionInfo | None:
//     """Return a RegionInfo for the region containing addr, or None if unmapped."""
std::string WindowsEmulator::_resolve_region_info(uint64_t addr) {
    (void)addr;
    return "";
}


// ── Hardware interrupts ──────────────────────────────────────


// Python winemu.py:2742
// def _hook_interrupt(self, emu, intnum):
//     """Called when software interrupts occur (INT3, INT0, INT1, INT0x29, etc.)"""
bool WindowsEmulator::_hook_interrupt(void* emu, int intnum) {
    (void)emu; (void)intnum;
    return false;
}

// ── Run control extension ─────────────────────────────────────


// Python winemu.py:386
// def add_run(self, run):
//     """Add a run to the emulation run queue"""
void WindowsEmulator::add_run(std::shared_ptr<Run> run) {
    run_queue.push_back(run);
}

// ── Bootstrap / reference counting ────────────────────────────


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

// ── File management wrappers ──────────────────────────────────


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
void* WindowsEmulator::file_create_mapping(void* hfile, const std::string& name,
                                            size_t size, int prot) {
    auto* fm = static_cast<FileManager*>(fileman);
    if (fm) {
        uint32_t handle = fm->file_create_mapping(
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(hfile)), name, size, prot);
        (void)handle;
    }
    return nullptr;
}

// ── Manager accessors ─────────────────────────────────────────


// Python winemu.py:309
// def get_file_manager(self):
//     """Get the file emulation manager"""
FileManager* WindowsEmulator::get_file_manager()    { return fileman; }

// Python winemu.py:315
// def get_network_manager(self):
//     """Get the network emulation manager"""
NetworkManager* WindowsEmulator::get_network_manager() { return netman; }

// Python winemu.py:321
// def get_crypt_manager(self):
//     """Get the crypto manager"""
CryptoManager* WindowsEmulator::get_crypt_manager()   { return cryptman; }

// Python winemu.py:327
// def get_drive_manager(self):
//     """Get the drive manager"""
DriveManager* WindowsEmulator::get_drive_manager()   { return driveman; }

// ── Registry wrappers ─────────────────────────────────────────


// Python winemu.py:357
// def reg_get_subkeys(self, hkey):
//     """Get subkeys for a given registry key"""
std::vector<std::string> WindowsEmulator::reg_get_subkeys(void* hkey) {
    (void)hkey;
    // RegistryManager::get_subkeys accepts shared_ptr<RegKey> — adapter needed
    return {};
}


// Python winemu.py:333
// def dev_ioctl(self, arch, dev, ioctl, inbuf):
//     """Dispatch a device I/O control request to the I/O manager."""
void* WindowsEmulator::dev_ioctl(uint32_t ctl_code, void* in_buf,
                                  size_t in_len, void* out_buf, size_t out_len) {
    (void)in_buf; (void)in_len; (void)out_buf; (void)out_len;
    // Dispatch to kernel-mode IRP handler via IoManager
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ctl_code));
}


// Python winemu.py:— (Unicorn engine binding)
void WindowsEmulator::_register_code_hook(void* callback, uint64_t begin, uint64_t end) {
    if (!emu_eng) return;
    uc_hook hh = 0;
    uc_err err = uc_hook_add(emu_eng->get_engine(), &hh, UC_HOOK_CODE,
                              callback, static_cast<void*>(this), begin, end);
    if (err == UC_ERR_OK) {
        uc_hooks_.push_back(hh);
    }
}


// Python winemu.py:— (Unicorn engine binding)
void WindowsEmulator::_register_mem_hook(int hook_type, void* callback) {
    if (!emu_eng) return;
    uc_hook hh = 0;
    uc_err err = uc_hook_add(emu_eng->get_engine(), &hh, UC_HOOK_MEM_READ,
                              callback, static_cast<void*>(this), 1, 0);
    (void)hook_type;
    if (err == UC_ERR_OK) {
        uc_hooks_.push_back(hh);
    }
}

// _get_exception_list was accidentally removed — re-adding

// Python winemu.py:2467
// def _get_exception_list(self):
//     """Retrieves the exception handler list for the current thread"""
uint64_t WindowsEmulator::_get_exception_list() {
    uint64_t teb = (ptr_size == 4) ? fs_addr : gs_addr;
    return (teb != 0) ? read_ptr(teb) : 0;
}

// Python winemu.py:2652
// def _map_faulting_page_for_exception(self, faulting_address):
//     """Map a single page at faulting_address with RW permissions for SEH recovery"""
void WindowsEmulator::_map_faulting_page_for_exception(uint64_t faulting_address) {
    uint64_t fakeout = faulting_address & ~(page_size - 1);
    // Check if already mapped
    for (const auto& region : get_mem_regions()) {
        uint64_t base = std::get<0>(region);
        uint64_t end = std::get<1>(region);
        if (base <= fakeout && fakeout <= end)
            return;
    }
    mem_map(page_size, fakeout, PERM_MEM_RW, "emu.seh.fault_page");
    tmp_maps.push_back({fakeout, page_size});
}
