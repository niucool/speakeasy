// unicorn_eng.cpp
#include "unicorn_eng.h"
#include <stdexcept>
#include <cstring>

/**
 * Constructor for EmuEngine
 */
EmuEngine::EmuEngine() : name("unicorn"), emu(nullptr), mmap(nullptr) {
    init_regs();
    init_mem_access();
    init_perms();
    init_hook_types();
}

/**
 * Initialize register mappings
 */
void EmuEngine::init_regs() {
    // x86 registers
    regs[X86_REG_EAX] = UC_X86_REG_EAX;
    regs[X86_REG_EBX] = UC_X86_REG_EBX;
    regs[X86_REG_ESP] = UC_X86_REG_ESP;
    regs[X86_REG_EIP] = UC_X86_REG_EIP;
    regs[X86_REG_EBP] = UC_X86_REG_EBP;
    regs[X86_REG_ECX] = UC_X86_REG_ECX;
    regs[X86_REG_EDX] = UC_X86_REG_EDX;
    regs[X86_REG_EDI] = UC_X86_REG_EDI;
    regs[X86_REG_ESI] = UC_X86_REG_ESI;
    regs[X86_REG_EFLAGS] = UC_X86_REG_EFLAGS;
    
    // AMD64 registers
    regs[AMD64_REG_RIP] = UC_X86_REG_RIP;
    regs[AMD64_REG_RAX] = UC_X86_REG_RAX;
    regs[AMD64_REG_RBX] = UC_X86_REG_RBX;
    regs[AMD64_REG_RSP] = UC_X86_REG_RSP;
    regs[AMD64_REG_RCX] = UC_X86_REG_RCX;
    regs[AMD64_REG_RDX] = UC_X86_REG_RDX;
    regs[AMD64_REG_RSI] = UC_X86_REG_RSI;
    regs[AMD64_REG_RDI] = UC_X86_REG_RDI;
    regs[AMD64_REG_RBP] = UC_X86_REG_RBP;
    regs[AMD64_REG_R8] = UC_X86_REG_R8;
    regs[AMD64_REG_R9] = UC_X86_REG_R9;
    regs[AMD64_REG_R10] = UC_X86_REG_R10;
    regs[AMD64_REG_R11] = UC_X86_REG_R11;
    regs[AMD64_REG_R12] = UC_X86_REG_R12;
    regs[AMD64_REG_R13] = UC_X86_REG_R13;
    regs[AMD64_REG_R14] = UC_X86_REG_R14;
    regs[AMD64_REG_R15] = UC_X86_REG_R15;
    
    // Descriptor registers
    regs[X86_REG_IDTR] = UC_X86_REG_IDTR;
    regs[X86_REG_GDTR] = UC_X86_REG_GDTR;
    
    // XMM registers
    regs[X86_REG_XMM0] = UC_X86_REG_XMM0;
    regs[X86_REG_XMM1] = UC_X86_REG_XMM1;
    regs[X86_REG_XMM2] = UC_X86_REG_XMM2;
    regs[X86_REG_XMM3] = UC_X86_REG_XMM3;
    
    // Segment registers
    regs[X86_REG_CS] = UC_X86_REG_CS;
    regs[X86_REG_ES] = UC_X86_REG_ES;
    regs[X86_REG_SS] = UC_X86_REG_SS;
    regs[X86_REG_DS] = UC_X86_REG_DS;
    regs[X86_REG_FS] = UC_X86_REG_FS;
    regs[X86_REG_GS] = UC_X86_REG_GS;
    
    regs[X86_REG_MSR] = UC_X86_REG_MSR;
}

/**
 * Initialize memory access mappings
 */
void EmuEngine::init_mem_access() {
    mem_access[UC_MEM_FETCH_UNMAPPED] = INVALID_MEM_EXEC;
    mem_access[UC_MEM_READ_UNMAPPED] = INVALID_MEM_READ;
    mem_access[UC_MEM_FETCH_PROT] = INVAL_PERM_MEM_EXEC;
    mem_access[UC_MEM_WRITE_PROT] = INVAL_PERM_MEM_WRITE;
    mem_access[UC_MEM_READ_PROT] = INVAL_PERM_MEM_READ;
    mem_access[UC_MEM_WRITE_UNMAPPED] = INVALID_MEM_WRITE;
}

/**
 * Initialize permission mappings
 */
void EmuEngine::init_perms() {
    perms[PERM_MEM_RWX] = UC_PROT_ALL;
    perms[PERM_MEM_WRITE] = UC_PROT_WRITE;
    perms[PERM_MEM_READ] = UC_PROT_READ;
    perms[PERM_MEM_RW] = UC_PROT_READ | UC_PROT_WRITE;
}

/**
 * Initialize hook type mappings
 */
void EmuEngine::init_hook_types() {
    hook_types[HOOK_CODE] = UC_HOOK_CODE;
    hook_types[HOOK_MEM_ACCESS] = UC_HOOK_MEM_VALID;
    hook_types[HOOK_MEM_INVALID] = UC_HOOK_MEM_INVALID;
    hook_types[HOOK_MEM_PERM_EXEC] = UC_HOOK_MEM_FETCH_PROT;
    hook_types[HOOK_MEM_PERM_WRITE] = UC_HOOK_MEM_WRITE_PROT;
    hook_types[HOOK_MEM_READ] = UC_HOOK_MEM_READ;
    hook_types[HOOK_MEM_WRITE] = UC_HOOK_MEM_WRITE;
    hook_types[HOOK_INTERRUPT] = UC_HOOK_INTR;
    hook_types[HOOK_INSN] = UC_HOOK_INSN;
    hook_types[HOOK_INSN_INVALID] = UC_HOOK_INSN_INVALID;
}

/**
 * Convert seconds to microseconds
 */
uint64_t EmuEngine::_sec_to_usec(double sec) {
    return static_cast<uint64_t>(sec * 1000000);
}

/**
 * Initialize cpu engine
 */
void EmuEngine::init_engine(int eng_arch, int mode) {
    uc_arch arch;
    uc_mode m;
    
    if (eng_arch == ARCH_X86 || eng_arch == ARCH_AMD64) {
        arch = UC_ARCH_X86;
    } else {
        throw std::runtime_error("Invalid architecture");
    }
    
    if (mode == BITS_32) {
        m = UC_MODE_32;
    } else if (mode == BITS_64) {
        m = UC_MODE_64;
    } else {
        throw std::runtime_error("Invalid bitness");
    }
    
    uc_err err = uc_open(arch, m, &emu);
    if (err != UC_ERR_OK) {
        throw std::runtime_error("Failed to initialize Unicorn engine");
    }
}

/**
 * Allocate memory in the cpu engine
 */
uc_err EmuEngine::mem_map(uint64_t base, size_t size, uint32_t perms) {
    uint32_t perm = perms;
    auto it = this->perms.find(perms);
    if (it != this->perms.end()) {
        perm = it->second;
    }
    return uc_mem_map(emu, base, size, perm);
}

/**
 * Free memory in the cpu engine
 */
uc_err EmuEngine::mem_unmap(uint64_t addr, size_t size) {
    return uc_mem_unmap(emu, addr, size);
}

/**
 * Get current memory allocations from the engine
 */
uc_err EmuEngine::mem_regions(uc_mem_region** regions, uint32_t* count) {
    return uc_mem_regions(emu, regions, count);
}

/**
 * Write data into the address space of the engine
 */
uc_err EmuEngine::mem_write(uint64_t addr, const void* data, size_t size) {
    return uc_mem_write(emu, addr, data, size);
}

/**
 * Read data from the address space of the engine
 */
uc_err EmuEngine::mem_read(uint64_t addr, void* data, size_t size) {
    return uc_mem_read(emu, addr, data, size);
}

/**
 * Change the memory protections for pages in the emu engine
 */
uc_err EmuEngine::mem_protect(uint64_t addr, size_t size, uint32_t perms) {
    uint32_t perm = perms;
    auto it = this->perms.find(perms);
    if (it != this->perms.end()) {
        perm = it->second;
    }
    return uc_mem_protect(emu, addr, size, perm);
}

/**
 * Modify register values
 */
uc_err EmuEngine::reg_write(int reg, uint64_t val) {
    auto it = regs.find(reg);
    if (it == regs.end()) {
        return UC_ERR_ARG;
    }
    return uc_reg_write(emu, it->second, &val);
}

/**
 * Read register values
 */
uc_err EmuEngine::reg_read(int reg, uint64_t* val) {
    auto it = regs.find(reg);
    if (it == regs.end()) {
        return UC_ERR_ARG;
    }
    return uc_reg_read(emu, it->second, val);
}

/**
 * Stop the emulation engine
 */
uc_err EmuEngine::stop() {
    return uc_emu_stop(emu);
}

/**
 * Start the emulation engine
 */
uc_err EmuEngine::start(uint64_t addr, uint64_t timeout, size_t count) {
    if (count == static_cast<size_t>(-1)) {
        count = 0;
    }
    
    // Unicorn expects the timeout to be in microseconds, convert it here
    timeout = _sec_to_usec(timeout / 1000000.0);
    return uc_emu_start(emu, addr, 0xFFFFFFFF, timeout, count);
}

/**
 * Add a callback function for a specific event type or address
 */
uint64_t EmuEngine::hook_add(void* addr, void* cb, uint32_t htype, 
                             void* ctx, uint64_t begin, uint64_t end, uint32_t arg1) {
    auto hook_it = hook_types.find(htype);
    if (hook_it == hook_types.end()) {
        return 0; // Invalid hook type
    }
    
    uint32_t hook_type = hook_it->second;
    uc_hook hook;
    uc_err err;
    
    // For now, we'll use the standard unicorn hook_add
    // In a more complete implementation, you might want to implement
    // custom callback handling similar to the Python version
    err = uc_hook_add(emu, &hook, hook_type, cb, ctx, begin, end);
    if (err != UC_ERR_OK) {
        return 0;
    }
    
    // Store the hook in our callback map
    auto toggle_hook = std::make_shared<ToggleableHook>([](){}); // Placeholder
    callbacks[reinterpret_cast<uint64_t>(hook)] = toggle_hook;
    
    return reinterpret_cast<uint64_t>(hook);
}

/**
 * Enable a previously disabled hook
 */
void EmuEngine::hook_enable(uint64_t hook_handle) {
    auto it = callbacks.find(hook_handle);
    if (it != callbacks.end()) {
        it->second->enable();
    }
}

/**
 * Disable a previously enabled hook
 */
void EmuEngine::hook_disable(uint64_t hook_handle) {
    auto it = callbacks.find(hook_handle);
    if (it != callbacks.end()) {
        it->second->disable();
    }
}

/**
 * Remove a hook
 */
uc_err EmuEngine::hook_remove(uint64_t hid) {
    uc_hook hook = reinterpret_cast<uc_hook>(hid);
    return uc_hook_del(emu, hook);
}