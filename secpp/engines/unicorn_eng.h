// unicorn_eng.h
#ifndef SPEAKEASY_UNICORN_ENG_H
#define SPEAKEASY_UNICORN_ENG_H

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <string>

#include "../winenv/arch.h" // Include architecture definitions
// Include Unicorn Engine C API
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

// Forward declarations
class Process;


/**
 * Hook that can be toggled on/off at arbitrary times.
 */
class ToggleableHook {
private:
    std::function<void()> cb;
    bool enabled;

public:
    ToggleableHook(std::function<void()> callback) : cb(callback), enabled(false) {}

    void enable() {
        if (enabled) return;
        enabled = true;
    }

    void disable() {
        enabled = false;
    }

    bool is_enabled() const {
        return enabled;
    }
};

/**
 * Wrapper class for underlying cpu emulation engines
 */
class EmuEngine {
private:
    std::string name;
    uc_engine* emu;
    void* mmap;
    std::unordered_map<uint64_t, std::shared_ptr<ToggleableHook>> callbacks;

    // Register mapping
    std::unordered_map<int, int> regs;

    // Memory access mapping
    std::unordered_map<int, uint32_t> mem_access;

    // Permission mapping
    std::unordered_map<uint32_t, uint32_t> perms;

    // Hook type mapping
    std::unordered_map<uint32_t, uint32_t> hook_types;

public:
    /**
     * Constructor for EmuEngine
     */
    EmuEngine();

    /**
     * Initialize cpu engine
     */
    void init_engine(int eng_arch, int mode);

    /**
     * Allocate memory in the cpu engine
     */
    uc_err mem_map(uint64_t base, size_t size, uint32_t perms = PERM_MEM_RWX);

    /**
     * Free memory in the cpu engine
     */
    uc_err mem_unmap(uint64_t addr, size_t size);

    /**
     * Get current memory allocations from the engine
     */
    uc_err mem_regions(uc_mem_region** regions, uint32_t* count);

    /**
     * Write data into the address space of the engine
     */
    uc_err mem_write(uint64_t addr, const void* data, size_t size);

    /**
     * Read data from the address space of the engine
     */
    uc_err mem_read(uint64_t addr, void* data, size_t size);

    /**
     * Change the memory protections for pages in the emu engine
     */
    uc_err mem_protect(uint64_t addr, size_t size, uint32_t perms);

    /**
     * Modify register values
     */
    uc_err reg_write(int reg, uint64_t val);

    /**
     * Read register values
     */
    uc_err reg_read(int reg, uint64_t* val);

    /**
     * Stop the emulation engine
     */
    uc_err stop();

    /**
     * Start the emulation engine
     */
    uc_err start(uint64_t addr, uint64_t timeout = 0, size_t count = 0);

    /**
     * Add a callback function for a specific event type or address
     */
    uint64_t hook_add(void* addr = nullptr, void* cb = nullptr, uint32_t htype = 0, 
                      void* ctx = nullptr, uint64_t begin = 1, uint64_t end = 0, 
                      uint32_t arg1 = 0);

    /**
     * Enable a previously disabled hook
     */
    void hook_enable(uint64_t hook_handle);

    /**
     * Disable a previously enabled hook
     */
    void hook_disable(uint64_t hook_handle);

    /**
     * Remove a hook
     */
    uc_err hook_remove(uint64_t hid);

    /**
     * Get the underlying unicorn engine
     */
    uc_engine* get_engine() const { return emu; }

private:
    /**
     * Convert seconds to microseconds
     */
    uint64_t _sec_to_usec(double sec);

    /**
     * Initialize register mappings
     */
    void init_regs();

    /**
     * Initialize memory access mappings
     */
    void init_mem_access();

    /**
     * Initialize permission mappings
     */
    void init_perms();

    /**
     * Initialize hook type mappings
     */
    void init_hook_types();
};

#endif // SPEAKEASY_UNICORN_ENG_H