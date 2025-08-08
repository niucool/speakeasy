// common.h
#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <functional>
#include <memory>

// Emulation hook types
const int HOOK_CODE = 1000;
const int HOOK_MEM_INVALID = 1001;
const int HOOK_MEM_PERM_EXEC = 1002;
const int HOOK_MEM_READ = 1003;
const int HOOK_MEM_WRITE = 1004;
const int HOOK_INTERRUPT = 1005;
const int HOOK_MEM_ACCESS = 1006;
const int HOOK_MEM_PERM_WRITE = 1007;
const int HOOK_API = 1008;
const int HOOK_DYN_CODE = 1009;
const int HOOK_INSN = 1010;
const int HOOK_MEM_MAP = 1011;
const int HOOK_INSN_INVALID = 1012;

// Emulation memory protection types
const int PERM_MEM_NONE = 0;
const int PERM_MEM_EXEC = 0x10;
const int PERM_MEM_READ = 0x02;
const int PERM_MEM_WRITE = 0x04;
const int PERM_MEM_RW = PERM_MEM_READ | PERM_MEM_WRITE;
const int PERM_MEM_RWX = PERM_MEM_READ | PERM_MEM_WRITE | PERM_MEM_EXEC;

// Emulation memory access types
const int INVALID_MEM_EXEC = 2000;
const int INVALID_MEM_READ = 2001;
const int INVALID_MEM_WRITE = 2002;
const int INVAL_PERM_MEM_WRITE = 2003;
const int INVAL_PERM_MEM_EXEC = 2004;
const int INVAL_PERM_MEM_READ = 2005;

// Forward declarations
class Speakeasy;
class EmuEngine;

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path);

/**
 * Base class for all emulator hooks
 */
class Hook {
protected:
    std::function<bool()> cb;
    int handle;
    bool enabled;
    bool added;
    bool native_hook;
    EmuEngine* emu_eng;
    Speakeasy* se_obj;
    std::vector<void*> ctx;

public:
    /**
     * Constructor for Hook
     * @param se_obj: speakeasy emulator object
     * @param emu_eng: emulation engine object
     * @param cb: callback function
     * @param ctx: Arbitrary context that be passed between hook callbacks
     * @param native_hook: When set to true, a new, raw callback will be registered with
     *                     with the underlying emulation engine that is called directly by the DLL.
     *                     Otherwise, this hook will be dispatched via a wrapper hook
     */
    Hook(Speakeasy* se_obj, EmuEngine* emu_eng, 
         std::function<bool()> cb, 
         const std::vector<void*>& ctx = {},
         bool native_hook = false);

    virtual ~Hook() = default;

    /**
     * Enable the hook
     */
    void enable();

    /**
     * Disable the hook
     */
    void disable();

    /**
     * Wrapper for code callback
     */
    bool _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, const std::vector<void*>& ctx = {});

    /**
     * Wrapper for interrupt callback
     */
    bool _wrap_intr_cb(void* emu, int num, const std::vector<void*>& ctx = {});

    /**
     * Wrapper for IN instruction callback
     */
    bool _wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx = {});

    /**
     * Wrapper for syscall instruction callback
     */
    bool _wrap_syscall_insn_cb(void* emu, const std::vector<void*>& ctx = {});

    /**
     * Wrapper for memory access callback
     */
    bool _wrap_memory_access_cb(void* emu, int access, uint64_t addr, 
                               uint32_t size, uint64_t value, void* ctx);

    /**
     * Wrapper for invalid instruction callback
     */
    bool _wrap_invalid_insn_cb(void* emu, const std::vector<void*>& ctx = {});

    // Getters
    bool is_enabled() const { return enabled; }
    bool is_added() const { return added; }
    int get_handle() const { return handle; }
};

/**
 * This hook type is used when using a specific API (e.g. kernel32.CreateFile)
 */
class ApiHook : public Hook {
private:
    std::string module;
    std::string api_name;
    int argc;
    void* call_conv;

public:
    ApiHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
            std::function<bool()> cb, 
            const std::string& module = "",
            const std::string& api_name = "",
            int argc = 0,
            void* call_conv = nullptr);
};

/**
 * This hook type is used to get a callback when dynamically created/copied code is executed
 * Currently, this will only fire once per dynamic code mapping. Could be useful for unpacking.
 */
class DynCodeHook : public Hook {
public:
    DynCodeHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                std::function<bool()> cb, 
                const std::vector<void*>& ctx = {});
};

/**
 * This hook callback will fire for every CPU instruction
 */
class CodeHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    CodeHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
             std::function<bool()> cb, 
             uint64_t begin = 1, 
             uint64_t end = 0, 
             const std::vector<void*>& ctx = {},
             bool native_hook = true);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time a valid chunk of memory is read from
 */
class ReadMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    ReadMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                std::function<bool()> cb, 
                uint64_t begin = 1, 
                uint64_t end = 0, 
                bool native_hook = true);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time a valid chunk of memory is written to
 */
class WriteMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    WriteMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                 std::function<bool()> cb, 
                 uint64_t begin = 1, 
                 uint64_t end = 0, 
                 bool native_hook = true);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time a chunk of memory is mapped
 */
class MapMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    MapMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
               std::function<bool()> cb, 
               uint64_t begin = 1, 
               uint64_t end = 0);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time an invalid chunk of memory is accessed
 */
class InvalidMemHook : public Hook {
public:
    InvalidMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                   std::function<bool()> cb, 
                   bool native_hook = false);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time a software interrupt is triggered
 */
class InterruptHook : public Hook {
public:
    InterruptHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                  std::function<bool()> cb, 
                  const std::vector<void*>& ctx = {},
                  bool native_hook = true);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire each time an instruction hook is triggered,
 * Only the instructions: IN, OUT, SYSCALL, and SYSENTER are supported by unicorn.
 */
class InstructionHook : public Hook {
private:
    void* insn;

public:
    InstructionHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                    std::function<bool()> cb, 
                    const std::vector<void*>& ctx = {},
                    bool native_hook = true,
                    void* insn = nullptr);

    /**
     * Add the hook
     */
    void add();
};

/**
 * This hook will fire every time an invalid instruction is attempted
 * to be executed
 */
class InvalidInstructionHook : public Hook {
public:
    InvalidInstructionHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                           std::function<bool()> cb, 
                           const std::vector<void*>& ctx = {},
                           bool native_hook = true);

    /**
     * Add the hook
     */
    void add();
};

#endif // COMMON_H