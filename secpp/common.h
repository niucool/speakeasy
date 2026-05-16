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
const int PERM_MEM_RX = PERM_MEM_READ | PERM_MEM_EXEC;
const int PERM_MEM_RWX = PERM_MEM_READ | PERM_MEM_WRITE | PERM_MEM_EXEC;

// Emulation memory access types
const int INVALID_MEM_EXEC = 2000;
const int INVALID_MEM_READ = 2001;
const int INVALID_MEM_WRITE = 2002;
const int INVAL_PERM_MEM_WRITE = 2003;
const int INVAL_PERM_MEM_EXEC = 2004;
const int INVAL_PERM_MEM_READ = 2005;

// Forward declarations
class EmuEngine;

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path);

/**
 * Base class for all emulator hooks.
 *
 * @param container  opaque context pointer (BinaryEmulator* or Speakeasy*)
 * @param emu_eng    emulation engine object
 * @param cb         callback function (returns true to stop further hooks)
 */
class Hook {
protected:
    std::function<bool()> cb;
    int handle;
    bool enabled;
    bool added;
    bool native_hook;
    EmuEngine* emu_eng;
    void* container;  // opaque context for _wrap_*_cb
    std::vector<void*> ctx;

public:
    Hook(void* container, EmuEngine* emu_eng, 
         std::function<bool()> cb, 
         const std::vector<void*>& ctx = {},
         bool native_hook = false);

    virtual ~Hook() = default;

    void enable();
    void disable();

    static bool _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, const std::vector<void*>& ctx = {});
    static bool _wrap_intr_cb(void* emu, int num, const std::vector<void*>& ctx = {});
    static bool _wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx = {});
    static bool _wrap_syscall_insn_cb(void* emu, const std::vector<void*>& ctx = {});
    static bool _wrap_memory_access_cb(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value, void* ctx);
    static bool _wrap_mem_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx = {});
    static bool _wrap_mem_invalid_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx = {});
    static bool _wrap_insn_cb(void* emu, const std::vector<void*>& ctx = {});
    static bool _wrap_invalid_insn_cb(void* emu, const std::vector<void*>& ctx = {});

    bool is_enabled() const { return enabled; }
    bool is_added() const { return added; }
    int get_handle() const { return handle; }
    virtual void add();
};

/** Hook that fires when a specific API is called (e.g. kernel32.CreateFile) */
class ApiHook : public Hook {
private:
    std::string module;
    std::string api_name;
    int argc;
    void* call_conv;

public:
    ApiHook(void* container, EmuEngine* emu_eng, 
            std::function<bool()> cb, 
            const std::string& module = "",
            const std::string& api_name = "",
            int argc = 0,
            void* call_conv = nullptr);
};

/** Hook that fires when dynamically created/copied code is executed */
class DynCodeHook : public Hook {
public:
    DynCodeHook(void* container, EmuEngine* emu_eng, 
                std::function<bool()> cb, 
                const std::vector<void*>& ctx = {});
};

/** Hook that fires for every CPU instruction in a range */
class CodeHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    CodeHook(void* container, EmuEngine* emu_eng, 
             std::function<bool()> cb, 
             uint64_t begin = 1, 
             uint64_t end = 0, 
             const std::vector<void*>& ctx = {},
             bool native_hook = true);
    void add();
};

/** Hook that fires each time a valid chunk of memory is read from */
class ReadMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    ReadMemHook(void* container, EmuEngine* emu_eng, 
                std::function<bool()> cb, 
                uint64_t begin = 1, 
                uint64_t end = 0, 
                bool native_hook = true);
    void add();
};

/** Hook that fires each time a valid chunk of memory is written to */
class WriteMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    WriteMemHook(void* container, EmuEngine* emu_eng, 
                 std::function<bool()> cb, 
                 uint64_t begin = 1, 
                 uint64_t end = 0, 
                 bool native_hook = true);
    void add();
};

/** Hook that fires each time a chunk of memory is mapped */
class MapMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;

public:
    MapMemHook(void* container, EmuEngine* emu_eng, 
               std::function<bool()> cb, 
               uint64_t begin = 1, 
               uint64_t end = 0);
    void add();
};

/** Hook that fires each time an invalid chunk of memory is accessed */
class InvalidMemHook : public Hook {
public:
    InvalidMemHook(void* container, EmuEngine* emu_eng, 
                   std::function<bool()> cb, 
                   bool native_hook = false);
    void add();
};

/** Hook that fires each time a software interrupt is triggered */
class InterruptHook : public Hook {
public:
    InterruptHook(void* container, EmuEngine* emu_eng, 
                  std::function<bool()> cb, 
                  const std::vector<void*>& ctx = {},
                  bool native_hook = true);
    void add();
};

/** Hook for specific CPU instructions (IN, OUT, SYSCALL, SYSENTER) */
class InstructionHook : public Hook {
private:
    void* insn;

public:
    InstructionHook(void* container, EmuEngine* emu_eng, 
                    std::function<bool()> cb, 
                    const std::vector<void*>& ctx = {},
                    bool native_hook = true,
                    void* insn = nullptr);
    void add();
};

/** Hook that fires every time an invalid instruction is attempted */
class InvalidInstructionHook : public Hook {
public:
    InvalidInstructionHook(void* container, EmuEngine* emu_eng, 
                           std::function<bool()> cb, 
                           const std::vector<void*>& ctx = {},
                           bool native_hook = true);
    void add();
};

#endif // COMMON_H
