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
class MemMap;

using ApiCallback = std::function<bool(void* emu, const std::string& api, void* orig, std::vector<uint64_t> argv)>;
using DynCodeCallback = std::function<bool(std::shared_ptr<MemMap> mm)>;
using CodeCallback = std::function<bool(void* emu, uint64_t addr, uint32_t size)>;
using MemAccessCallback = std::function<bool(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value)>;
using MemCallback = std::function<bool(void* emu, int access, uint64_t addr, uint32_t size, int64_t value)>;
using IntrCallback = std::function<bool(void* emu, int num)>;
using InsnCallback = std::function<bool(void* emu)>;
using MapMemCallback = std::function<bool(void* emu, uint64_t addr, uint32_t size, const std::string& tag, int64_t prot, int64_t flags)>;

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path);

/**
 * Base class for all emulator hooks.
 *
 * @param container  opaque context pointer (BinaryEmulator* or Speakeasy*)
 * @param emu_eng    emulation engine object
 */
class Hook {
protected:
    int handle;
    bool enabled;
    bool added;
    bool native_hook;
    std::shared_ptr<EmuEngine> emu_eng;
    void* container;  // opaque context for _wrap_*_cb
    std::vector<void*> ctx;

public:
    Hook(void* container, std::shared_ptr<EmuEngine> emu_eng,
         const std::vector<void*>& ctx = {},
         bool native_hook = false);

    virtual ~Hook() = default;

    void enable();
    void disable();

    //static bool _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, const std::vector<void*>& ctx = {});
    //static bool _wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx = {});
    //static bool _wrap_memory_access_cb(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value, void* ctx);
    //static bool _wrap_mem_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx = {});
    //static bool _wrap_mem_invalid_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx = {});
    //static bool _wrap_insn_cb(void* emu, const std::vector<void*>& ctx = {});

    //virtual bool invoke_code(void* emu, uint64_t addr, uint32_t size) { (void)emu; (void)addr; (void)size; return true; }
    //virtual bool invoke_intr(void* emu, int num) { (void)emu; (void)num; return true; }
    //virtual bool invoke_in_insn(void* emu, uint32_t port, int size) { (void)emu; (void)port; (void)size; return true; }
    //virtual bool invoke_syscall_insn(void* emu) { (void)emu; return true; }
    //virtual bool invoke_memory_access(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value) { (void)emu; (void)access; (void)addr; (void)size; (void)value; return true; }
    //virtual bool invoke_mem(void* emu, int access, uint64_t addr, uint32_t size, int64_t value) { (void)emu; (void)access; (void)addr; (void)size; (void)value; return true; }
    //virtual bool invoke_mem_invalid(void* emu, int access, uint64_t addr, uint32_t size, int64_t value) { (void)emu; (void)access; (void)addr; (void)size; (void)value; return true; }
    //virtual bool invoke_insn(void* emu) { (void)emu; return true; }
    //virtual bool invoke_invalid_insn(void* emu) { (void)emu; return true; }

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
    int call_conv;
    ApiCallback cb;

public:
    ApiHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
            ApiCallback cb,
            const std::string& module = "",
            const std::string& api_name = "",
            int argc = 0,
            int call_conv = 1);

    const std::string& get_module() const { return module; }
    const std::string& get_api_name() const { return api_name; }
    int get_argc() const { return argc; }
    int get_call_conv() const { return call_conv; }
    ApiCallback get_cb() const { return cb; }
};

/** Hook that fires when dynamically created/copied code is executed */
class DynCodeHook : public Hook {
private:
        DynCodeCallback cb;
public:
    DynCodeHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                DynCodeCallback cb,
                const std::vector<void*>& ctx = {});
    bool invoke(std::shared_ptr<MemMap> mm);
};

/** Hook that fires for every CPU instruction in a range */
class CodeHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;
    CodeCallback cb;

public:
    CodeHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
             CodeCallback cb,
             uint64_t begin = 1,
             uint64_t end = 0,
             const std::vector<void*>& ctx = {},
             bool native_hook = true);
    void add();

    static bool _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, void* ctx);

    bool invoke(void* emu, uint64_t addr, uint32_t size);
};

class MemHook : public Hook {
protected:
    uint64_t begin;
    uint64_t end;
    MemAccessCallback cb;
    int access_type;  // e.g. HOOK_MEM_READ, HOOK_MEM_WRITE, HOOK_MEM_INVALID

public:
    MemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
        MemAccessCallback cb,
        uint64_t begin = 1,
        uint64_t end = 0,
        bool native_hook = true);

    static bool _wrap_memory_access_cb(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value, void* ctx);

    virtual void add();
    virtual bool invoke(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value);
};


/** Hook that fires each time a valid chunk of memory is read from */
class ReadMemHook : public MemHook {

public:
    ReadMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                MemAccessCallback cb,
                uint64_t begin = 1,
                uint64_t end = 0,
                bool native_hook = true);
};

/** Hook that fires each time a valid chunk of memory is written to */
class WriteMemHook : public MemHook {

public:
    WriteMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                 MemAccessCallback cb,
                 uint64_t begin = 1,
                 uint64_t end = 0,
                 bool native_hook = true);
};

/** Hook that fires each time a chunk of memory is mapped */
class MapMemHook : public Hook {
private:
    uint64_t begin;
    uint64_t end;
    MapMemCallback cb;

public:
    MapMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
               MapMemCallback cb,
               uint64_t begin = 1,
               uint64_t end = 0);
    void add() override;
    bool invoke(void* emu, uint64_t addr, uint32_t size, const std::string& tag, int64_t prot, int64_t flags);
};

/** Hook that fires each time an invalid chunk of memory is accessed */
class InvalidMemHook : public MemHook {

public:
    InvalidMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                   MemAccessCallback cb,
                   bool native_hook = false);
};

/** Hook that fires each time a software interrupt is triggered */
class InterruptHook : public Hook {
private:
    IntrCallback cb;

public:
    InterruptHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                  IntrCallback cb,
                  const std::vector<void*>& ctx = {},
                  bool native_hook = true);

    static bool _wrap_intr_cb(void* emu, int num, void* ctx);

    void add();
    bool invoke(void* emu, int num);
};

/** Hook for specific CPU instructions (IN, OUT, SYSCALL, SYSENTER) */
class InstructionHook : public Hook {
private:
    void* insn;
    InsnCallback cb;

public:
    InstructionHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                    InsnCallback cb,
                    const std::vector<void*>& ctx = {},
                    bool native_hook = true,
                    void* insn = nullptr);

    static bool _wrap_syscall_insn_cb(void* emu, void* ctx);

    void add();
    bool invoke(void* emu);
};

/** Hook that fires every time an invalid instruction is attempted */
class InvalidInstructionHook : public Hook {
private:
    InsnCallback cb;

public:
    InvalidInstructionHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
                           InsnCallback cb,
                           const std::vector<void*>& ctx = {},
                           bool native_hook = true);

    static bool _wrap_invalid_insn_cb(void* emu, void* ctx);

    void add();
    bool invoke(void* emu);
};

#endif // COMMON_H
