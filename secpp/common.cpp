// common.cpp
#include "common.h"
#include "engines/unicorn_eng.h"
#include <algorithm>
#include <filesystem>

#include "memmgr.h"

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path) {
    const std::string root_var = "$ROOT$";
    if (path.find(root_var) != std::string::npos) {
        std::string root = "speakeasy";
        if (!std::filesystem::exists(root)) {
            root = ".";
        }
        std::string result = path;
        size_t pos = result.find(root_var);
        if (pos != std::string::npos) {
            result.replace(pos, root_var.length(), root);
        }
        return result;
    }
    return path;
}

/**
 * Constructor for Hook
 */
Hook::Hook(void* container, std::shared_ptr<EmuEngine> emu_eng,
           void* ctx,
           bool native_hook)
    : handle(0), enabled(false), added(false),
      native_hook(native_hook), emu_eng(emu_eng), container(container), ctx(ctx) {
}

void Hook::add() {
    added = true;
    enabled = true;
}

/**
 * Enable the hook
 */
void Hook::enable() {
    enabled = true;
    // emu_eng->hook_enable(handle); // Would need actual implementation
}

/**
 * Disable the hook
 */
void Hook::disable() {
    enabled = false;
    // emu_eng->hook_disable(handle); // Would need actual implementation
}

/**
 * Wrapper for IN/INSB/OUT/OUTSB instruction callback
 */
//bool Hook::_wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx) {
//    if (ctx.empty()) return true;
//    auto* hook = static_cast<Hook*>(ctx[0]);
//    if (hook) return hook->invoke_in_insn(emu, port, size);
//    return true;
//}

///**
// * Wrapper for memory callback
// */
//bool Hook::_wrap_mem_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx) {
//    if (ctx.empty()) return true;
//    auto* hook = static_cast<Hook*>(ctx[0]);
//    if (hook) return hook->invoke_mem(emu, access, addr, size, value);
//    return true;
//}
//
///**
// * Wrapper for invalid memory callback
// */
//bool Hook::_wrap_mem_invalid_cb(void* emu, int access, uint64_t addr, uint32_t size, int64_t value, const std::vector<void*>& ctx) {
//    if (ctx.empty()) return true;
//    auto* hook = static_cast<Hook*>(ctx[0]);
//    if (hook) return hook->invoke_mem_invalid(emu, access, addr, size, value);
//    return true;
//}
//
///**
// * Wrapper for instruction callback
// */
//bool Hook::_wrap_insn_cb(void* emu, const std::vector<void*>& ctx) {
//    if (ctx.empty()) return true;
//    auto* hook = static_cast<Hook*>(ctx[0]);
//    if (hook) return hook->invoke_insn(emu);
//    return true;
//}

/**
 * Constructor for ApiHook
 */
ApiHook::ApiHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                 ApiCallback cb, 
                 const std::string& module,
                 const std::string& api_name,
                 int argc,
                 int call_convl)
    : Hook(container, emu_eng), module(module), api_name(api_name), 
      argc(argc), call_conv(call_convl), cb(cb) {
}

/**
 * Constructor for DynCodeHook
 */
DynCodeHook::DynCodeHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                         DynCodeCallback cbl, 
                         void* ctx)
    : Hook(container, emu_eng, ctx), cb(cbl) {
}

bool DynCodeHook::invoke(std::shared_ptr<MemMap> mm) {
    if (cb) {
        return cb(mm);
    }
    return true;
}

/**
 * Constructor for CodeHook
 */
CodeHook::CodeHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                   CodeCallback cbl, 
                   uint64_t beginl, 
                   uint64_t endl, 
                   void* ctx,
                   bool native_hook)
    : Hook(container, emu_eng, ctx, native_hook), begin(beginl), end(endl), cb(cbl) {
}

/**
 * Wrapper for code callback
 */
bool CodeHook::_wrap_code_cb(void* emu, uint64_t addr, uint32_t size, void* ctx) {
    if (!ctx) return true;
    auto* hook = static_cast<CodeHook*>(ctx);
    if (hook && hook->is_enabled()) return hook->invoke(emu, addr, size);
    return true;
}


/**
 * Add the hook
 */
void CodeHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(
            nullptr, reinterpret_cast<void*>(&CodeHook::_wrap_code_cb), HOOK_CODE, this, begin, end));
    }
    added = true;
    enabled = true;
}

bool CodeHook::invoke(void* emu, uint64_t addr, uint32_t size) {
    if (cb) {
        return cb(emu, addr, size, ctx);
    }
    return true;
}

/**
 * Constructor for MemHook
 */
MemHook::MemHook(void* container, std::shared_ptr<EmuEngine> emu_eng,
    MemAccessCallback cbl,
    uint64_t beginl,
    uint64_t endl,
    void* ctx,
    bool native_hookl)
    : Hook(container, emu_eng, ctx, native_hookl), begin(beginl), end(endl), cb(cbl) {
}

/**
 * Wrapper for memory access callback (read/write/invalid)
 */
bool MemHook::_wrap_memory_access_cb(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value, void* ctx) {
    if (!ctx) return true;
    auto* hook = static_cast<MemHook*>(ctx);
    if (hook) return hook->invoke(emu, access, addr, size, value);
    return true;
}

/**
 * Add the hook
 */
void MemHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(
            nullptr, reinterpret_cast<void*>(&MemHook::_wrap_memory_access_cb), access_type, this, begin, end));
    }
    added = true;
    enabled = true;
}

bool MemHook::invoke(void* emu, int access, uint64_t addr, uint32_t size, uint64_t value) {
    if (cb) {
        return cb(emu, access, addr, size, value, ctx);
    }
    return true;
}

/**
 * Constructor for ReadMemHook
 */
ReadMemHook::ReadMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                         MemAccessCallback cb, 
                         uint64_t begin, 
                         uint64_t end, 
                         void* ctx,
                         bool native_hook)
    : MemHook(container, emu_eng, cb, begin, end, ctx, native_hook) {
    access_type = HOOK_MEM_READ;
}

/**
 * Constructor for WriteMemHook
 */
WriteMemHook::WriteMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                           MemAccessCallback cb, 
                           uint64_t begin, 
                           uint64_t end, 
                           void* ctx,
                           bool native_hook)
    : MemHook(container, emu_eng, cb, begin, end, ctx, native_hook) {
    access_type = HOOK_MEM_WRITE;
}

/**
 * Constructor for MapMemHook
 */
MapMemHook::MapMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                       MapMemCallback cbl, 
                       uint64_t beginl, 
                       uint64_t endl, void* ctx)
    : Hook(container, emu_eng, ctx), begin(beginl), end(endl), cb(cbl) {
}

/**
 * Add the hook
 */
void MapMemHook::add() {
    added = true;
    enabled = true;
}

bool MapMemHook::invoke(void* emu, uint64_t addr, uint32_t size, const std::string& tag, int64_t prot, int64_t flags) {
   if (cb) {
        return cb(emu, addr, size, tag, prot, flags);
   }
   return true;
}

/**
 * Constructor for InvalidMemHook
 */
InvalidMemHook::InvalidMemHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                               MemAccessCallback cb, void* ctx,
                               bool native_hook)
    : MemHook(container, emu_eng, cb, 1, 0, ctx, native_hook) {
    access_type = HOOK_MEM_INVALID;
}

/**
 * Constructor for InterruptHook
 */
InterruptHook::InterruptHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                             IntrCallback cb, 
                             void* ctx,
                             bool native_hook)
    : Hook(container, emu_eng, ctx, native_hook), cb(cb) {
}

/**
 * Wrapper for interrupt callback
 */
bool InterruptHook::_wrap_intr_cb(void* emu, int num, void* ctx) {
    if (!ctx) return true;
    auto* hook = static_cast<InterruptHook*>(ctx);
    if (hook) return hook->invoke(emu, num);
    return true;
}


bool InterruptHook::invoke(void* emu, int num) {
    if (cb) {
        return cb(emu, num, ctx);
    }
    return true;
}

/**
 * Add the hook
 */
void InterruptHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(
            nullptr, reinterpret_cast<void*>(&InterruptHook::_wrap_intr_cb), HOOK_INTERRUPT, this));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InstructionHook
 */
InstructionHook::InstructionHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                                 InsnCallback cb, 
                                 void* ctx,
                                 bool native_hook,
                                 void* insn)
    : Hook(container, emu_eng, ctx, native_hook), insn(insn), cb(cb) {
}

/**
 * Wrapper for syscall/sysenter instruction callback
 */
bool InstructionHook::_wrap_syscall_insn_cb(void* emu, void* ctx) {
    if (!ctx) return true;
    auto* hook = static_cast<InstructionHook*>(ctx);
    if (hook) return hook->invoke(emu);
    return true;
}


/**
 * Add the hook
 */
void InstructionHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(
            nullptr, reinterpret_cast<void*>(&InstructionHook::_wrap_syscall_insn_cb), 
            HOOK_INSN, this, 1, 0, reinterpret_cast<uintptr_t>(insn)));
    }
    added = true;
    enabled = true;
}

bool InstructionHook::invoke(void* emu) {
    if (cb) {
        return cb(emu);
    }
    return true;
}

/**
 * Constructor for InvalidInstructionHook
 */
InvalidInstructionHook::InvalidInstructionHook(void* container, std::shared_ptr<EmuEngine> emu_eng, 
                                               InsnCallback cb, 
                                               void* ctx,
                                               bool native_hook)
    : Hook(container, emu_eng, ctx, native_hook), cb(cb) {
}

bool InvalidInstructionHook::invoke(void* emu) {
    if (cb) {
        return cb(emu);
    }
    return true;
}

/**
 * Wrapper for invalid instruction callback
 */
bool InvalidInstructionHook::_wrap_invalid_insn_cb(void* emu, void* ctx) {
    if (!ctx) return true;
    auto* hook = static_cast<InvalidInstructionHook*>(ctx);
    if (hook) return hook->invoke(emu);
    return true;
}

/**
 * Add the hook
 */
void InvalidInstructionHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(
            nullptr, reinterpret_cast<void*>(&InvalidInstructionHook::_wrap_invalid_insn_cb), 
            HOOK_INSN_INVALID, this));
    }
    added = true;
    enabled = true;
}