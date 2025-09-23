// common.cpp
#include "common.h"
#include <algorithm>
#include <filesystem>

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path) {
    // Placeholder implementation - would need actual implementation based on requirements
    const std::string root_var = "$ROOT$";
    if (path.find(root_var) != std::string::npos) {
        // In a real implementation, this would get the actual root path
        std::string root = "/path/to/speakeasy"; // Placeholder
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
Hook::Hook(Speakeasy* se_obj, EmuEngine* emu_eng, 
           std::function<bool()> cb, 
           const std::vector<void*>& ctx,
           bool native_hook)
    : cb(cb), handle(0), enabled(false), added(false), 
      native_hook(native_hook), emu_eng(emu_eng), se_obj(se_obj), ctx(ctx) {
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
 * Wrapper for code callback
 */
bool Hook:: _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, const std::vector<void*>& ctx) {
    try {
        if (enabled) {
            // Would need actual implementation for exit_event check
            // if (se_obj->exit_event && se_obj->exit_event->is_set()) {
            //     se_obj->stop();
            //     return false;
            // }
            // return cb(se_obj, addr, size, this->ctx);
            return true; // Placeholder
        }
        return true;
    } catch (...) { // C++ equivalent of except KeyboardInterrupt
        // se_obj->stop(); // Would need actual implementation
        return false;
    }
}

/**
 * Wrapper for interrupt callback
 */
bool Hook::_wrap_intr_cb(void* emu, int num, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(se_obj, num, this->ctx);
        return true; // Placeholder
    }
    return true;
}

/**
 * Wrapper for IN instruction callback
 */
bool Hook::_wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(se_obj, port, size);
        return true; // Placeholder
    }
    return true;
}

/**
 * Wrapper for syscall instruction callback
 */
bool Hook::_wrap_syscall_insn_cb(void* emu, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(se_obj);
        return true; // Placeholder
    }
    return true;
}

/**
 * Wrapper for memory access callback
 */
bool Hook::_wrap_memory_access_cb(void* emu, int access, uint64_t addr, 
                                  uint32_t size, uint64_t value, void* ctx) {
    try {
        if (enabled) {
            // Would need actual implementation for exit_event check
            // if (se_obj->exit_event && se_obj->exit_event->is_set()) {
            //     se_obj->stop();
            //     return false;
            // }
            // return cb(se_obj, access, addr, size, value, ctx);
            return true; // Placeholder
        }
        return true;
    } catch (...) { // C++ equivalent of except KeyboardInterrupt
        // se_obj->stop(); // Would need actual implementation
        return false;
    }
}

/**
 * Wrapper for invalid instruction callback
 */
bool Hook::_wrap_invalid_insn_cb(void* emu, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(se_obj, this->ctx);
        return true; // Placeholder
    }
    return true;
}

/**
 * Constructor for ApiHook
 */
ApiHook::ApiHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                 std::function<bool()> cb, 
                 const std::string& module,
                 const std::string& api_name,
                 int argc,
                 void* call_conv)
    : Hook(se_obj, emu_eng, cb), module(module), api_name(api_name), 
      argc(argc), call_conv(call_conv) {
}

/**
 * Constructor for DynCodeHook
 */
DynCodeHook::DynCodeHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                         std::function<bool()> cb, 
                         const std::vector<void*>& ctx)
    : Hook(se_obj, emu_eng, cb, ctx) {
}

/**
 * Constructor for CodeHook
 */
CodeHook::CodeHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                   std::function<bool()> cb, 
                   uint64_t begin, 
                   uint64_t end, 
                   const std::vector<void*>& ctx,
                   bool native_hook)
    : Hook(se_obj, emu_eng, cb, ctx, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void CodeHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_CODE, _wrap_code_cb, begin, end);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for ReadMemHook
 */
ReadMemHook::ReadMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                         std::function<bool()> cb, 
                         uint64_t begin, 
                         uint64_t end, 
                         bool native_hook)
    : Hook(se_obj, emu_eng, cb, {}, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void ReadMemHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_MEM_READ, _wrap_memory_access_cb, begin, end);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for WriteMemHook
 */
WriteMemHook::WriteMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                           std::function<bool()> cb, 
                           uint64_t begin, 
                           uint64_t end, 
                           bool native_hook)
    : Hook(se_obj, emu_eng, cb, {}, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void WriteMemHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_MEM_WRITE, _wrap_memory_access_cb, begin, end);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for MapMemHook
 */
MapMemHook::MapMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                       std::function<bool()> cb, 
                       uint64_t begin, 
                       uint64_t end)
    : Hook(se_obj, emu_eng, cb), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void MapMemHook::add() {
    added = true;
    enabled = true;
}

/**
 * Constructor for InvalidMemHook
 */
InvalidMemHook::InvalidMemHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                               std::function<bool()> cb, 
                               bool native_hook)
    : Hook(se_obj, emu_eng, cb, {}, native_hook) {
}

/**
 * Add the hook
 */
void InvalidMemHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_MEM_INVALID, _wrap_memory_access_cb);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InterruptHook
 */
InterruptHook::InterruptHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                             std::function<bool()> cb, 
                             const std::vector<void*>& ctx,
                             bool native_hook)
    : Hook(se_obj, emu_eng, cb, ctx, native_hook) {
}

/**
 * Add the hook
 */
void InterruptHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_INTERRUPT, _wrap_intr_cb);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InstructionHook
 */
InstructionHook::InstructionHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                                 std::function<bool()> cb, 
                                 const std::vector<void*>& ctx,
                                 bool native_hook,
                                 void* insn)
    : Hook(se_obj, emu_eng, cb, ctx, native_hook), insn(insn) {
}

/**
 * Add the hook
 */
void InstructionHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_INSN, _wrap_syscall_insn_cb, insn);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InvalidInstructionHook
 */
InvalidInstructionHook::InvalidInstructionHook(Speakeasy* se_obj, EmuEngine* emu_eng, 
                                               std::function<bool()> cb, 
                                               const std::vector<void*>& ctx,
                                               bool native_hook)
    : Hook(se_obj, emu_eng, cb, ctx, native_hook) {
}

/**
 * Add the hook
 */
void InvalidInstructionHook::add() {
    if (!added && native_hook) {
        // handle = emu_eng->hook_add(HOOK_INSN_INVALID, _wrap_invalid_insn_cb);
        // Would need actual implementation
    }
    added = true;
    enabled = true;
}