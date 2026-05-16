// common.cpp
#include "common.h"
#include "engines/unicorn_eng.h"
#include <algorithm>
#include <filesystem>

/**
 * Get the supplied path in relation to the package root
 */
std::string normalize_package_path(const std::string& path) {    const std::string root_var = "$ROOT$";
    if (path.find(root_var) != std::string::npos) {
        // In a real implementation, this would get the actual root path
        std::string root = "/path/to/speakeasy";        std::string result = path;
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
Hook::Hook(void* container, EmuEngine* emu_eng, 
           std::function<bool()> cb, 
           const std::vector<void*>& ctx,
           bool native_hook)
    : cb(cb), handle(0), enabled(false), added(false), 
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
 * Wrapper for code callback
 */
bool Hook:: _wrap_code_cb(void* emu, uint64_t addr, uint32_t size, const std::vector<void*>& ctx) {
    try {
        if (enabled) {
            // if (container->exit_event && container->exit_event->is_set()) {
            //     container->stop();
            //     return false;
            // }
            // return cb(container, addr, size, this->ctx);
            return true;        }
        return true;
    } catch (...) { // C++ equivalent of except KeyboardInterrupt
        return false;
    }
}

/**
 * Wrapper for interrupt callback
 */
bool Hook::_wrap_intr_cb(void* emu, int num, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(container, num, this->ctx);
        return true;    }
    return true;
}

/**
 * Wrapper for IN instruction callback
 */
bool Hook::_wrap_in_insn_cb(void* emu, uint32_t port, int size, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(container, port, size);
        return true;    }
    return true;
}

/**
 * Wrapper for syscall instruction callback
 */
bool Hook::_wrap_syscall_insn_cb(void* emu, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(container);
        return true;    }
    return true;
}

/**
 * Wrapper for memory access callback
 */
bool Hook::_wrap_memory_access_cb(void* emu, int access, uint64_t addr, 
                                  uint32_t size, uint64_t value, void* ctx) {
    try {
        if (enabled) {
            // if (container->exit_event && container->exit_event->is_set()) {
            //     container->stop();
            //     return false;
            // }
            // return cb(container, access, addr, size, value, ctx);
            return true;        }
        return true;
    } catch (...) { // C++ equivalent of except KeyboardInterrupt
        return false;
    }
}

/**
 * Wrapper for invalid instruction callback
 */
bool Hook::_wrap_invalid_insn_cb(void* emu, const std::vector<void*>& ctx) {
    if (enabled) {
        // return cb(container, this->ctx);
        return true;    }
    return true;
}

/**
 * Constructor for ApiHook
 */
ApiHook::ApiHook(void* container, EmuEngine* emu_eng, 
                 std::function<bool()> cb, 
                 const std::string& module,
                 const std::string& api_name,
                 int argc,
                 void* call_conv)
    : Hook(container, emu_eng, cb), module(module), api_name(api_name), 
      argc(argc), call_conv(call_conv) {
}

/**
 * Constructor for DynCodeHook
 */
DynCodeHook::DynCodeHook(void* container, EmuEngine* emu_eng, 
                         std::function<bool()> cb, 
                         const std::vector<void*>& ctx)
    : Hook(container, emu_eng, cb, ctx) {
}

/**
 * Constructor for CodeHook
 */
CodeHook::CodeHook(void* container, EmuEngine* emu_eng, 
                   std::function<bool()> cb, 
                   uint64_t begin, 
                   uint64_t end, 
                   const std::vector<void*>& ctx,
                   bool native_hook)
    : Hook(container, emu_eng, cb, ctx, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void CodeHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_code_cb), HOOK_CODE, container, begin, end));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for ReadMemHook
 */
ReadMemHook::ReadMemHook(void* container, EmuEngine* emu_eng, 
                         std::function<bool()> cb, 
                         uint64_t begin, 
                         uint64_t end, 
                         bool native_hook)
    : Hook(container, emu_eng, cb, {}, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void ReadMemHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_memory_access_cb), HOOK_MEM_READ, container, begin, end));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for WriteMemHook
 */
WriteMemHook::WriteMemHook(void* container, EmuEngine* emu_eng, 
                           std::function<bool()> cb, 
                           uint64_t begin, 
                           uint64_t end, 
                           bool native_hook)
    : Hook(container, emu_eng, cb, {}, native_hook), begin(begin), end(end) {
}

/**
 * Add the hook
 */
void WriteMemHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_memory_access_cb), HOOK_MEM_WRITE, container, begin, end));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for MapMemHook
 */
MapMemHook::MapMemHook(void* container, EmuEngine* emu_eng, 
                       std::function<bool()> cb, 
                       uint64_t begin, 
                       uint64_t end)
    : Hook(container, emu_eng, cb), begin(begin), end(end) {
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
InvalidMemHook::InvalidMemHook(void* container, EmuEngine* emu_eng, 
                               std::function<bool()> cb, 
                               bool native_hook)
    : Hook(container, emu_eng, cb, {}, native_hook) {
}

/**
 * Add the hook
 */
void InvalidMemHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_memory_access_cb), HOOK_MEM_INVALID, container));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InterruptHook
 */
InterruptHook::InterruptHook(void* container, EmuEngine* emu_eng, 
                             std::function<bool()> cb, 
                             const std::vector<void*>& ctx,
                             bool native_hook)
    : Hook(container, emu_eng, cb, ctx, native_hook) {
}

/**
 * Add the hook
 */
void InterruptHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_intr_cb), HOOK_INTERRUPT, container));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InstructionHook
 */
InstructionHook::InstructionHook(void* container, EmuEngine* emu_eng, 
                                 std::function<bool()> cb, 
                                 const std::vector<void*>& ctx,
                                 bool native_hook,
                                 void* insn)
    : Hook(container, emu_eng, cb, ctx, native_hook), insn(insn) {
}

/**
 * Add the hook
 */
void InstructionHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_syscall_insn_cb), HOOK_INSN, container, 1, 0, reinterpret_cast<uintptr_t>(insn)));
    }
    added = true;
    enabled = true;
}

/**
 * Constructor for InvalidInstructionHook
 */
InvalidInstructionHook::InvalidInstructionHook(void* container, EmuEngine* emu_eng, 
                                               std::function<bool()> cb, 
                                               const std::vector<void*>& ctx,
                                               bool native_hook)
    : Hook(container, emu_eng, cb, ctx, native_hook) {
}

/**
 * Add the hook
 */
void InvalidInstructionHook::add() {
    if (!added && native_hook) {
        handle = static_cast<int>(emu_eng->hook_add(nullptr, reinterpret_cast<void*>(&Hook::_wrap_invalid_insn_cb), HOOK_INSN_INVALID, container));
    }
    added = true;
    enabled = true;
}