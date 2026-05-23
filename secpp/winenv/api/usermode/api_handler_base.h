// api_handler_base.h — Base class for DLL API handlers (v2)
//
// Maps to: speakeasy/winenv/api/api.py
//
// Uses macro-based registration that mirrors Python's @apihook decorator:
//
//   class Kernel32 : public ApiHandler {
//       API_ENTRY(CreateFileA, 7)     // ← like @apihook('CreateFileA', argc=7)
//       API_ENTRY(VirtualAlloc, 4)
//       ...
//   public:
//       Kernel32() { INIT_API_TABLE(Kernel32); }
//   };

#ifndef SPEAKEASY_API_HANDLER_BASE_H
#define SPEAKEASY_API_HANDLER_BASE_H

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include "../api.h"

namespace speakeasy {
namespace api {

using ApiFunc = std::function<uint64_t(void* emu, const std::string& api_name,
                                        int argc, const std::vector<uint64_t>& argv)>;

struct ApiEntry {
    std::string name;
    int argc;
    ApiFunc handler;
};

/// Base class for all DLL-specific API handlers
class ApiHandler : public ::ApiHandler {
public:
    ApiHandler(void* emu) : ::ApiHandler(emu) {}
    virtual ~ApiHandler() = default;
    virtual std::string get_name() const = 0;
    virtual const std::vector<ApiEntry>& get_apis() const = 0;

    const ApiEntry* find_api(const std::string& name) const {
        for (auto& e : get_apis())
            if (e.name == name) return &e;
        return nullptr;
    }
};

} // namespace api
} // namespace speakeasy

// ── Registration macros ─────────────────────────────────────
//
// Usage in handler class:
//   class Foo : public ApiHandler {
//       API_LIST_BEGIN
//       API_ENTRY(CreateFileA, 7)
//       API_ENTRY(ReadFile, 5)
//       API_ENTRY(CloseHandle, 1)
//       API_LIST_END
//   public:
//       Foo();
//   };

#define API_LIST_BEGIN \
private: \
    std::vector<speakeasy::api::ApiEntry> apis_; \
    static uint64_t _stub(void* e, const std::string&, int, const std::vector<uint64_t>& a) { (void)e; (void)a; return 1; }

/// Declare an API handler method + register it in the table.
/// Each API_ENTRY declares `static uint64_t name(...)` and adds it to the list.
#define API_ENTRY(name, argc) \
    static uint64_t name(void* emu, const std::string&, int, const std::vector<uint64_t>& argv);

#define API_LIST_END

/// Initialize the API table in the constructor.
/// Usage: INIT_API_TABLE(Kernel32)
#define INIT_API_TABLE(klass) \
    apis_ = {

/// Register one API entry. Usage: REG(klass, CreateFileA, 7)
#define REG(klass, name, argc) \
    {#name, argc, klass::name},

/// End the API table initialization.
#define END_API_TABLE \
    };

/// Generate a stub implementation for an API (returns 1, for usermode).
#define STUB(klass, name) \
    uint64_t klass::name(void* e, const std::string&, int, const std::vector<uint64_t>& a) { \
        (void)e; (void)a; return 1; \
    }

/// Generate a stub implementation for a kernel-mode API (returns 0 = STATUS_SUCCESS).
#define KERNEL_STUB(klass, name) \
    uint64_t klass::name(void* e, const std::string&, int, const std::vector<uint64_t>& a) { \
        (void)e; (void)a; return 0; \
    }

#endif // SPEAKEASY_API_HANDLER_BASE_H
