// psapi.cpp  psapi.dll handler (real implementations)
#include "psapi.h"
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include "windows/winemu.h"
#include "windows/objman.h"
#include "windows/common.h"

using namespace speakeasy;

namespace speakeasy { namespace api {

static inline int ptr_sz(void* e) { return (be(e)->get_arch() == speakeasy::arch::ARCH_AMD64) ? 8 : 4; }

Psapi::Psapi(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Psapi)
    REG(Psapi, EnumProcesses, 3)        REG(Psapi, EnumProcessModules, 4)
    REG(Psapi, GetModuleBaseName, 4)    REG(Psapi, GetModuleBaseNameA, 4)
    REG(Psapi, GetModuleBaseNameW, 4)   REG(Psapi, GetModuleFileNameEx, 4)
    REG(Psapi, GetModuleFileNameExA, 4) REG(Psapi, GetModuleFileNameExW, 4)
    END_API_TABLE
}

// Helper: get module bases for a process
static std::vector<uint64_t> get_process_module_bases(void* e, std::shared_ptr<Process> proc) {
    std::vector<uint64_t> bases;
    if (!proc) return bases;

    auto module = proc->pe;
    if (module) {
        bases.push_back(module->base);
        return bases;
    } 

    std::string p = proc->path;
    if (!p.empty()) {
        size_t slash = p.rfind('\\');
        std::string mod_name;
        if (slash != std::string::npos) mod_name = p.substr(slash + 1);
        else mod_name = p;
        size_t dot = mod_name.rfind('.');
        if (dot != std::string::npos) mod_name = mod_name.substr(0, dot);
        auto mod = we(e)->get_mod_by_name(mod_name);
        if (mod) {
            bases.push_back(mod->base);
            return bases;
        }
    }

    uint64_t process_base = proc->base;
    if (process_base) {
        bases.push_back(process_base);
    }

    return bases;
}

// Helper: get module base name
static std::string get_module_base_name(void* e, std::shared_ptr<Process> proc, uint64_t hModule) {
    if (hModule) {
        auto mod = we(e)->get_mod_from_addr(hModule);
        if (mod) {
            std::string ep = mod->emu_path;
            size_t slash = ep.rfind('\\');
            if (slash != std::string::npos) return ep.substr(slash + 1);
            return ep;
        }
    }
    std::string p = proc->path;
    size_t slash = p.rfind('\\');
    if (slash != std::string::npos) return p.substr(slash + 1);
    return p;
}

// Helper: get module file name (full path)
static std::string get_module_file_name(void* e, std::shared_ptr<Process> proc, uint64_t hModule) {
    if (hModule) {
        auto mod = we(e)->get_mod_from_addr(hModule);
        if (mod) return mod->emu_path;
    }
    return proc->path;
}

// 
//  EnumProcesses  enumerate running processes
// 
uint64_t Psapi::EnumProcesses(void* e, ArgList& a, void* ctx) {
    uint64_t lpidProcess = a[0];
    uint64_t cb = a[1];
    uint64_t lpcbNeeded = a[2];

    auto& processes = we(e)->get_processes();
    uint32_t count = static_cast<uint32_t>(processes.size());

    // Write needed size
    if (lpcbNeeded) {
        uint32_t needed = count * 4;
        std::vector<uint8_t> nb(4, 0);
        speakeasy::write_le(nb, 0, static_cast<uint64_t>(needed), 4);
        we(e)->mem_write(lpcbNeeded, nb);
    }

    if (!lpidProcess || cb < 4) return 1;

    uint32_t max_write = static_cast<uint32_t>(std::min(cb / 4, static_cast<uint64_t>(count)));
    uint64_t cursor = lpidProcess;
    for (uint32_t i = 0; i < max_write; i++) {
        auto proc = processes[i];
        uint32_t pid = proc ? static_cast<uint32_t>(proc->get_pid()) : 0;
        std::vector<uint8_t> pid_buf(4, 0);
        speakeasy::write_le(pid_buf, 0, static_cast<uint64_t>(pid), 4);
        we(e)->mem_write(cursor, pid_buf);
        cursor += 4;
    }

    return 1;
}

// 
//  EnumProcessModules  enumerate modules in a process
// 
uint64_t Psapi::EnumProcessModules(void* e, ArgList& a, void* ctx) {
    uint64_t hProcess = a[0];
    uint64_t lphModule = a[1];
    uint64_t cb = a[2];
    uint64_t lpcbNeeded = a[3];

    auto proc = std::dynamic_pointer_cast<Process>(we(e)->get_object_from_handle(hProcess));
    if (!proc) return 0;

    auto bases = get_process_module_bases(e, proc);
    int ps = ptr_sz(e);

    // Write needed size
    if (lpcbNeeded) {
        uint32_t needed = static_cast<uint32_t>(bases.size() * ps);
        std::vector<uint8_t> nb(4, 0);
        speakeasy::write_le(nb, 0, static_cast<uint64_t>(needed), 4);
        we(e)->mem_write(lpcbNeeded, nb);
    }

    if (!lphModule || cb < static_cast<uint64_t>(ps)) return 1;

    uint32_t max_write = static_cast<uint32_t>(std::min(cb / ps, static_cast<uint64_t>(bases.size())));
    uint64_t cursor = lphModule;
    for (uint32_t i = 0; i < max_write; i++) {
        std::vector<uint8_t> mb(ps, 0);
        speakeasy::write_le(mb, 0, bases[i], ps);
        we(e)->mem_write(cursor, mb);
        cursor += ps;
    }

    return 1;
}

// 
//  GetModuleBaseName / GetModuleBaseNameA / GetModuleBaseNameW
// 
uint64_t Psapi::GetModuleBaseName(void* e, ArgList& a, void* ctx) {
    uint64_t hProcess = a[0];
    uint64_t hModule = a[1];
    uint64_t lpBaseName = a[2];
    uint64_t nSize = a[3];

    if (!lpBaseName || nSize == 0) return 0;

    auto proc = std::dynamic_pointer_cast<Process>(we(e)->get_object_from_handle(hProcess));
    if (!proc) return 0;

    std::string name = get_module_base_name(e, proc, hModule);
    if (name.empty()) return 0;

    if (name.size() >= nSize) name = name.substr(0, nSize - 1);

    be(e)->write_mem_string(name, lpBaseName, 1);
    return static_cast<uint64_t>(name.size());
}

uint64_t Psapi::GetModuleBaseNameA(void* e, ArgList& a, void* ctx) {
    return GetModuleBaseName(e, a, ctx);
}

uint64_t Psapi::GetModuleBaseNameW(void* e, ArgList& a, void* ctx) {
    uint64_t hProcess = a[0];
    uint64_t hModule = a[1];
    uint64_t lpBaseName = a[2];
    uint64_t nSize = a[3];

    if (!lpBaseName || nSize == 0) return 0;

    auto proc = std::dynamic_pointer_cast<Process>(we(e)->get_object_from_handle(hProcess));
    if (!proc) return 0;

    std::string name = get_module_base_name(e, proc, hModule);
    if (name.empty()) return 0;

    if (name.size() >= nSize) name = name.substr(0, nSize - 1);

    be(e)->write_mem_string(name, lpBaseName, 2);
    return static_cast<uint64_t>(name.size());
}

// 
//  GetModuleFileNameEx / GetModuleFileNameExA / GetModuleFileNameExW
// 
uint64_t Psapi::GetModuleFileNameEx(void* e, ArgList& a, void* ctx) {
    uint64_t hProcess = a[0];
    uint64_t hModule = a[1];
    uint64_t lpFilename = a[2];
    uint64_t nSize = a[3];

    if (!lpFilename || nSize == 0) return 0;

    auto proc = std::dynamic_pointer_cast<Process>(we(e)->get_object_from_handle(hProcess));
    if (!proc) return 0;

    std::string name = get_module_file_name(e, proc, hModule);
    if (name.empty()) return 0;

    if (name.size() >= nSize) name = name.substr(0, nSize - 1);

    be(e)->write_mem_string(name, lpFilename, 1);
    return static_cast<uint64_t>(name.size());
}

uint64_t Psapi::GetModuleFileNameExA(void* e, ArgList& a, void* ctx) {
    return GetModuleFileNameEx(e, a, ctx);
}

uint64_t Psapi::GetModuleFileNameExW(void* e, ArgList& a, void* ctx) {
    uint64_t hProcess = a[0];
    uint64_t hModule = a[1];
    uint64_t lpFilename = a[2];
    uint64_t nSize = a[3];

    if (!lpFilename || nSize == 0) return 0;

    auto proc = std::dynamic_pointer_cast<Process>(we(e)->get_object_from_handle(hProcess));
    if (!proc) return 0;

    std::string name = get_module_file_name(e, proc, hModule);
    if (name.empty()) return 0;

    if (name.size() >= nSize) name = name.substr(0, nSize - 1);

    be(e)->write_mem_string(name, lpFilename, 2);
    return static_cast<uint64_t>(name.size());
}

}} // namespaces
