// ntdll.cpp  ntdll.dll API handler implementation
//
// Maps to: speakeasy/winenv/api/usermode/ntdll.py
//
// Implements exported native functions from ntdll.dll. If a function is not supported
// here, but is supported in the ntoskrnl handler (e.g. NtCreateFile) it will be handled by
// the kernel export handler.
//
// Registered APIs (21 + stub_api, matching Python ntdll.py)

#include "ntdll.h"
#include "../../../helper.h"

#include <cstring>
#include <algorithm>

#include "memmgr.h"           // MemoryManager
#include "windows/winemu.h"   // WindowsEmulator, BinaryEmulator
#include "windows/win32.h"    // Win32Emulator
#include "struct.h"           // speakeasy::write_le, speakeasy::read_le
#include "winenv/arch.h"      // ARCH_X86, ARCH_AMD64

// NTSTATUS constants
static constexpr uint32_t NT_SUCCESS          = 0x00000000;
static constexpr uint32_t NT_UNSUCCESSFUL     = 0xC0000001;
static constexpr uint32_t NT_INVALID_HANDLE   = 0xC0000008;
static constexpr uint32_t NT_INVALID_PARAM    = 0xC000000D;
static constexpr uint32_t NT_OBJECT_NAME_NOT_FOUND = 0xC0000034;

// Aliases matching Python ntdll.py naming
#define STATUS_SUCCESS               NT_SUCCESS
#define STATUS_UNSUCCESSFUL          NT_UNSUCCESSFUL
#define STATUS_INVALID_HANDLE        NT_INVALID_HANDLE
#define STATUS_INVALID_PARAMETER     NT_INVALID_PARAM
#define STATUS_OBJECT_NAME_NOT_FOUND NT_OBJECT_NAME_NOT_FOUND
#define STATUS_DLL_NOT_FOUND         static_cast<uint32_t>(0xC0000135)
#define STATUS_PROCEDURE_NOT_FOUND   static_cast<uint32_t>(0xC000007A)
#define STATUS_RESOURCE_DATA_NOT_FOUND static_cast<uint32_t>(0xC0000084)

// Windows SDK defines these as macros; undefine for C++ method names
#ifdef RtlZeroMemory
#undef RtlZeroMemory
#endif
#ifdef RtlMoveMemory
#undef RtlMoveMemory
#endif

namespace speakeasy {
namespace api {

//
// Helper functions
//

static inline int get_ptr_size(void* emu) {
    auto* mm = static_cast<MemoryManager*>(emu);
    auto* bemu = static_cast<BinaryEmulator*>(mm);
    int arch = bemu->get_arch();
    return (arch == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
}

static inline uint16_t read_u16(void* emu, uint64_t addr) {
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, 2);
    return (raw.size() >= 2) ? static_cast<uint16_t>(read_le(raw, 0, 2)) : 0;
}

static inline uint32_t read_u32(void* emu, uint64_t addr) {
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, 4);
    return (raw.size() >= 4) ? static_cast<uint32_t>(read_le(raw, 0, 4)) : 0;
}

static inline uint64_t read_ptr(void* emu, uint64_t addr) {
    int psz = get_ptr_size(emu);
    auto raw = static_cast<MemoryManager*>(emu)->mem_read(addr, psz);
    return (raw.size() >= static_cast<size_t>(psz)) ? read_le(raw, 0, psz) : 0;
}

static inline void write_u16(void* emu, uint64_t addr, uint16_t val) {
    std::vector<uint8_t> buf(2, 0);
    write_le(buf, 0, val, 2);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

static inline void write_u32(void* emu, uint64_t addr, uint32_t val) {
    std::vector<uint8_t> buf(4, 0);
    write_le(buf, 0, val, 4);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

static inline void write_ptr(void* emu, uint64_t addr, uint64_t val) {
    int psz = get_ptr_size(emu);
    std::vector<uint8_t> buf(psz, 0);
    write_le(buf, 0, val, psz);
    static_cast<MemoryManager*>(emu)->mem_write(addr, buf);
}

/// Read a UNICODE_STRING structure from emulated memory and return as narrow string
static inline std::string read_unicode_string_content(void* emu, uint64_t us_addr) {
    if (us_addr == 0) return "";
    int psz = get_ptr_size(emu); (void)psz;
    auto raw_len = static_cast<MemoryManager*>(emu)->mem_read(us_addr, 2);
    if (raw_len.size() < 2) return "";
    uint16_t length = static_cast<uint16_t>(read_le(raw_len, 0, 2));
    uint64_t buffer_addr = read_ptr(emu, us_addr + 4);
    if (buffer_addr == 0) return "";
    auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
    return bemu->read_mem_string(buffer_addr, 2, length / 2);
}

/// Read an ANSI_STRING structure
static inline std::string read_ansi_string_content(void* emu, uint64_t as_addr) {
    if (as_addr == 0) return "";
    auto raw_len = static_cast<MemoryManager*>(emu)->mem_read(as_addr, 2);
    if (raw_len.size() < 2) return "";
    uint16_t length = static_cast<uint16_t>(read_le(raw_len, 0, 2));
    uint64_t buffer_addr = read_ptr(emu, as_addr + 4);
    if (buffer_addr == 0) return "";
    auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
    return bemu->read_mem_string(buffer_addr, 1, length);
}

//
// Constructor — register 21 APIs matching Python ntdll.py exactly
//

Ntdll::Ntdll(void* emu) : ApiHandler(emu) {
    INIT_API_TABLE(Ntdll)
    REG(Ntdll, RtlGetLastWin32Error, 0)           REG(Ntdll, RtlNtStatusToDosError, 1)
    REG(Ntdll, RtlFlushSecureMemoryCache, 2)       REG(Ntdll, RtlAddVectoredExceptionHandler, 2)
    REG(Ntdll, NtYieldExecution, 0)                REG(Ntdll, RtlRemoveVectoredExceptionHandler, 1)
    REG(Ntdll, LdrLoadDll, 4)                      REG(Ntdll, LdrGetProcedureAddress, 4)
    REG(Ntdll, RtlZeroMemory, 2)                   REG(Ntdll, RtlMoveMemory, 3)
    REG(Ntdll, NtSetInformationProcess, 4)         REG(Ntdll, RtlEncodePointer, 1)
    REG(Ntdll, RtlDecodePointer, 1)                REG(Ntdll, NtWaitForSingleObject, 3)
    REG(Ntdll, RtlComputeCrc32, 3)                 REG(Ntdll, LdrFindResource_U, 4)
    REG(Ntdll, NtUnmapViewOfSection, 2)            REG(Ntdll, LdrAccessResource, 4)
    REG(Ntdll, RtlGetNtVersionNumbers, 3)          REG(Ntdll, RtlGetCurrentPeb, 0)
    REG(Ntdll, RtlGetVersion, 1)
    END_API_TABLE
}

//
// API Implementations (order matches Python ntdll.py)
//

uint64_t Ntdll::RtlGetLastWin32Error(void* emu, ArgList& argv, void* ctx) {
    // DWORD RtlGetLastWin32Error();
    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    return static_cast<uint64_t>(wemu->get_last_error());
}

uint64_t Ntdll::RtlNtStatusToDosError(void* emu, ArgList& argv, void* ctx) {
    // ULONG RtlNtStatusToDosError(NTSTATUS Status);
    (void)emu;
    uint32_t status = static_cast<uint32_t>(argv[0]);
    switch (status) {
        case NT_SUCCESS:              return 0;      // ERROR_SUCCESS
        case NT_INVALID_HANDLE:        return 6;     // ERROR_INVALID_HANDLE
        case NT_INVALID_PARAM:           return 87;    // ERROR_INVALID_PARAMETER
        case 0xC0000005:                return 998;   // ERROR_NOACCESS
        case 0xC0000023:                return 122;   // ERROR_INSUFFICIENT_BUFFER
        case NT_OBJECT_NAME_NOT_FOUND:   return 2;     // ERROR_FILE_NOT_FOUND
        case STATUS_PROCEDURE_NOT_FOUND: return 127;   // ERROR_PROC_NOT_FOUND
        case 0xC00000BB:               return 50;    // ERROR_NOT_SUPPORTED
        default:                           return 0;
    }
}

uint64_t Ntdll::RtlFlushSecureMemoryCache(void* emu, ArgList& argv, void* ctx) {
    // DWORD RtlFlushSecureMemoryCache(PVOID arg0, PVOID arg1);
    (void)emu; (void)argv;
    return 1; // TRUE
}

uint64_t Ntdll::RtlAddVectoredExceptionHandler(void* emu, ArgList& argv, void* ctx) {
    // PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
    uint32_t first = static_cast<uint32_t>(argv[0]);
    uint64_t handler = argv[1];

    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    wemu->add_vectored_exception_handler(first != 0, handler);
    return handler;
}

uint64_t Ntdll::NtYieldExecution(void* emu, ArgList& argv, void* ctx) {
    // NtYieldExecution();
    (void)emu; (void)argv;
    return 0; // STATUS_SUCCESS
}

uint64_t Ntdll::RtlRemoveVectoredExceptionHandler(void* emu, ArgList& argv, void* ctx) {
    // ULONG RemoveVectoredExceptionHandler(PVOID Handle)
    uint64_t handler = argv[0];

    auto* wemu = static_cast<Win32Emulator*>(static_cast<MemoryManager*>(emu));
    wemu->remove_vectored_exception_handler(handler);
    return handler;
}

uint64_t Ntdll::LdrLoadDll(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS LdrLoadDll(PWSTR SearchPath, PULONG LoadFlags,
    //                      PUNICODE_STRING Name, PVOID *BaseAddress)
    uint64_t search_path_ptr = argv[0];
    uint64_t load_flags_ptr  = argv[1];
    uint64_t name_ptr        = argv[2];
    uint64_t base_addr_ptr   = argv[3];

    std::string req_lib;
    if (name_ptr != 0) {
        req_lib = read_unicode_string_content(emu, name_ptr);
    }

    // Normalize DLL name (e.g. "kernel32" → "kernel32.dll")
    std::string norm_name;
    auto dot = req_lib.find_last_of('.');
    std::string base = (dot != std::string::npos) ? req_lib.substr(0, dot) : req_lib;
    norm_name = speakeasy::to_lower(base) + ".dll";

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));

    void* hmod = wemu->load_library(norm_name);
    if (!hmod) {
        hmod = wemu->load_library(req_lib);  // Try original name
    }

    // Update ArgList for logging (matches Python argv[0/1/2] updates)
    if (search_path_ptr != 0) {
        auto* bemu = static_cast<BinaryEmulator*>(static_cast<MemoryManager*>(emu));
        argv[0] = bemu->read_mem_string(search_path_ptr, 2);
    }
    argv[1] = "";  // LoadFlags string (Python resolves flags to names; stub for now)
    argv[2] = req_lib;  // Replace UNICODE_STRING ptr with readable name

    if (!hmod) {
        return STATUS_DLL_NOT_FOUND;
    }

    if (base_addr_ptr != 0) {
        uint64_t mod_base = reinterpret_cast<uint64_t>(hmod);
        int psz = get_ptr_size(emu);
        auto* mm = static_cast<MemoryManager*>(emu);
        std::vector<uint8_t> buf(psz, 0);
        write_le(buf, 0, mod_base, psz);
        mm->mem_write(base_addr_ptr, buf);
    }

    return STATUS_SUCCESS;
}

uint64_t Ntdll::LdrGetProcedureAddress(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS LdrGetProcedureAddress(HMODULE ModuleHandle,
    //     PANSI_STRING FunctionName, WORD Ordinal, PVOID *FunctionAddress)
    uint64_t hmod           = argv[0];
    uint64_t proc_name_ptr  = argv[1];
    uint64_t ordinal        = argv[2];
    uint64_t func_addr_ptr  = argv[3];

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* mm   = static_cast<MemoryManager*>(emu);

    std::string proc;
    uint64_t rv = STATUS_PROCEDURE_NOT_FOUND;

    if (proc_name_ptr != 0) {
        proc = read_ansi_string_content(emu, proc_name_ptr);
        argv[1] = proc;  // Replace ANSI_STRING ptr with readable string (matches Python argv[1])
    } else if (ordinal != 0) {
        proc = "ordinal_" + std::to_string(ordinal);
    }

    if (!proc.empty()) {
        auto mods = wemu->get_peb_modules();
        for (auto mod : mods) {
            if (mod->base == hmod) {
                auto* bemu = static_cast<BinaryEmulator*>(mm);
                std::string mod_name = bemu->get_address_tag(mod->base);
                uint64_t addr = reinterpret_cast<uint64_t>(wemu->get_proc(mod_name, proc));
                if (addr != 0) {
                    if (func_addr_ptr != 0) {
                        int psz = get_ptr_size(emu);
                        std::vector<uint8_t> buf(psz, 0);
                        write_le(buf, 0, addr, psz);
                        mm->mem_write(func_addr_ptr, buf);
                    }
                    rv = STATUS_SUCCESS;
                }
                break;
            }
        }
    }

    return rv;
}

uint64_t Ntdll::RtlZeroMemory(void* emu, ArgList& argv, void* ctx) {
    // void RtlZeroMemory(void* Destination, size_t Length)
    uint64_t dest = argv[0];
    size_t length = static_cast<size_t>(argv[1]);

    if (dest == 0 || length == 0) return 0;

    auto* mm = static_cast<MemoryManager*>(emu);
    std::vector<uint8_t> zeros(length, 0);
    mm->mem_write(dest, zeros);
    return 0;
}

uint64_t Ntdll::RtlMoveMemory(void* emu, ArgList& argv, void* ctx) {
    // void RtlMoveMemory(void* pvDest, const void* pSrc, size_t Length)
    uint64_t dest = argv[0];
    uint64_t src = argv[1];
    size_t length = static_cast<size_t>(argv[2]);

    if (dest == 0 || src == 0 || length == 0) return 0;

    auto* mm = static_cast<MemoryManager*>(emu);
    auto data = mm->mem_read(src, length);
    if (!data.empty()) {
        mm->mem_write(dest, data);
    }
    return 0;
}

uint64_t Ntdll::NtSetInformationProcess(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS NtSetInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG)
    (void)emu; (void)argv;
    return STATUS_SUCCESS;  // Python ntdll.py: return 0
}

uint64_t Ntdll::RtlEncodePointer(void* emu, ArgList& argv, void* ctx) {
    // PVOID RtlEncodePointer(PVOID Pointer)
    (void)emu;
    return argv[0] + 1;
}

uint64_t Ntdll::RtlDecodePointer(void* emu, ArgList& argv, void* ctx) {
    // PVOID RtlDecodePointer(PVOID Pointer)
    (void)emu;
    return argv[0] - 1;
}

uint64_t Ntdll::NtWaitForSingleObject(void* emu, ArgList& argv, void* ctx) {
    // NTSYSAPI NTSTATUS NtWaitForSingleObject(HANDLE, BOOLEAN, PLARGE_INTEGER)
    (void)emu; (void)argv;
    // Python ntdll.py: always returns STATUS_SUCCESS
    return STATUS_SUCCESS;
}

uint64_t Ntdll::RtlComputeCrc32(void* emu, ArgList& argv, void* ctx) {
    // DWORD RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen)
    uint32_t initial = static_cast<uint32_t>(argv[0]);
    uint64_t data_ptr = argv[1];
    int32_t len = static_cast<int32_t>(argv[2]);
    (void)initial;  // Python's binascii.crc32 ignores initial; matches our behavior

    auto* mm = static_cast<MemoryManager*>(emu);

    if (data_ptr == 0 || len <= 0) return 0;

    auto raw = mm->mem_read(data_ptr, static_cast<size_t>(len));

    uint32_t crc = 0xFFFFFFFF;
    static const uint32_t crc32_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };

    for (size_t i = 0; i < raw.size(); i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ raw[i]) & 0xFF];
    }
    crc ^= 0xFFFFFFFF;

    return static_cast<uint64_t>(crc);
}

uint64_t Ntdll::LdrFindResource_U(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS LdrFindResource_U(PVOID DllHandle, PLDR_RESOURCE_INFO ResourceInfo,
    //                             ULONG Level, PIMAGE_RESOURCE_DATA_ENTRY *ResourceDataEntry)
    //
    // LDR_RESOURCE_INFO: { ULONG_PTR Type; ULONG_PTR Name; ULONG_PTR Language; }
    // IMAGE_RESOURCE_DATA_ENTRY: { ULONG OffsetToData; ULONG Size; ULONG CodePage; ULONG Reserved; }
    uint64_t DllHandle         = argv[0];
    uint64_t ResourceInfo      = argv[1];
    uint32_t Level             = static_cast<uint32_t>(argv[2]);
    uint64_t ResourceDataEntry = argv[3];
    (void)Level;

    if (!ResourceInfo || !ResourceDataEntry) return STATUS_INVALID_PARAMETER;

    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto* mm   = static_cast<MemoryManager*>(emu);
    int psz = get_ptr_size(emu);

    // Resolve module
    std::shared_ptr<speakeasy::RuntimeModule> pe;
    if (DllHandle == 0) {
        // Python: emu.modules[0] (main executable)
        auto mods = wemu->get_peb_modules();
        if (!mods.empty()) pe = mods[0];
    } else {
        pe = wemu->get_mod_from_addr(DllHandle);
        if (pe && DllHandle != pe->base) return STATUS_INVALID_HANDLE;
    }

    if (!pe) return STATUS_INVALID_HANDLE;

    // Read LDR_RESOURCE_INFO: Type(psz), Name(psz)
    uint64_t type_id = read_ptr(emu, ResourceInfo);
    uint64_t name_id = read_ptr(emu, ResourceInfo + psz);

    // Write a placeholder IMAGE_RESOURCE_DATA_ENTRY address
    // (Full PE resource directory walk not implemented — matches kernel32's simplified FindResource)
    uint64_t entry_addr = pe->base + 0x3000;  // placeholder data entry
    write_ptr(emu, ResourceDataEntry, entry_addr);

    // Log identifiers for debugging
    argv[0] = type_id;
    argv[1] = name_id;

    (void)mm;
    return STATUS_SUCCESS;
}

uint64_t Ntdll::NtUnmapViewOfSection(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
    // Python ntdll.py: just returns STATUS_SUCCESS (delegates to ntoskrnl for actual work)
    (void)emu; (void)argv;
    return STATUS_SUCCESS;
}

uint64_t Ntdll::LdrAccessResource(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS LdrAccessResource(PVOID BaseAddress,
    //     PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry,
    //     PVOID *Resource, PULONG Size)
    uint64_t base_addr  = argv[0];
    uint64_t res_entry  = argv[1];
    uint64_t resource_ptr = argv[2];
    uint64_t size_ptr   = argv[3];

    auto* mm = static_cast<MemoryManager*>(emu);

    if (res_entry == 0) return STATUS_INVALID_PARAMETER;

    // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4), Size(4), CodePage(4), Reserved(4)
    uint32_t offset = read_u32(emu, res_entry);
    uint32_t size   = read_u32(emu, res_entry + 4);

    if (size_ptr != 0) {
        write_ptr(emu, size_ptr, static_cast<uint64_t>(size));  // PULONG written as pointer-sized (matches Python write_ptr)
    }

    if (resource_ptr != 0) {
        write_ptr(emu, resource_ptr, base_addr + offset);
    }

    (void)mm;
    return STATUS_SUCCESS;
}

uint64_t Ntdll::RtlGetNtVersionNumbers(void* emu, ArgList& argv, void* ctx) {
    // void RtlGetNtVersionNumbers(DWORD *pNtMajorVersion,
    //     DWORD *pNtMinorVersion, DWORD *pNtBuildNumber)
    uint64_t p_major = argv[0];
    uint64_t p_minor = argv[1];
    uint64_t p_build = argv[2];

    if (p_major != 0) write_u32(emu, p_major, 10);             // Major = 10
    if (p_minor != 0) write_u32(emu, p_minor, 0);              // Minor = 0
    if (p_build != 0) write_u32(emu, p_build, 0xF0004A61);     // Build (matches Python)

    return 0;
}

uint64_t Ntdll::RtlGetCurrentPeb(void* emu, ArgList& argv, void* ctx) {
    // PPEB RtlGetCurrentPeb();
    auto* wemu = static_cast<WindowsEmulator*>(static_cast<MemoryManager*>(emu));
    auto proc = wemu->get_current_process();
    if (proc && proc->peb) {
        return proc->peb->get_address();
    }
    return 0;
}

uint64_t Ntdll::RtlGetVersion(void* emu, ArgList& argv, void* ctx) {
    // NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
    uint64_t info_ptr = argv[0];

    if (info_ptr == 0) return STATUS_INVALID_PARAMETER;

    // RTL_OSVERSIONINFOW: dwOSVersionInfoSize(4), dwMajorVersion(4),
    // dwMinorVersion(4), dwBuildNumber(4), dwPlatformId(4), szCSDVersion(128*WCHAR)
    write_u32(emu, info_ptr, 276);         // dwOSVersionInfoSize
    write_u32(emu, info_ptr + 4, 10);      // dwMajorVersion = 10
    write_u32(emu, info_ptr + 8, 0);       // dwMinorVersion = 0
    write_u32(emu, info_ptr + 12, 19041);  // dwBuildNumber
    write_u32(emu, info_ptr + 16, 2);      // dwPlatformId = VER_PLATFORM_WIN32_NT

    // szCSDVersion: zero-filled (256 bytes in Python, 260 = 128*WCHAR+null)
    auto* mm = static_cast<MemoryManager*>(emu);
    std::vector<uint8_t> zero(256, 0);
    mm->mem_write(info_ptr + 20, zero);

    return STATUS_SUCCESS;
}

//
// Fallback stub — unregistered ntdll exports are handled by ntoskrnl
//

uint64_t Ntdll::stub_api(void* e, ArgList& a, void* ctx) {
    (void)e; (void)a;
    return STATUS_SUCCESS;
}

} // namespace api
} // namespace speakeasy
