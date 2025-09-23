// common.h
#ifndef WINDOWS_COMMON_H
#define WINDOWS_COMMON_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <exception>
#include <tuple>

// TODO: Need C++ equivalents for these Python imports
// #include <pefile.h> // Need a C++ PE file library
// #include "arch.h"
// #include "winenv/defs/nt/ddk.h"
// #include "struct.h"

// GDT Constants needed to set our emulator into protected mode
// Access bits
struct GDT_ACCESS_BITS {
    static const uint8_t ProtMode32 = 0x4;
    static const uint8_t PresentBit = 0x80;
    static const uint8_t Ring3 = 0x60;
    static const uint8_t Ring0 = 0;
    static const uint8_t DataWritable = 0x2;
    static const uint8_t CodeReadable = 0x2;
    static const uint8_t DirectionConformingBit = 0x4;
    static const uint8_t Code = 0x18;
    static const uint8_t Data = 0x10;
};

struct GDT_FLAGS {
    static const uint8_t Ring3 = 0x3;
    static const uint8_t Ring0 = 0;
};

// Memory addresses and constants
const uint32_t IMPORT_HOOK_ADDR = 0xFEEDFACE;
const uint32_t DEFAULT_LOAD_ADDR = 0x40000;
const uint32_t PAGE_SIZE = 0x1000;

const uint32_t EMU_RESERVED = 0xfeedf000;
const uint32_t EMU_RESERVE_SIZE = 0x4000;
const uint32_t DYM_IMP_RESERVE = EMU_RESERVED + 0x1000;
const uint32_t EMU_CALLBACK_RESERVE = DYM_IMP_RESERVE + 0x1000;
const uint32_t EMU_SYSCALL_RESERVE = EMU_CALLBACK_RESERVE + 0x1000;

const uint32_t EMU_RESERVED_END = (EMU_RESERVED + EMU_RESERVE_SIZE);
const uint32_t EMU_RETURN_ADDR = EMU_RESERVED;
const uint32_t EXIT_RETURN_ADDR = EMU_RETURN_ADDR + 1;
const uint32_t SEH_RETURN_ADDR = EMU_RETURN_ADDR + 4;
const uint32_t API_CALLBACK_HANDLER_ADDR = EMU_RETURN_ADDR + 8;
// Note: IMPORT_HOOK_ADDR is redefined here, using the previous definition

// Common blank DOS header
const std::vector<uint8_t> DOS_HEADER = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00......
};

// Blank header used for a 32-bit PE header
const std::vector<uint8_t> EMPTY_PE_32 = {
    // DOS_HEADER + 
    0x50, 0x45, 0x00, 0x00, 0x4C, 0x01, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x03, 0x01, 0x0B, 0x01, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00,
    0x00, 0xD4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xD4, 0x01, 0x00, 0x00, 0xD0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10
    // + (b'\x00' * 131)
};

// Blank header used for a 64-bit PE header
const std::vector<uint8_t> EMPTY_PE_64 = {
    // DOS_HEADER + 
    0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x03, 0x10, 0x0B, 0x02, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x41, 0x41, 0x41,
    0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    // + (b'\x00' * 131)
};

// Exception class for PE parsing errors
class PeParseException : public std::exception {
private:
    std::string message;
    
public:
    explicit PeParseException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};

// Forward declarations
class PeFile;

// Structure to represent a PE export
struct ExportEntry {
    std::string name;
    uint64_t address;
    std::string forwarder;
    uint32_t ordinal;
};

// Structure to represent a PE section
struct PeSection {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
};

// Function to normalize DLL names
std::string normalize_dll_name(const std::string& name);

// Class that represents PE files loaded into the emulator
class PeFile {
protected:
    uint64_t imp_id;
    uint64_t imp_step;
    size_t file_size;
    uint64_t base;
    std::string hash;
    std::map<uint64_t, std::tuple<std::string, std::string>> imports;
    std::vector<ExportEntry> exports;
    std::vector<uint8_t> mapped_image;
    size_t image_size;
    std::map<uint64_t, std::tuple<std::string, std::string>> import_table;
    bool is_mapped;
    std::vector<PeSection> pe_sections;
    uint64_t ep;
    uint64_t stack_commit;
    std::string path;
    std::string name;
    std::string emu_path;
    int arch;
    int ptr_size;

public:
    // Constructor
    PeFile(const std::string& path = "", const std::vector<uint8_t>& data = {}, 
           uint64_t imp_id = IMPORT_HOOK_ADDR, uint64_t imp_step = 4, 
           const std::string& emu_path = "", bool fast_load = false);
    
    // Methods
    std::vector<uint64_t> get_tls_callbacks();
    uint32_t get_resource_dir_rva();
    std::string get_emu_path();
    void set_emu_path(const std::string& path);
    std::string _hash_pe(const std::string& path = "", const std::vector<uint8_t>& data = {});
    std::map<uint64_t, std::tuple<std::string, std::string>> _get_pe_imports();
    std::vector<ExportEntry> get_exports();
    std::vector<ExportEntry> _get_pe_exports();
    std::vector<PeSection> _get_pe_sections();
    std::vector<PeSection> get_sections();
    PeSection* get_section_by_name(const std::string& name);
    int _get_architecture();
    void _patch_imports();
    uint64_t get_export_by_name(const std::string& name);
    std::vector<uint8_t> get_raw_data();
    int find_bytes(const std::vector<uint8_t>& pattern, int offset = 0);
    void set_bytes(int offset, const std::vector<uint8_t>& pattern);
    int get_ptr_size();
    uint64_t get_base();
    std::string get_base_name();
    size_t get_image_size();
    bool is_decoy();
    bool is_driver();
    bool is_dotnet();
    bool has_reloc_table();
    void rebase(uint64_t to);
};

// Class that represents "decoy" modules that are loaded into emulated memory
class DecoyModule : public PeFile {
private:
    uint64_t decoy_base;
    std::string decoy_path;
    std::string base_name;
    bool is_jitted;
    std::vector<uint8_t> data;

public:
    // Constructor
    DecoyModule(const std::string& path = "", const std::vector<uint8_t>& data = {}, 
                bool fast_load = true, uint64_t base = 0, const std::string& emu_path = "", 
                bool is_jitted = false);
    
    // Methods
    std::vector<uint8_t> get_memory_mapped_image(uint64_t max_virtual_address = 0x10000000, 
                                                 uint64_t base = 0) override;
    uint64_t get_base() override;
    std::string get_emu_path() override;
    std::string get_base_name() override;
    uint64_t get_ep();
    bool is_decoy() override;
};

// Class used to rapidly assemble a decoy PE that will only contain an export table
class JitPeFile {
private:
    int pattern_size;
    std::vector<uint8_t> basepe_data;
    int arch;

public:
    // Constructor
    JitPeFile(int arch);
    
    // Methods
    // TODO: Implement PE section handling methods
    /*
    void* get_section_by_name(void* pe, const std::string& name);
    std::vector<uint8_t> get_raw_pe();
    void update();
    void* cast_section(int offset = -1);
    void update_image_size();
    void* add_section(const std::string& name, uint32_t chars = 0x40000040);
    int get_current_offset();
    void append_data(const std::vector<uint8_t>& data);
    int get_exports_size(const std::string& name, const std::vector<std::string>& exports);
    std::vector<uint8_t> get_decoy_pe_image(const std::string& mod_name, 
                                            const std::vector<std::string>& exports);
    void init_export_section(const std::string& name, const std::vector<std::string>& exports);
    void init_text_section(const std::vector<std::string>& names);
    */
};

#endif // WINDOWS_COMMON_H