// common.cpp — Windows emulation common utilities
#include "common.h"
#include "struct.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstring>
#include <pe-parse/parse.h>
#include <pe-parse/nt-headers.h>

#include "picosha2.h"

static std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

std::string normalize_dll_name(const std::string& name) {
    std::string ret = name;
    std::string lower = to_lower(name);
    auto startswith = [&](const std::string& prefix) {
        return lower.substr(0, std::min(lower.size(), prefix.size())) == prefix;
    };
    if (startswith("api-ms-win-crt") || startswith("vcruntime") ||
        startswith("ucrtbased") || startswith("ucrtbase") ||
        startswith("msvcr") || startswith("msvcp"))
        ret = "msvcrt";
    else if (startswith("winsock") || startswith("wsock32"))
        ret = "ws2_32";
    else if (startswith("api-ms-win-core"))
        ret = "kernel32";
    return ret;
}

static void sync_optional_header(peparse::parsed_pe* parsed_pe) {
    if (!parsed_pe) return;
    if (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) { // NT_OPTIONAL_64_MAGIC
        auto& oh64 = parsed_pe->peHeader.nt.OptionalHeader64;
        auto& oh32 = parsed_pe->peHeader.nt.OptionalHeader;
        
        oh32.ImageBase = static_cast<uint32_t>(oh64.ImageBase & 0xFFFFFFFF);
        oh32.AddressOfEntryPoint = oh64.AddressOfEntryPoint;
        oh32.SectionAlignment = oh64.SectionAlignment;
        oh32.FileAlignment = oh64.FileAlignment;
        oh32.SizeOfImage = oh64.SizeOfImage;
        oh32.SizeOfStackCommit = static_cast<uint32_t>(oh64.SizeOfStackCommit);
        oh32.Subsystem = oh64.Subsystem;
        oh32.NumberOfRvaAndSizes = oh64.NumberOfRvaAndSizes;
        
        // Copy DataDirectory
        for (size_t i = 0; i < 16; ++i) {
            oh32.DataDirectory[i] = oh64.DataDirectory[i];
        }
    }
}

// ── Import callback ──────────────────────────────────────
struct PeImportCtx {
    std::map<uint64_t, std::tuple<std::string, std::string>> imports;
};
static int pefile_imp_cb(void* cbd, const peparse::VA& iat_addr,
                         const std::string& mod_name,
                         const std::string& sym_name) {
    auto* ctx = static_cast<PeImportCtx*>(cbd);
    std::string dll = mod_name;
    auto dot = dll.rfind('.');
    if (dot != std::string::npos) {
        dll = dll.substr(0, dot);
    }
    std::string func = sym_name.empty() ? ("ordinal_unknown") : sym_name;
    ctx->imports[iat_addr] = {dll, func};
    return 0;
}

// ── Export callback ──────────────────────────────────────
struct PeExportCtx {
    std::vector<ExportEntry> exports;
};
static int pefile_exp_cb(void* cbd, const peparse::VA& addr,
                         const std::string& name,
                         const std::string& mod_name) {
    auto* ctx = static_cast<PeExportCtx*>(cbd);
    ExportEntry e;
    e.name = name;
    e.address = addr;
    e.forwarder = "";
    e.ordinal = 0;
    ctx->exports.push_back(e);
    (void)mod_name;
    return 0;
}

// ── Section callback ─────────────────────────────────────
struct PeSectionCtx {
    std::vector<PeSection> sections;
    uint64_t image_base;
};
static int pefile_sec_cb(void* cbd, const peparse::VA& sec_base,
                         const std::string& sec_name,
                         const peparse::image_section_header& sec,
                         const peparse::bounded_buffer* sec_data) {
    (void)sec_name;
    auto* ctx = static_cast<PeSectionCtx*>(cbd);
    PeSection s;
    s.name = std::string((const char*)sec.Name, 8);
    auto nul = s.name.find('\0');
    if (nul != std::string::npos) s.name.erase(nul);
    s.virtual_address = static_cast<uint32_t>(sec_base - ctx->image_base);
    s.virtual_size = sec.Misc.VirtualSize;
    s.raw_size = sec.SizeOfRawData;
    s.pointer_to_raw_data = sec.PointerToRawData;
    ctx->sections.push_back(s);
    (void)sec_data;
    return 0;
}

// ── PeFile implementation ─────────────────────────────────
PeFile::PeFile(const std::string& path, const std::vector<uint8_t>& data,
               uint64_t imp_id, uint64_t imp_step,
               const std::string& emu_path, bool fast_load)
    : imp_id(imp_id), imp_step(imp_step), file_size(0), base(0),
      image_size(0), is_mapped(true), ep(0), stack_commit(0),
      path(path), emu_path(emu_path), parsed_pe(nullptr) {

    (void)fast_load;

    if(path.empty () && data.empty())
        return;

    // Load PE data
    if (!data.empty()) {
        raw_pe_data = data;
        file_size = data.size();
    } else {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) throw PeParseException("Cannot open: " + path);
        file_size = f.tellg();
        f.seekg(0);
        raw_pe_data.resize(file_size);
        f.read((char*)raw_pe_data.data(), file_size);
    }
    
    try {
        // Parse with pe-parse
        parsed_pe = peparse::ParsePEFromPointer(
            const_cast<uint8_t*>(raw_pe_data.data()),
            static_cast<uint32_t>(raw_pe_data.size()));
        if (!parsed_pe) throw PeParseException("Failed to parse PE");
        
        sync_optional_header(parsed_pe);
        
        // Compute hash
        hash = _hash_pe(path, raw_pe_data);
        
        // Header fields
        if (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) {
            base = parsed_pe->peHeader.nt.OptionalHeader64.ImageBase;
        } else {
            base = parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
        }
        if (base == 0) { base = DEFAULT_LOAD_ADDR; }
        ep = parsed_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
        image_size = parsed_pe->peHeader.nt.OptionalHeader.SizeOfImage;
        stack_commit = parsed_pe->peHeader.nt.OptionalHeader.SizeOfStackCommit;
        
        // Architecture
        arch = _get_architecture();
        ptr_size = (arch == 32) ? 4 : 8;
        
        // Sections
        pe_sections = _get_pe_sections();
        
        // Imports
        imports = _get_pe_imports();
        
        // Exports
        exports = _get_pe_exports();
        
        // Mapped image
        mapped_image = get_memory_mapped_image(0xF0000000);
        is_mapped = true;

        uint64_t orig_image_base = (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) ? parsed_pe->peHeader.nt.OptionalHeader64.ImageBase : parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
        if (orig_image_base == 0) {
            relocate_image(DEFAULT_LOAD_ADDR);
        }

        // Patch imports
        _patch_imports();
    } catch (...) {
        if (parsed_pe) {
            peparse::DestructParsedPE(parsed_pe);
            parsed_pe = nullptr;
        }
        throw;
    }
}

PeFile::~PeFile() {
    if (parsed_pe) {
        peparse::DestructParsedPE(parsed_pe);
    }
}

std::vector<uint64_t> PeFile::get_tls_callbacks() {
    if (!parsed_pe) return {};

    std::vector<uint64_t> callbacks;
    auto tls_dir = parsed_pe->peHeader.nt.OptionalHeader.DataDirectory[9]; // IMAGE_DIRECTORY_ENTRY_TLS
    if (tls_dir.VirtualAddress != 0) {
        uint64_t callbacks_rva = 0;

        auto read_bytes_at_va = [&](uint64_t addr, size_t size) -> std::vector<uint8_t> {
            std::vector<uint8_t> data;
            for (size_t i = 0; i < size; ++i) {
                uint8_t b = 0;
                if (peparse::ReadByteAtVA(parsed_pe, peparse::VA(addr + i), b))
                    data.push_back(b);
                else
                    break;
            }
            return data;
        };

        auto tls_data = read_bytes_at_va(tls_dir.VirtualAddress, 4 * ptr_size + ptr_size);
        if (tls_data.size() >= 4 * ptr_size) {
            for (int j = 3 * ptr_size; j < 4 * ptr_size && j + ptr_size <= (int)tls_data.size(); ++j) {
                callbacks_rva |= static_cast<uint64_t>(tls_data[j]) << ((j - 3 * ptr_size) * 8);
            }
        }

        if (callbacks_rva != 0) {
            for (int i = 0; i < 100; ++i) {
                auto ptr_data = read_bytes_at_va(callbacks_rva + i * ptr_size, ptr_size);
                if (ptr_data.size() < (size_t)ptr_size) break;
                uint64_t ptr = 0;
                for (int j = 0; j < ptr_size; ++j)
                    ptr |= static_cast<uint64_t>(ptr_data[j]) << (j * 8);
                if (ptr == 0) break;
                callbacks.push_back(ptr);
            }
        }
    }
    return callbacks;
}

uint32_t PeFile::get_resource_dir_rva() {
    if (!parsed_pe) return 0;
    uint32_t rva = 0;
    // Access data directory directly via parsed_pe->peHeader
    // IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
    // Access via the NT headers
    if (parsed_pe->peHeader.nt.OptionalMagic == 0x010b) {
        auto& oh = parsed_pe->peHeader.nt.OptionalHeader;
        const auto* dirs = reinterpret_cast<const peparse::data_directory*>(
            reinterpret_cast<const char*>(&oh) + sizeof(peparse::optional_header_32) - 
            sizeof(peparse::data_directory) * 16);
        rva = dirs[2].VirtualAddress;
    } else {
        auto& oh = parsed_pe->peHeader.nt.OptionalHeader;
        const auto* dirs = reinterpret_cast<const peparse::data_directory*>(
            reinterpret_cast<const char*>(&oh) + sizeof(peparse::optional_header_64) - 
            sizeof(peparse::data_directory) * 16);
        rva = dirs[2].VirtualAddress;
    }
    return rva;
}

std::string PeFile::get_emu_path() { return emu_path; }

void PeFile::set_emu_path(const std::string& p) { emu_path = p; }

std::string PeFile::_hash_pe(const std::string& pe_path, const std::vector<uint8_t>& data) {
    (void)pe_path;
    return picosha2::hash256_hex_string(data.begin(), data.end());
}

std::map<uint64_t, std::tuple<std::string, std::string>> PeFile::_get_pe_imports() {
    if (!parsed_pe) return {};
    PeImportCtx ctx;
    peparse::IterImpVAString(parsed_pe, pefile_imp_cb, &ctx);
    return ctx.imports;
}

std::vector<ExportEntry> PeFile::get_exports() {
    if (exports.empty()) exports = _get_pe_exports();
    return exports;
}

std::vector<ExportEntry> PeFile::_get_pe_exports() {
    if (!parsed_pe) return {};
    PeExportCtx ctx;
    peparse::IterExpVA(parsed_pe, pefile_exp_cb, &ctx);
    return ctx.exports;
}

std::vector<PeSection> PeFile::_get_pe_sections() {
    if (!parsed_pe) return {};
    PeSectionCtx ctx;
    ctx.image_base = (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) ? parsed_pe->peHeader.nt.OptionalHeader64.ImageBase : parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
    peparse::IterSec(parsed_pe, pefile_sec_cb, &ctx);
    return ctx.sections;
}

std::vector<PeSection> PeFile::get_sections() {
    if (pe_sections.empty()) pe_sections = _get_pe_sections();
    return pe_sections;
}

PeSection* PeFile::get_section_by_name(const std::string& sec_name) {
    for (auto& s : pe_sections) {
        if (s.name == sec_name) return &s;
    }
    return nullptr;
}

int PeFile::_get_architecture() {
    if (!parsed_pe) return 64;
    uint16_t magic = parsed_pe->peHeader.nt.OptionalMagic;
    return (magic == 0x020b) ? 64 : 32;
}

void PeFile::_patch_imports() {
    if (imports.empty() || mapped_image.empty()) return;
    for (auto& [addr, imp] : imports) {
        uint64_t offset = addr - base;
        if (offset + ptr_size > mapped_image.size()) continue;
        for (size_t j = 0; j < (size_t)ptr_size; ++j) {
            if (offset + j < mapped_image.size())
                mapped_image[offset + j] = (imp_id >> (j * 8)) & 0xFF;
        }
        import_table[imp_id] = imp;
        imp_id += imp_step;
    }
}

uint64_t PeFile::get_export_by_name(const std::string& exp_name) {
    for (auto& e : get_exports()) {
        if (e.name == exp_name) return e.address;
    }
    return 0;
}

std::vector<uint8_t> PeFile::get_raw_data() {
    return mapped_image;
}

int PeFile::find_bytes(const std::vector<uint8_t>& pattern, int offset) {
    if (offset >= (int)mapped_image.size()) return -1;
    auto it = std::search(mapped_image.begin() + offset, mapped_image.end(),
                          pattern.begin(), pattern.end());
    if (it == mapped_image.end()) return -1;
    return (int)(it - mapped_image.begin());
}

void PeFile::set_bytes(int offset, const std::vector<uint8_t>& pattern) {
    if (offset + (int)pattern.size() > (int)mapped_image.size()) return;
    std::copy(pattern.begin(), pattern.end(), mapped_image.begin() + offset);
}

int PeFile::get_ptr_size() { return ptr_size; }
uint64_t PeFile::get_base() { return base; }

std::string PeFile::get_base_name() {
    auto slash = path.rfind('/');
    if (slash == std::string::npos) slash = path.rfind('\\');
    if (slash == std::string::npos) slash = 0;
    std::string fn = path.substr(slash + 1);
    auto dot = fn.rfind('.');
    if (dot != std::string::npos) fn.erase(dot);
    return fn;
}

size_t PeFile::get_image_size() { return image_size; }

bool PeFile::is_decoy() { return false; }

bool PeFile::is_dll() {
    if (!parsed_pe) return false;
    return (parsed_pe->peHeader.nt.FileHeader.Characteristics &
        0x2000/*peparse::IMAGE_FILE_DLL*/) != 0;
}

bool PeFile::is_driver() {
    if (parsed_pe) {
        if (parsed_pe->peHeader.nt.OptionalHeader.Subsystem == 1) { // IMAGE_SUBSYSTEM_NATIVE
            return true;
        }
    }
    if (!imports.empty()) {
        static const std::vector<std::string> sys_dlls = {
            "ntoskrnl", "hal", "ndis", "bootvid", "kdcom", "win32k"};
        for (auto& [addr, imp] : imports) {
            (void)addr;
            if (std::find(sys_dlls.begin(), sys_dlls.end(),
                          to_lower(std::get<0>(imp))) != sys_dlls.end())
                return true;
        }
    }
    return false;
}

bool PeFile::is_dotnet() {
    for (auto& [addr, imp] : imports) {
        (void)addr;
        auto& [dll, func] = imp;
        if (to_lower(dll) == "mscoree" &&
            (func == "_CorExeMain" || func == "_CorDllMain"))
            return true;
    }
    return false;
}

bool PeFile::has_reloc_table() {
    if (!parsed_pe) return false;
    auto num_dirs = parsed_pe->peHeader.nt.OptionalHeader.NumberOfRvaAndSizes;
    if (num_dirs >= 6) {
        return parsed_pe->peHeader.nt.OptionalHeader.DataDirectory[5].Size > 0;
    }
    return false;
}

void PeFile::relocate_image(uint64_t new_base) {
    if (!parsed_pe) return;

    auto num_dirs = parsed_pe->peHeader.nt.OptionalHeader.NumberOfRvaAndSizes;
    if (num_dirs < 6) return;

    auto reloc_dir = parsed_pe->peHeader.nt.OptionalHeader.DataDirectory[5];
    if (reloc_dir.Size == 0 || reloc_dir.VirtualAddress == 0) {
        return; // No relocations
    }

    uint64_t reloc_rva = reloc_dir.VirtualAddress;
    uint64_t reloc_size = reloc_dir.Size;

    uint64_t preferred_base = (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) ? parsed_pe->peHeader.nt.OptionalHeader64.ImageBase : parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
    uint64_t delta = new_base - preferred_base;
    if (delta == 0) {
        return; // No change in base address, no relocations needed
    }

    uint64_t bytes_processed = 0;
    while (bytes_processed + 8 <= reloc_size) {
        uint64_t block_rva_offset = reloc_rva + bytes_processed;
        if (block_rva_offset + 8 > mapped_image.size()) {
            break;
        }

        uint32_t page_rva = static_cast<uint32_t>(speakeasy::read_le(mapped_image, block_rva_offset, 4));
        uint32_t block_size = static_cast<uint32_t>(speakeasy::read_le(mapped_image, block_rva_offset + 4, 4));

        if (block_size < 8 || bytes_processed + block_size > reloc_size) {
            break;
        }

        uint32_t num_entries = (block_size - 8) / 2;
        for (uint32_t i = 0; i < num_entries; ++i) {
            uint64_t entry_offset = block_rva_offset + 8 + i * 2;
            if (entry_offset + 2 > mapped_image.size()) {
                break;
            }

            uint16_t descriptor = static_cast<uint16_t>(speakeasy::read_le(mapped_image, entry_offset, 2));
            uint16_t type = descriptor >> 12;
            uint16_t offset = descriptor & 0x0FFF;

            if (type == 0) { // IMAGE_REL_BASED_ABSOLUTE
                continue;
            }

            uint64_t target_rva = static_cast<uint64_t>(page_rva) + offset;

            if (type == 3) { // IMAGE_REL_BASED_HIGHLOW (32-bit absolute address)
                if (target_rva + 4 <= mapped_image.size()) {
                    uint32_t val = static_cast<uint32_t>(speakeasy::read_le(mapped_image, target_rva, 4));
                    val += static_cast<uint32_t>(delta);
                    speakeasy::write_le(mapped_image, target_rva, val, 4);
                }
            } else if (type == 10) { // IMAGE_REL_BASED_DIR64 (64-bit absolute address)
                if (target_rva + 8 <= mapped_image.size()) {
                    uint64_t val = speakeasy::read_le(mapped_image, target_rva, 8);
                    val += delta;
                    speakeasy::write_le(mapped_image, target_rva, val, 8);
                }
            }
        }

        bytes_processed += block_size;
    }
}

void PeFile::rebase(uint64_t to) {
    base = to;
    if (parsed_pe) {
        ep = parsed_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
    }
    mapped_image = get_memory_mapped_image(0xF0000000);
    relocate_image(to);
    pe_sections = _get_pe_sections();
    imports = _get_pe_imports();
    exports = _get_pe_exports();
    import_table.clear();
    _patch_imports();
}

std::vector<uint8_t> PeFile::get_memory_mapped_image(uint64_t max_virtual_address, uint64_t base_addr) {
    (void)base_addr;
    if (!parsed_pe) {
        return {};
    }

    uint32_t section_alignment = parsed_pe->peHeader.nt.OptionalHeader.SectionAlignment;
    uint32_t file_alignment = parsed_pe->peHeader.nt.OptionalHeader.FileAlignment;

    // Helper lambdas to match Python's pefile helper functions:
    auto adjust_PointerToRawData = [](uint32_t val) -> uint32_t {
        return val & ~0x1FF;
    };

    auto adjust_SectionAlignment = [](uint32_t val, uint32_t sect_align, uint32_t file_align) -> uint32_t {
        if (sect_align < 0x1000) {
            sect_align = file_align;
        }
        if (sect_align != 0 && (val % sect_align) != 0) {
            return sect_align * (val / sect_align);
        }
        return val;
    };

    auto get_PointerToRawData_adj = [&](uint32_t ptr_raw, uint32_t virt_addr) -> uint32_t {
        uint32_t ptrd = adjust_PointerToRawData(ptr_raw);
        if (section_alignment < 0x1000) {
            if (ptr_raw == virt_addr) {
                ptrd = virt_addr;
            }
        }
        return ptrd;
    };

    auto get_VirtualAddress_adj = [&](uint32_t virt_addr) -> uint32_t {
        return adjust_SectionAlignment(virt_addr, section_alignment, file_alignment);
    };

    // Calculate offset (end of section table headers)
    uint32_t e_lfanew = parsed_pe->peHeader.dos.e_lfanew;
    uint32_t size_of_optional_header = parsed_pe->peHeader.nt.FileHeader.SizeOfOptionalHeader;
    uint32_t sections_offset = e_lfanew + 4 + 20 + size_of_optional_header;
    uint32_t offset = sections_offset + static_cast<uint32_t>(pe_sections.size()) * 40;

    // Find lowest_section_offset
    uint32_t lowest_section_offset = 0;
    bool has_lowest = false;
    for (auto& s : pe_sections) {
        if (s.pointer_to_raw_data > 0) {
            uint32_t adj_ptr = adjust_PointerToRawData(s.pointer_to_raw_data);
            if (!has_lowest || adj_ptr < lowest_section_offset) {
                lowest_section_offset = adj_ptr;
                has_lowest = true;
            }
        }
    }

    uint32_t header_len = offset;
    if (has_lowest && lowest_section_offset >= offset) {
        header_len = lowest_section_offset;
    }

    std::vector<uint8_t> mapped_data;
    if (header_len > raw_pe_data.size()) {
        header_len = static_cast<uint32_t>(raw_pe_data.size());
    }
    mapped_data.assign(raw_pe_data.begin(), raw_pe_data.begin() + header_len);

    // Map each section
    for (auto& s : pe_sections) {
        if (s.virtual_size == 0 && s.raw_size == 0) {
            continue;
        }

        uint32_t srd = s.raw_size;
        uint32_t prd = adjust_PointerToRawData(s.pointer_to_raw_data);
        uint32_t VirtualAddress_adj = get_VirtualAddress_adj(s.virtual_address);

        if (srd > raw_pe_data.size() ||
            prd > raw_pe_data.size() ||
            srd + prd > raw_pe_data.size() ||
            VirtualAddress_adj >= max_virtual_address) {
            continue;
        }

        int64_t padding_length = static_cast<int64_t>(VirtualAddress_adj) - static_cast<int64_t>(mapped_data.size());
        if (padding_length > 0) {
            mapped_data.insert(mapped_data.end(), padding_length, 0);
        } else if (padding_length < 0) {
            if (VirtualAddress_adj < mapped_data.size()) {
                mapped_data.resize(VirtualAddress_adj);
            }
        }

        // Get section data
        uint32_t sec_offset = get_PointerToRawData_adj(s.pointer_to_raw_data, s.virtual_address);
        uint32_t sec_end = sec_offset + s.raw_size;
        if (s.pointer_to_raw_data + s.raw_size < sec_end) {
            sec_end = s.pointer_to_raw_data + s.raw_size;
        }

        if (sec_offset < raw_pe_data.size()) {
            if (sec_end > raw_pe_data.size()) {
                sec_end = static_cast<uint32_t>(raw_pe_data.size());
            }
            if (sec_end >= sec_offset) {
                mapped_data.insert(mapped_data.end(), raw_pe_data.begin() + sec_offset, raw_pe_data.begin() + sec_end);
            }
        }
    }

    return mapped_data;
}

// ── DecoyModule implementation ────────────────────────────
DecoyModule::DecoyModule(const std::string& path, const std::vector<uint8_t>& data,
                         bool fast_load, uint64_t base, const std::string& emu_path,
                         bool is_jitted)
    : PeFile(path, data, 0xFEEDFACE, 4, emu_path, fast_load),
      decoy_base(base), decoy_path(path), base_name(emu_path), is_jitted(is_jitted), data(data) {
    this->base = base;
    set_emu_path(emu_path);
}

std::string DecoyModule::get_emu_path() {
    if (!decoy_path.empty()) return decoy_path;
    std::string p = emu_path;
    if (p.empty()) p = get_base_name() + ".dll";
    return p;
}

uint64_t DecoyModule::get_base() { return decoy_base ? decoy_base : base; }
bool DecoyModule::is_decoy() { return true; }
std::string DecoyModule::get_base_name() { return base_name; }

std::vector<uint8_t> DecoyModule::get_memory_mapped_image(uint64_t max_virtual_address, uint64_t base_addr) {
    return PeFile::get_memory_mapped_image(max_virtual_address, base_addr);
}

// ── JitPeFile implementation ──────────────────────────────

// Exported stub template definitions
static const std::vector<uint8_t> X86_EXPORTED_FUNCTION = {
    0x8B, 0xFF,                    // mov edi, edi
    0x55,                          // push ebp
    0x8B, 0xEC,                    // mov ebp, esp
    0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0
    0x8B, 0xE5,                    // mov esp, ebp
    0x5D,                          // pop ebp
    0xC3,                          // ret
    0xCC,                          // int3
    0xCC,                          // int3
    0xCC                           // int3
};

static const std::vector<uint8_t> X64_EXPORTED_FUNCTION = {
    0x48, 0x89, 0xFF,              // mov rdi, rdi
    0x90,                          // nop
    0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, // mov rax, 0
    0xC3,                          // ret
    0xCC,                          // int3
    0xCC,                          // int3
    0xCC,                          // int3
    0xCC                           // int3
};

// Little-endian writing helpers
static inline void write_u16(std::vector<uint8_t>& buf, size_t offset, uint16_t val) {
    if (offset + 2 > buf.size()) buf.resize(offset + 2, 0);
    std::memcpy(&buf[offset], &val, 2);
}

static inline void write_u32(std::vector<uint8_t>& buf, size_t offset, uint32_t val) {
    if (offset + 4 > buf.size()) buf.resize(offset + 4, 0);
    std::memcpy(&buf[offset], &val, 4);
}

static inline uint16_t read_u16(const std::vector<uint8_t>& buf, size_t offset) {
    if (offset + 2 > buf.size()) return 0;
    uint16_t val;
    std::memcpy(&val, &buf[offset], 2);
    return val;
}

static inline uint32_t read_u32(const std::vector<uint8_t>& buf, size_t offset) {
    if (offset + 4 > buf.size()) return 0;
    uint32_t val;
    std::memcpy(&val, &buf[offset], 4);
    return val;
}

static inline uint32_t align_up(uint32_t val, uint32_t align) {
    if (align == 0) return val;
    return (val + align - 1) & ~(align - 1);
}

static void write_section_header(std::vector<uint8_t>& buf, size_t sect_table_offset, int sect_idx,
                                 const std::string& name, uint32_t v_size, uint32_t v_addr,
                                 uint32_t raw_size, uint32_t raw_ptr, uint32_t chars) {
    size_t offset = sect_table_offset + sect_idx * 40;
    if (offset + 40 > buf.size()) buf.resize(offset + 40, 0);
    
    // Name (up to 8 bytes, null-padded)
    uint8_t name_bytes[8] = {0};
    std::memcpy(name_bytes, name.c_str(), std::min(name.length(), (size_t)8));
    std::memcpy(&buf[offset], name_bytes, 8);
    
    write_u32(buf, offset + 8, v_size);
    write_u32(buf, offset + 12, v_addr);
    write_u32(buf, offset + 16, raw_size);
    write_u32(buf, offset + 20, raw_ptr);
    write_u32(buf, offset + 24, 0); // PointerToRelocations
    write_u32(buf, offset + 28, 0); // PointerToLinenumbers
    write_u16(buf, offset + 32, 0); // NumberOfRelocations
    write_u16(buf, offset + 34, 0); // NumberOfLinenumbers
    write_u32(buf, offset + 36, chars);
}

JitPeFile::JitPeFile(int arch, uint64_t base, const std::string& mod_name, const std::vector<std::string>& exports)
    : PeFile("", {}, 0xFEEDFACE, 4, "", true),
      pattern_size(arch == 32 ? 4 : 8) {
    this->arch = arch;
    this->base = base;
    
    // Correctly prepend DOS_HEADER and append trailing zeroes to match python EMPTY_PE_32/64
    raw_pe_data = (arch == 32) ? EMPTY_PE_32 : EMPTY_PE_64;

    parsed_pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(raw_pe_data.data()),
        static_cast<uint32_t>(raw_pe_data.size()));

    if(!parsed_pe) {
        throw PeParseException("Failed to parse initial PE template");
    }

    if (arch == 32) {
        parsed_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint = 0;
        parsed_pe->peHeader.nt.OptionalHeader.FileAlignment = 0x200;
        parsed_pe->peHeader.nt.OptionalHeader.SectionAlignment = 0x1000;
        if (base)
            parsed_pe->peHeader.nt.OptionalHeader.ImageBase = base;

        size_t pe_sig_offset = 0xB0;
        size_t coff_offset = pe_sig_offset + 4;
        size_t opt_offset = coff_offset + 20;
        write_u32(raw_pe_data, opt_offset + 16, 0);
        write_u32(raw_pe_data, opt_offset + 36, 0x200);
        write_u32(raw_pe_data, opt_offset + 32, 0x1000);
        if (base)
            write_u32(raw_pe_data, opt_offset + 28, static_cast<uint32_t>(base));
    }
    else {
        parsed_pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint = 0;
        parsed_pe->peHeader.nt.OptionalHeader64.FileAlignment = 0x200;
        parsed_pe->peHeader.nt.OptionalHeader64.SectionAlignment = 0x1000;
        if (base)
            parsed_pe->peHeader.nt.OptionalHeader64.ImageBase = base;

        size_t pe_sig_offset = 0xB0;
        size_t coff_offset = pe_sig_offset + 4;
        size_t opt_offset = coff_offset + 20;
        write_u32(raw_pe_data, opt_offset + 16, 0);
        write_u32(raw_pe_data, opt_offset + 36, 0x200);
        write_u32(raw_pe_data, opt_offset + 32, 0x1000);
        if (base) {
            write_u32(raw_pe_data, opt_offset + 24, static_cast<uint32_t>(base & 0xFFFFFFFF));
            write_u32(raw_pe_data, opt_offset + 28, static_cast<uint32_t>(base >> 32));
        }
    }

    update();

    if (!exports.empty()) {
        get_decoy_pe_image(mod_name, exports);
    }
}

int JitPeFile::get_section_count() {
    return static_cast<int>(pe_sections.size());
}

std::vector<uint8_t> JitPeFile::get_raw_pe() {
    return raw_pe_data;
}

void JitPeFile::update() {
    if (parsed_pe) {
        peparse::DestructParsedPE(parsed_pe);
        parsed_pe = nullptr;
    }
    // Re-parse the PE data to refresh sections
    parsed_pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(raw_pe_data.data()),
        static_cast<uint32_t>(raw_pe_data.size()));
    if (!parsed_pe) {
        std::fprintf(stderr, "[DEBUG] update: ParsePEFromPointer failed! raw_pe_data.size()=%d\n", (int)raw_pe_data.size());
        return;
    }
    
    sync_optional_header(parsed_pe);
    
    if (parsed_pe->peHeader.nt.OptionalMagic == 0x020b) {
        base = parsed_pe->peHeader.nt.OptionalHeader64.ImageBase;
    } else {
        base = parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
    }
    if (base == 0) { base = DEFAULT_LOAD_ADDR; }
    ep = parsed_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
    image_size = parsed_pe->peHeader.nt.OptionalHeader.SizeOfImage;
    stack_commit = parsed_pe->peHeader.nt.OptionalHeader.SizeOfStackCommit;
    ptr_size = (arch == 32) ? 4 : 8;
    
    pe_sections = _get_pe_sections();
    exports = _get_pe_exports();
    
    if (!pe_sections.empty()) {
        mapped_image = get_memory_mapped_image(0xF0000000);
        is_mapped = true;
    }
}

void JitPeFile::update_image_size() {
    if (raw_pe_data.size() < 0x40) return;
    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, &raw_pe_data[0x3C], sizeof(e_lfanew));
    if (raw_pe_data.size() < e_lfanew + 84) return;

    size_t pe_sig_offset = e_lfanew;
    size_t coff_offset = pe_sig_offset + 4;
    size_t opt_offset = coff_offset + 20;
    size_t opt_header_size = (arch == 32) ? 0xE0 : 0xF0;
    size_t section_table_offset = opt_offset + opt_header_size;

    uint16_t num_sections = read_u16(raw_pe_data, coff_offset + 2);
    uint32_t max_vaddr = 0x1000; // default for headers

    std::fprintf(stderr, "[DEBUG] update_image_size: num_sections=%d, raw_size=%d\n", (int)num_sections, (int)raw_pe_data.size());

    for (uint16_t i = 0; i < num_sections; ++i) {
        size_t sect_offset = section_table_offset + i * 40;
        if (sect_offset + 40 > raw_pe_data.size()) break;
        uint32_t v_size = read_u32(raw_pe_data, sect_offset + 8);
        uint32_t v_addr = read_u32(raw_pe_data, sect_offset + 12);
        uint32_t aligned_end = align_up(v_addr + v_size, 0x1000);
        std::fprintf(stderr, "[DEBUG]   Section %d: v_addr=0x%X, v_size=0x%X, aligned_end=0x%X\n", (int)i, (int)v_addr, (int)v_size, (int)aligned_end);
        if (aligned_end > max_vaddr) {
            max_vaddr = aligned_end;
        }
    }

    std::fprintf(stderr, "[DEBUG] update_image_size: writing SizeOfImage=0x%X at offset %d\n", (int)max_vaddr, (int)(e_lfanew + 80));
    std::memcpy(&raw_pe_data[e_lfanew + 80], &max_vaddr, sizeof(max_vaddr));
    
    update();
}

void JitPeFile::add_section(const std::string& name, uint32_t chars) {
    size_t pe_sig_offset = 0xB0;
    size_t coff_offset = pe_sig_offset + 4;
    size_t opt_offset = coff_offset + 20;
    
    size_t num_sections_offset = coff_offset + 2;
    size_t size_of_image_offset = opt_offset + 56;
    size_t size_of_headers_offset = opt_offset + 60;
    
    size_t opt_header_size = (arch == 32) ? 0xE0 : 0xF0;
    size_t section_table_offset = opt_offset + opt_header_size;
    
    uint16_t num_sections = read_u16(raw_pe_data, num_sections_offset);
    int new_sect_idx = num_sections;
    
    std::fprintf(stderr, "[DEBUG] add_section: '%s', num_sections: %d, opt_header_size: %d, section_table_offset: %d, raw_pe_data.size: %d\n",
                 name.c_str(), (int)num_sections, (int)opt_header_size, (int)section_table_offset, (int)raw_pe_data.size());
    
    // Increment NumberOfSections
    write_u16(raw_pe_data, num_sections_offset, num_sections + 1);
    
    // Expand SizeOfHeaders and SizeOfImage by 40 bytes
    uint32_t size_of_headers = read_u32(raw_pe_data, size_of_headers_offset);
    uint32_t size_of_image = read_u32(raw_pe_data, size_of_image_offset);
    
    std::fprintf(stderr, "[DEBUG] add_section: size_of_headers was %d, size_of_image was %d\n", (int)size_of_headers, (int)size_of_image);
    
    write_u32(raw_pe_data, size_of_headers_offset, size_of_headers + 40);
    write_u32(raw_pe_data, size_of_image_offset, size_of_image + 40);
    
    // Write the new empty section header
    write_section_header(raw_pe_data, section_table_offset, new_sect_idx, name, 0, 0, 0, 0, chars);
    
    std::fprintf(stderr, "[DEBUG] add_section: wrote header at offset %d, raw_pe_data.size: %d\n",
                 (int)(section_table_offset + new_sect_idx * 40), (int)raw_pe_data.size());
    
    update();
}

void JitPeFile::pad_file() {
    size_t cur_offset = raw_pe_data.size();
    size_t aligned_offset = align_up(static_cast<uint32_t>(cur_offset), 0x200);
    if (aligned_offset > cur_offset) {
        raw_pe_data.resize(aligned_offset, 0);
    }
}

int JitPeFile::get_current_offset() {
    return static_cast<int>(raw_pe_data.size());
}

void JitPeFile::append_data(const std::vector<uint8_t>& data) {
    raw_pe_data.insert(raw_pe_data.end(), data.begin(), data.end());
}

int JitPeFile::get_exports_size(const std::string& name, const std::vector<std::pair<uint32_t, std::string>>& exports_info) {
    size_t num_funcs = exports_info.size();
    size_t size = 40; // Size of IMAGE_EXPORT_DIRECTORY
    size += name.length() + 1;
    for (const auto& exp : exports_info) {
        size += exp.second.length() + 1;
        size += 10; // funcs (4) + names (4) + ordinals (2)
    }
    // Loop fluff to pass forwarded export checks
    size += num_funcs * num_funcs;
    return static_cast<int>(size);
}

void JitPeFile::init_export_section(const std::string& name, const std::vector<std::pair<uint32_t, std::string>>& exports_info) {
    size_t pe_sig_offset = 0xB0;
    size_t coff_offset = pe_sig_offset + 4;
    size_t opt_offset = coff_offset + 20;
    size_t opt_header_size = (arch == 32) ? 0xE0 : 0xF0;
    size_t section_table_offset = opt_offset + opt_header_size;
    
    size_t size_of_init_data_offset = opt_offset + 8;
    size_t export_dir_offset = (arch == 32) ? opt_offset + 96 : opt_offset + 112;
    
    // Find .edata and .text section headers
    int edata_sect_idx = -1;
    int text_sect_idx = -1;
    uint16_t num_sections = read_u16(raw_pe_data, coff_offset + 2);
    for (int i = 0; i < num_sections; ++i) {
        size_t offset = section_table_offset + i * 40;
        char sect_name[9] = {0};
        std::memcpy(sect_name, &raw_pe_data[offset], 8);
        if (std::string(sect_name) == ".edata") {
            edata_sect_idx = i;
        } else if (std::string(sect_name) == ".text") {
            text_sect_idx = i;
        }
    }
    
    if (edata_sect_idx == -1 || text_sect_idx == -1) return;
    
    // Read text section virtual size and virtual address
    size_t text_off = section_table_offset + text_sect_idx * 40;
    uint32_t text_v_size = read_u32(raw_pe_data, text_off + 8);
    uint32_t text_v_addr = read_u32(raw_pe_data, text_off + 12);
    
    uint32_t sa = 0x1000; // SectionAlignment
    uint32_t text_aligned_size = align_up(text_v_size, sa);
    uint32_t sec_rva = text_v_addr + text_aligned_size;
    
    int exports_size = get_exports_size(name, exports_info);
    size_t cur_offset = raw_pe_data.size();
    
    // Update .edata section header
    write_section_header(raw_pe_data, section_table_offset, edata_sect_idx, ".edata",
                         static_cast<uint32_t>(exports_size), sec_rva,
                         align_up(static_cast<uint32_t>(exports_size), 0x200),
                         static_cast<uint32_t>(cur_offset), 0x40000040);
    
    // Update SizeOfInitializedData
    uint32_t size_of_init_data = read_u32(raw_pe_data, size_of_init_data_offset);
    write_u32(raw_pe_data, size_of_init_data_offset, size_of_init_data + exports_size);
    
    // Update Export Directory RVA and Size
    write_u32(raw_pe_data, export_dir_offset, sec_rva);
    write_u32(raw_pe_data, export_dir_offset + 4, static_cast<uint32_t>(exports_size));
    
    // Generate edata_data containing IMAGE_EXPORT_DIRECTORY and tables
    std::vector<uint8_t> edata_data(exports_size, 0);
    
    size_t num_funcs = exports_info.size();
    size_t funcs_offset = 40;
    size_t names_offset = funcs_offset + 4 * num_funcs;
    size_t ords_offset = names_offset + 4 * num_funcs;
    size_t dll_name_offset = ords_offset + 2 * num_funcs;
    size_t strings_offset = dll_name_offset + name.length() + 1;
    
    // Initialize IMAGE_EXPORT_DIRECTORY structure
    write_u32(edata_data, 0, 0); // Characteristics
    write_u32(edata_data, 4, 0xD1234567); // TimeDateStamp
    write_u16(edata_data, 8, 0); // Major
    write_u16(edata_data, 10, 0); // Minor
    write_u32(edata_data, 12, sec_rva + static_cast<uint32_t>(dll_name_offset)); // DLL Name string RVA
    write_u32(edata_data, 16, 1); // Base ordinal = 1
    write_u32(edata_data, 20, static_cast<uint32_t>(num_funcs)); // NumberOfFunctions
    write_u32(edata_data, 24, static_cast<uint32_t>(num_funcs)); // NumberOfNames
    write_u32(edata_data, 28, sec_rva + static_cast<uint32_t>(funcs_offset)); // AddressOfFunctions RVA
    write_u32(edata_data, 32, sec_rva + static_cast<uint32_t>(names_offset)); // AddressOfNames RVA
    write_u32(edata_data, 36, sec_rva + static_cast<uint32_t>(ords_offset)); // AddressOfNameOrdinals RVA
    
    // Write DLL name
    std::memcpy(&edata_data[dll_name_offset], name.c_str(), name.length() + 1);
    
    // Write functions table, names table, ordinals table, and string table
    size_t curr_str_offset = strings_offset;
    for (size_t i = 0; i < num_funcs; ++i) {
        uint32_t func_rva = exports_info[i].first;
        std::string func_name = exports_info[i].second;
        
        write_u32(edata_data, funcs_offset + i * 4, func_rva);
        write_u16(edata_data, ords_offset + i * 2, static_cast<uint16_t>(i));
        write_u32(edata_data, names_offset + i * 4, sec_rva + static_cast<uint32_t>(curr_str_offset));
        
        std::memcpy(&edata_data[curr_str_offset], func_name.c_str(), func_name.length() + 1);
        curr_str_offset += func_name.length() + 1;
    }
    
    // Append edata_data to raw_pe_data
    raw_pe_data.insert(raw_pe_data.end(), edata_data.begin(), edata_data.end());
    
    update();
}

std::vector<std::pair<uint32_t, std::string>> JitPeFile::init_text_section(const std::vector<std::string>& names) {
    std::vector<std::pair<uint32_t, std::string>> exports_info;
    std::vector<uint8_t> pattern;
    
    size_t pe_sig_offset = 0xB0;
    size_t coff_offset = pe_sig_offset + 4;
    size_t opt_offset = coff_offset + 20;
    size_t ep_offset = opt_offset + 16;
    size_t opt_header_size = (arch == 32) ? 0xE0 : 0xF0;
    size_t section_table_offset = opt_offset + opt_header_size;
    
    // Find .text section header in sections
    int text_sect_idx = -1;
    uint16_t num_sections = read_u16(raw_pe_data, coff_offset + 2);
    for (int i = 0; i < num_sections; ++i) {
        size_t offset = section_table_offset + i * 40;
        char sect_name[9] = {0};
        std::memcpy(sect_name, &raw_pe_data[offset], 8);
        if (std::string(sect_name) == ".text") {
            text_sect_idx = i;
            break;
        }
    }
    
    if (text_sect_idx == -1) return exports_info;
    
    size_t cur_offset = raw_pe_data.size();
    uint32_t sec_rva = align_up(static_cast<uint32_t>(cur_offset), 0x1000);
    if (sec_rva == 0) sec_rva = 0x1000;
    
    auto& stub_template = (arch == 32) ? X86_EXPORTED_FUNCTION : X64_EXPORTED_FUNCTION;
    size_t val_offset = (arch == 32) ? 6 : 7;
    
    for (size_t i = 0; i < names.size(); ++i) {
        uint32_t func_rva = sec_rva + static_cast<uint32_t>(pattern.size());
        exports_info.push_back({func_rva, names[i]});
        
        std::vector<uint8_t> stub = stub_template;
        uint32_t ret_val = static_cast<uint32_t>(i + 1);
        std::memcpy(&stub[val_offset], &ret_val, 4);
        
        pattern.insert(pattern.end(), stub.begin(), stub.end());
    }
    
    // Update section header
    write_section_header(raw_pe_data, section_table_offset, text_sect_idx, ".text",
                         static_cast<uint32_t>(pattern.size()), sec_rva,
                         align_up(static_cast<uint32_t>(pattern.size()), 0x200),
                         static_cast<uint32_t>(cur_offset), 0x60000020);
    
    // Update AddressOfEntryPoint
    write_u32(raw_pe_data, ep_offset, sec_rva);
    
    // Update SizeOfHeaders to aligned headers size
    size_t size_of_headers_offset = opt_offset + 60;
    write_u32(raw_pe_data, size_of_headers_offset, static_cast<uint32_t>(cur_offset));
    
    if (!pattern.empty()) {
        // Append pattern data
        raw_pe_data.insert(raw_pe_data.end(), pattern.begin(), pattern.end());
    }
    
    update();
    return exports_info;
}

void* JitPeFile::cast_section(int offset) {
    (void)offset;
    return nullptr;
}

std::vector<uint8_t> JitPeFile::get_decoy_pe_image(const std::string& mod_name,
                                                const std::vector<std::string>& exports) {
    add_section(".text", 0x60000020);
    add_section(".edata", 0x40000040);
    pad_file();
    
    auto exports_info = init_text_section(exports);
    pad_file();
    
    init_export_section(mod_name, exports_info);
    update_image_size();
    
    return raw_pe_data;
}
