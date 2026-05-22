// common.cpp — Windows emulation common utilities
#include "common.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <pe-parse/parse.h>
#include <pe-parse/nt-headers.h>

#include <picosha2.h>

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

// ── Import callback ──────────────────────────────────────
struct PeImportCtx {
    std::map<uint64_t, std::tuple<std::string, std::string>> imports;
};
static int pefile_imp_cb(void* cbd, const peparse::VA& iat_addr,
                         const std::string& mod_name,
                         const std::string& sym_name) {
    auto* ctx = static_cast<PeImportCtx*>(cbd);
    std::string dll = mod_name;
    auto dot = dll.rfind(".dll");
    if (dot != std::string::npos) dll.erase(dot);
    if (dot == std::string::npos) {
        dot = dll.rfind(".DLL");
        if (dot != std::string::npos) dll.erase(dot);
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
    auto* ctx = static_cast<PeSectionCtx*>(cbd);
    PeSection s;
    s.name = std::string((const char*)sec.Name, 8);
    auto nul = s.name.find('\0');
    if (nul != std::string::npos) s.name.erase(nul);
    s.virtual_address = sec_base - ctx->image_base;
    s.virtual_size = sec.Misc.VirtualSize;
    s.raw_size = sec.SizeOfRawData;
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
    // Load PE data
    std::vector<uint8_t> pe_data;
    if (!data.empty()) {
        pe_data = data;
        file_size = data.size();
    } else {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) throw PeParseException("Cannot open: " + path);
        file_size = f.tellg();
        f.seekg(0);
        pe_data.resize(file_size);
        f.read((char*)pe_data.data(), file_size);
    }
    
    try {
        // Parse with pe-parse
        parsed_pe = peparse::ParsePEFromPointer(
            const_cast<uint8_t*>(pe_data.data()),
            static_cast<uint32_t>(pe_data.size()));
        if (!parsed_pe) throw PeParseException("Failed to parse PE");
        
        // Compute hash
        hash = _hash_pe(path, pe_data);
        
        // Header fields
        base = parsed_pe->peHeader.nt.OptionalHeader.ImageBase;
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
        // GetRealImage not in pe-parse; skip mapped image
        is_mapped = true;
        
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
    return {}; // TLS via pe-parse callback deferred
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

std::string PeFile::_hash_pe(const std::string& path, const std::vector<uint8_t>& data) {
    (void)path;
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
    ctx.image_base = base;
    peparse::IterSec(parsed_pe, pefile_sec_cb, &ctx);
    return ctx.sections;
}

std::vector<PeSection> PeFile::get_sections() {
    if (pe_sections.empty()) pe_sections = _get_pe_sections();
    return pe_sections;
}

PeSection* PeFile::get_section_by_name(const std::string& name) {
    auto sects = get_sections();
    for (auto& s : sects) {
        if (s.name == name) return &s;
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

uint64_t PeFile::get_export_by_name(const std::string& name) {
    for (auto& e : get_exports()) {
        if (e.name == name) return e.address;
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
    // pe-parse exposes base relocation callback
    return false; // defer to pe-parse IterRelocs
}

void PeFile::rebase(uint64_t to) {
    // pe-parse doesn't support relocation rewrite
    base = to;
    ep = 0; // re-read from PE if needed
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

// ── JitPeFile implementation ──────────────────────────────

JitPeFile::JitPeFile(int arch)
    : pattern_size(arch == 32 ? 4 : 8), arch(arch) {
    basepe_data = (arch == 32) ? EMPTY_PE_32 : EMPTY_PE_64;
    update();
}

PeSection* JitPeFile::get_section_by_name(const std::string& name) {
    for (auto& s : sections) {
        if (s.name == name) return &s;
    }
    return nullptr;
}

int JitPeFile::get_section_count() {
    return static_cast<int>(sections.size());
}

std::vector<PeSection> JitPeFile::get_sections() {
    return sections;
}

std::vector<uint8_t> JitPeFile::get_raw_pe() {
    return basepe_data;
}

void JitPeFile::update() {
    // Re-parse the PE data to refresh sections
    auto* pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(basepe_data.data()),
        static_cast<uint32_t>(basepe_data.size()));
    if (!pe) return;
    PeSectionCtx ctx;
    ctx.image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
    peparse::IterSec(pe, pefile_sec_cb, &ctx);
    peparse::DestructParsedPE(pe);
    sections = ctx.sections;
}

void JitPeFile::add_section(const std::string& name, const std::vector<uint8_t>& data) {
    // Append section data to the raw PE buffer
    basepe_data.insert(basepe_data.end(), data.begin(), data.end());
    // Re-parse to refresh PE headers and section list
    update();
    // Ensure the new section appears in our list even if raw PE parsing
    // doesn't capture it immediately — add fallback entry
    bool found = false;
    for (auto& s : sections) {
        if (s.name == name) { found = true; break; }
    }
    if (!found) {
        PeSection sec;
        sec.name = name;
        sec.virtual_address = 0;
        sec.virtual_size = static_cast<uint32_t>(data.size());
        sec.raw_size = static_cast<uint32_t>(data.size());
        sections.push_back(sec);
    }
}
