// loaders.cpp — PE file loader implementation using pe-parse callback API

#include "loaders.h"
#include "../winenv/api/api.h"
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <algorithm>


namespace speakeasy {

// ── PE Section characteristics ───────────────────────────────

constexpr uint32_t IMAGE_SCN_MEM_READ    = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

// ── Callback context for pe-parse iterations ─────────────────

struct ParseCtx {
    std::vector<SectionEntry> sections;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;
    std::vector<uint64_t> tls_callbacks;
    std::vector<ResourceEntry> resources;
    uint64_t ep = 0;
    uint32_t machine = 0;
    uint32_t magic = 0;
    uint32_t subsystem = 0;
    uint32_t timestamp = 0;
    uint64_t image_base = 0;
    uint32_t image_size = 0;
    uint32_t section_align = 0;
    int arch = 32;
};

// ── Section callback ─────────────────────────────────────────

static int sec_cb(void* cbd,
                  const peparse::VA& sec_base,
                  const std::string& sec_name,
                  const peparse::image_section_header& sec,
                  const peparse::bounded_buffer* sec_data) {
    auto* ctx = static_cast<ParseCtx*>(cbd);
    (void)sec_base;

    SectionEntry entry;
    entry.name = sec_name;
    // Trim trailing nulls/spaces
    auto end = entry.name.find_last_not_of(" \t\0");
    if (end != std::string::npos) entry.name.erase(end + 1);
    entry.virtual_address = sec.VirtualAddress;
    entry.virtual_size = sec.Misc.VirtualSize;
    entry.perms = perms_from_section_chars(sec.Characteristics);

    if (sec_data) {
        // Section data available via bounded_buffer
        // We don't store it here — it'll be assembled in make_image
    }
    ctx->sections.push_back(entry);
    return 0;  // continue iteration
}

// ── Import callback ──────────────────────────────────────────

static int imp_cb(void* cbd,
                  const peparse::VA& iat_addr,
                  const std::string& mod_name,
                  const std::string& sym_name) {
    auto* ctx = static_cast<ParseCtx*>(cbd);

    ImportEntry entry;
    entry.iat_address = iat_addr;
    entry.dll_name = mod_name;
    // Strip file extension at the last dot
    auto dot = entry.dll_name.rfind('.');
    if (dot != std::string::npos) {
        entry.dll_name = entry.dll_name.substr(0, dot);
    }
    entry.func_name = sym_name.empty() ? "unknown" : sym_name;
    ctx->imports.push_back(entry);
    return 0;
}

// ── Export callback ──────────────────────────────────────────

static int exp_cb(void* cbd,
                  const peparse::VA& addr,
                  std::uint16_t ordinal,
                  const std::string& name,
                  const std::string& /*forward*/,
                  const std::string& mod_name) {
    auto* ctx = static_cast<ParseCtx*>(cbd);

    ExportEntry entry;
    entry.name = name;
    entry.address = addr;
    entry.ordinal = ordinal;
    entry.execution_mode = ctx->subsystem == 1 ? "kernel" : "user";
    (void)mod_name;
    ctx->exports.push_back(entry);
    return 0;
}

// ── Resource callback ────────────────────────────────────────

static int rsrc_cb(void* cbd, const peparse::resource& r) {
    auto* ctx = static_cast<ParseCtx*>(cbd);
    ResourceEntry entry;
    entry.id = static_cast<int>(r.name);
    entry.type_id = static_cast<int>(r.type);
    entry.data_rva = r.RVA;
    entry.size = r.size;
    entry.lang_id = static_cast<int>(r.lang);
    entry.entry_rva = r.RVA;
    ctx->resources.push_back(entry);
    return 0;
}

// ── Helper: read BYTE at RVA from PE raw data ───────────────

/**
 * Read a single byte at a given Virtual Address from the parsed PE.
 * Returns false if the address is out of range.
 */
/*
static bool read_byte_at_va(peparse::parsed_pe* pe, uint64_t va,
                            uint8_t& out) {
    peparse::VA va_struct;
    va_struct = va;
    (void)va_struct;
    return peparse::ReadByteAtVA(pe, peparse::VA(va), out);
}
*/

/**
 * Read N bytes at a given Virtual Address using repeated ReadByteAtVA.
 * Returns the bytes read (may be fewer than `size` if out-of-range).
 */
static std::vector<uint8_t> read_bytes_at_va(peparse::parsed_pe* pe,
                                              uint64_t addr, size_t size) {
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i) {
        uint8_t b = 0;
        if (peparse::ReadByteAtVA(pe, peparse::VA(addr + i), b))
            data.push_back(b);
        else
            break;
    }
    return data;
}

// ── PeLoader implementation ─────────────────────────────────

PeLoader::PeLoader(const std::string& path, 
    const std::vector<uint8_t>& data,
    int base_override,
    const std::string& emu_path)
    : path_(path), 
    data_(data),
    pefile(path, data),
    base_override_(base_override), 
    emu_path_(emu_path) {
}

PeLoader::~PeLoader() {
}

void PeLoader::parse_pe() {
    ParseCtx ctx;

    peparse::parsed_pe* pe = pefile.get_parsed_pe();
    if (!pe)
        return;

    // Read PE header fields
    metadata_.machine = pe->peHeader.nt.FileHeader.Machine;
    ctx.machine = metadata_.machine;
    metadata_.magic = pe->peHeader.nt.OptionalMagic;
    ctx.magic = metadata_.magic;
    metadata_.subsystem = pe->peHeader.nt.OptionalHeader.Subsystem;
    ctx.subsystem = metadata_.subsystem;
    metadata_.timestamp = pe->peHeader.nt.FileHeader.TimeDateStamp;
    ctx.timestamp = metadata_.timestamp;

    // Architecture
    ctx.arch = (metadata_.machine == 0x8664) ? 64 : 32;  // IMAGE_FILE_MACHINE_AMD64

    // Image base and size
    ctx.image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
    ctx.image_size = pe->peHeader.nt.OptionalHeader.SizeOfImage;
    ctx.section_align = pe->peHeader.nt.OptionalHeader.SectionAlignment;

    // Entry point
    peparse::VA ep_va;
    if (peparse::GetEntryPoint(pe, ep_va)) {
        ctx.ep = static_cast<uint64_t>(ep_va);
    }

    // Iterate sections
    peparse::IterSec(pe, sec_cb, &ctx);
    sections_ = ctx.sections;

    // Iterate imports
    peparse::IterImpVAString(pe, imp_cb, &ctx);
    imports_ = ctx.imports;

    // Iterate exports (use IterExpFull for full info including ordinal)
    peparse::IterExpFull(pe, exp_cb, &ctx);
    exports_ = ctx.exports;

    // Iterate resources
    peparse::IterRsrc(pe, rsrc_cb, &ctx);
    metadata_.resources = ctx.resources;

    // TLS callbacks — parse TLS directory
    auto tls_dir = pe->peHeader.nt.OptionalHeader.DataDirectory[9];
    if (tls_dir.VirtualAddress != 0) {
        uint64_t callbacks_rva = 0;
        int ptr_size = (ctx.arch == 64) ? 8 : 4;
        tls_directory_rva_ = tls_dir.VirtualAddress;

        // Read TLS directory: StartAddressOfRawData (ptr), EndAddressOfRawData (ptr),
        // AddressOfIndex (ptr), AddressOfCallBacks (ptr), ...
        // AddressOfCallBacks is at offset 3*ptr_size within TLS dir
        auto tls_data = read_bytes_at_va(pe, tls_dir.VirtualAddress,
                                         4 * ptr_size + ptr_size);
        if (tls_data.size() >= 4 * ptr_size) {
            // AddressOfCallBacks at offset 3*ptr_size
            for (int j = 3 * ptr_size; j < 4 * ptr_size && j + ptr_size <= (int)tls_data.size(); ++j) {
                callbacks_rva |= static_cast<uint64_t>(tls_data[j]) << ((j - 3 * ptr_size) * 8);
            }
        }

        // Read callback pointers until null
        if (callbacks_rva != 0) {
            for (int i = 0; i < 100; ++i) {
                auto ptr_data = read_bytes_at_va(pe, callbacks_rva + i * ptr_size, ptr_size);
                if (ptr_data.size() < (size_t)ptr_size) break;
                uint64_t ptr = 0;
                for (int j = 0; j < ptr_size; ++j)
                    ptr |= static_cast<uint64_t>(ptr_data[j]) << (j * 8);
                if (ptr == 0) break;
                tls_callbacks_.push_back(ptr);
            }
        }
    }

}

std::shared_ptr<LoadedImage> PeLoader::make_image() {
    auto img = std::make_shared<LoadedImage>();

    auto* pe = pefile.get_parsed_pe();
    if (!pe)
        return img;

    parse_pe();

    if (base_override_ && (base_override_ != pefile.base)) {
        pefile.rebase(base_override_);
    }

    img->module_type = "exe";
    if(pefile.is_driver())
        img->module_type = "driver";
    else if(pefile.is_dll())
        img->module_type = "dll";

    //auto mapped_image = pefile.get_memory_mapped_image(0xF0000000);

    uint64_t image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
    uint64_t image_size = pe->peHeader.nt.OptionalHeader.SizeOfImage;
    //uint32_t section_align = pe->peHeader.nt.OptionalHeader.SectionAlignment;
    //uint32_t file_align = pe->peHeader.nt.OptionalHeader.FileAlignment;

    // Copy PE headers
    //uint32_t header_size = pe->peHeader.nt.OptionalHeader.SizeOfHeaders;
    //img->mapped_image.assign(data_.begin(),
    //                        data_.begin() + std::min(header_size, static_cast<uint32_t>(data_.size())));

    //// Pad to section alignment after header
    //while (img->mapped_image.size() % section_align != 0) {
    //    img->mapped_image.push_back(0);
    //}

    // Collect section info from iteration
    struct SectionRaw {
        std::string name;
        uint32_t va;
        uint32_t vsize;
        uint32_t raw_ptr;
        uint32_t raw_size;
        uint32_t chars;
    };
    std::vector<SectionRaw> sec_raws;

    // Lambda for section iteration
    auto sec_iter = [](void* cbd, const peparse::VA& /*base*/,
                        const std::string& name,
                        const peparse::image_section_header& hdr,
                        const peparse::bounded_buffer* /*data*/) -> int {
        auto* vec = static_cast<std::vector<SectionRaw>*>(cbd);
        vec->push_back({name, hdr.VirtualAddress, hdr.Misc.VirtualSize,
                        hdr.PointerToRawData, hdr.SizeOfRawData,
                        hdr.Characteristics});
        return 0;
    };

    peparse::IterSec(pe, sec_iter, &sec_raws);

    // Add section data at their virtual addresses
    //for (auto& sec : sec_raws) {
    //    // Pad to virtual address
    //    while (img->mapped_image.size() < sec.va) {
    //        img->mapped_image.push_back(0);
    //    }

    //    // Copy raw section data
    //    if (sec.raw_ptr > 0 && sec.raw_ptr < data_.size() && sec.raw_size > 0) {
    //        size_t copy_size = std::min(static_cast<size_t>(sec.raw_size),
    //                                    data_.size() - sec.raw_ptr);
    //        img->mapped_image.insert(img->mapped_image.end(),
    //                                data_.begin() + sec.raw_ptr,
    //                                data_.begin() + sec.raw_ptr + copy_size);
    //    }

    //    // Pad to virtual size
    //    while (img->mapped_image.size() < sec.va + sec.vsize) {
    //        img->mapped_image.push_back(0);
    //    }
    //}

    MemoryRegion region;
    region.base = image_base;
    region.data = pefile.mapped_image;
    region.name = "pe_image";
    region.perms = 0x16;  // PERM_MEM_RWX
    img->regions.push_back(region);

    // Ensure full image size
    //while (img->mapped_image.size() < image_size) {
    //    img->mapped_image.push_back(0);
    //}


    // Fill metadata
    img->name = path_.empty() ? "unknown" :
        path_.substr(path_.find_last_of("/\\") + 1);
    auto dot = img->name.rfind('.');
    if (dot != std::string::npos) img->name.erase(dot);

    img->emu_path = path_;
    img->image_size = image_size;
    img->base = image_base;
    img->ep = pe ? pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint : 0;
    img->stack_size = pe ? pe->peHeader.nt.OptionalHeader.SizeOfStackReserve : 0x12000;
    img->arch = (metadata_.machine == 0x8664) ? 64 : 32;
    img->metadata = metadata_;
    img->imports = imports_;
    img->exports = exports_;
    img->sections = sections_;
    img->tls_callbacks = tls_callbacks_;
    img->tls_directory_va = tls_directory_rva_ + image_base;
    img->loader = this;

    return img;
}

uint32_t PeLoader::perms_from_section_chars(uint32_t chars) {
    uint32_t perms = 0;
    if (chars & IMAGE_SCN_MEM_READ)    perms |= 0x02;
    if (chars & IMAGE_SCN_MEM_WRITE)   perms |= 0x04;
    if (chars & IMAGE_SCN_MEM_EXECUTE) perms |= 0x10;
    return perms;
}

std::string PeLoader::get_prot_string(uint32_t perms) {
    std::string s;
    s += (perms & 0x02) ? 'r' : '-';
    s += (perms & 0x04) ? 'w' : '-';
    s += (perms & 0x10) ? 'x' : '-';
    return s;
}


// ── RuntimeModule ─────────────────────────────────────────

RuntimeModule::RuntimeModule(std::shared_ptr<speakeasy::LoadedImage> image) : _image(image) {
    if (!image) return;
    base = image->base;
    image_size = image->image_size;
    ep = image->ep;
    arch = image->arch;
    emu_path = image->emu_path;
    path = image->emu_path;
    name = image->name;
    sections = image->sections;
    exports_ = image->exports;
    tls_callbacks_ = image->tls_callbacks;
    metadata_ = image->metadata;
    stack_commit = 0x1000;  // default

    // Derive module_type from PE characteristics
    if (image->is_decoy) module_type = "decoy";
    else if (image->is_driver) module_type = "driver";
    else if (image->is_dll) module_type = "dll";
    else module_type = "exe";
}

bool RuntimeModule::is_exe() const { return module_type == "exe"; }
bool RuntimeModule::is_dll() const { return module_type == "dll"; }
bool RuntimeModule::is_driver() const { return module_type == "driver"; }
bool RuntimeModule::is_decoy() const { return module_type == "decoy"; }

std::string RuntimeModule::get_base_name() const {
    auto pos = emu_path.find_last_of("/\\");
    return (pos != std::string::npos) ? emu_path.substr(pos + 1) : emu_path;
}

const std::vector<ExportEntry>& RuntimeModule::get_exports() const { return exports_; }

const ExportEntry* RuntimeModule::get_export_by_name(const std::string& exp_name) const {
    for (const auto& exp : exports_) {
        if (exp.name == exp_name) return &exp;
    }
    return nullptr;
}

const SectionEntry* RuntimeModule::get_section_for_addr(uint64_t addr) const {
    uint64_t offset = addr - base;
    for (const auto& sect : sections) {
        if (sect.virtual_address <= offset &&
            offset < (uint64_t)sect.virtual_address + sect.virtual_size)
            return &sect;
    }
    return nullptr;
}

const std::vector<uint64_t>& RuntimeModule::get_tls_callbacks() const { return tls_callbacks_; }

const PeMetadata* RuntimeModule::get_pe_metadata() const { return &metadata_; }

std::string RuntimeModule::to_string() const {
    return "RuntimeModule(" + name + " at 0x" + 
           std::to_string(base) + ")";
}

// ── ShellcodeLoader ──────────────────────────────────────

ShellcodeLoader::ShellcodeLoader(const std::vector<uint8_t>& data, int arch)
    : data_(data), arch_(arch) {}

std::shared_ptr<LoadedImage> ShellcodeLoader::make_image() {
    auto img = std::make_shared<LoadedImage>();
    img->arch = arch_;
    img->name = "shellcode";
    img->emu_path = "";
    img->base = 0;
    img->image_size = data_.size();
    img->ep = 0;

    MemoryRegion region;
    region.base = 0;
    region.data = data_;
    region.name = "shellcode";
    region.perms = 0x16;  // PERM_MEM_RWX
    img->regions.push_back(region);

    SectionEntry sect;
    sect.name = "shellcode";
    sect.virtual_address = 0;
    sect.virtual_size = static_cast<uint32_t>(data_.size());
    sect.perms = 0x16;
    img->sections.push_back(sect);

    return img;
}

// ── ApiModuleLoader ──────────────────────────────────────

ApiModuleLoader::ApiModuleLoader(const std::string& name, void* api,
                                 int arch, uint64_t base, const std::string& emu_path)
    : name_(name), api_(api), arch_(arch), base_(base), emu_path_(emu_path) {}

std::shared_ptr<LoadedImage> ApiModuleLoader::make_image() {
    std::vector<std::string> all_exports;
    
    auto* handler = static_cast<ApiHandler*>(api_);
    if (handler) {
        const auto& hook_funcs = handler->get_hook_funcs();
        const auto& hook_data = handler->get_hook_data();
        
        std::vector<std::pair<int, std::string>> new_funcs;
        for (const auto& [k, f] : hook_funcs) {
            new_funcs.push_back({f.ordinal, f.name});
        }
        
        std::vector<std::string> data_exports;
        for (const auto& [k, d] : hook_data) {
            data_exports.push_back(d.name);
        }
        
        // Prefix / Suffix Expansion matching Python logic
        std::vector<std::pair<int, std::string>> expanded = new_funcs;
        if (name_ == "ntdll" || name_ == "ntoskrnl") {
            for (const auto& f : new_funcs) {
                std::string fn = f.second;
                if (fn.rfind("Nt", 0) == 0) { // startswith "Nt"
                    expanded.push_back({0, "Zw" + fn.substr(2)});
                } else if (fn.rfind("Zw", 0) == 0) { // startswith "Zw"
                    expanded.push_back({0, "Nt" + fn.substr(2)});
                }
            }
        } else {
            for (const auto& f : new_funcs) {
                std::string fn = f.second;
                expanded.push_back({0, fn + "A"});
                expanded.push_back({0, fn + "W"});
            }
        }
        
        std::vector<std::string> func_names;
        for (const auto& f : expanded) {
            func_names.push_back(f.second);
        }
        std::sort(func_names.begin(), func_names.end());
        func_names.erase(std::unique(func_names.begin(), func_names.end()), func_names.end());
        
        std::vector<int> ords;
        for (const auto& f : new_funcs) {
            if (f.first > 0) {
                ords.push_back(f.first);
            }
        }
        
        if (!ords.empty()) {
            int max_ord = *std::max_element(ords.begin(), ords.end());
            int num_exports = max_ord + 1;
            all_exports.resize(num_exports);
            for (int i = 0; i < num_exports; ++i) {
                all_exports[i] = "ordinal_" + std::to_string(i + 1);
            }
            for (const auto& f : new_funcs) {
                if (f.first > 0) {
                    all_exports[f.first - 1] = f.second;
                }
            }
            for (const auto& fn : func_names) {
                if (std::find(all_exports.begin(), all_exports.end(), fn) == all_exports.end()) {
                    all_exports.push_back(fn);
                }
            }
        }
        
        if (all_exports.empty()) {
            all_exports = func_names;
        }
        
        // Append data exports
        all_exports.insert(all_exports.end(), data_exports.begin(), data_exports.end());
    }
    
    // Construct dynamic PE using C++ JitPeFile
    JitPeFile jit(arch_, base_);
    std::vector<uint8_t> raw_pe = jit.get_decoy_pe_image(name_, all_exports);
    
    // Parse using PeFile to map and resolve section and header details
    std::shared_ptr<PeFile> pe;
    try {
        pe = std::make_shared<PeFile>("", raw_pe, 0xFEEDFACE, 4, emu_path_, true);
    } catch (const std::exception& e) {
        return nullptr;
    } catch (...) {
        return nullptr;
    }
    
    auto img = std::make_shared<LoadedImage>();
    img->arch = arch_;
    img->module_type = "dll";
    img->name = name_;
    img->emu_path = emu_path_;
    img->base = base_;
    img->image_size = pe->get_image_size();
    img->is_dll = true;
    img->visible_in_peb = true;
    img->loader = this;
    
    // Create memory region from mapped PE image
    MemoryRegion region;
    region.base = base_;
    region.data = pe->mapped_image;
    region.name = "api_module";
    region.perms = 0x16; // PERM_MEM_RWX
    img->regions.push_back(region);
    
    // Create export table stub entries
    size_t stub_size = (arch_ == 32) ? 17 : 16;
    uint32_t text_va = 0x1000; // text section RVA is always 0x1000 in dynamic JIT PEs
    
    for (size_t i = 0; i < all_exports.size(); ++i) {
        ExportEntry exp;
        exp.name = all_exports[i];
        exp.address = base_ + text_va + i * stub_size;
        exp.ordinal = static_cast<uint32_t>(i + 1);
        exp.execution_mode = "intercepted";
        img->exports.push_back(exp);
    }
    
    // Add section entries
    for (const auto& s : pe->get_sections()) {
        SectionEntry sect;
        sect.name = s.name;
        sect.virtual_address = s.virtual_address;
        sect.virtual_size = s.virtual_size;
        sect.perms = 0x16; // RWX
        img->sections.push_back(sect);
    }
    
    // Populate metadata
    PeMetadata meta;
    if (pe->get_parsed_pe()) {
        meta.subsystem = pe->get_parsed_pe()->peHeader.nt.OptionalHeader.Subsystem;
        meta.timestamp = pe->get_parsed_pe()->peHeader.nt.FileHeader.TimeDateStamp;
        meta.machine = pe->get_parsed_pe()->peHeader.nt.FileHeader.Machine;
        meta.magic = pe->get_parsed_pe()->peHeader.nt.OptionalMagic;
    }
    img->metadata = meta;
    
    return img;
}

// ── DecoyLoader ──────────────────────────────────────────

DecoyLoader::DecoyLoader(const std::string& name, uint64_t base,
                         const std::string& emu_path, uint64_t image_size)
    : name_(name), base_(base), emu_path_(emu_path), image_size_(image_size) {}

std::shared_ptr<LoadedImage> DecoyLoader::make_image() {
    auto img = std::make_shared<LoadedImage>();
    img->arch = 0;
    img->module_type = "decoy";
    img->name = name_;
    img->emu_path = emu_path_;
    img->base = base_;
    img->image_size = image_size_;
    img->ep = 0;
    img->is_decoy = true;

    PeMetadata meta;
    meta.subsystem = 2;  // IMAGE_SUBSYSTEM_WINDOWS_GUI
    meta.timestamp = 0;
    meta.machine = 0;
    meta.magic = 0;
    img->metadata = meta;

    return img;
}
} // namespace speakeasy
