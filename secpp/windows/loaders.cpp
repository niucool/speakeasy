// loaders.cpp — PE file loader implementation using pe-parse callback API

#include "loaders.h"
#include <fstream>
#include <cstring>
#include <stdexcept>
#include <algorithm>

#include <pe-parse/parse.h>
#include <pe-parse/nt-headers.h>

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
    // Strip .dll extension
    auto dot = entry.dll_name.rfind(".dll");
    if (dot != std::string::npos) entry.dll_name.erase(dot);
    if (dot == std::string::npos) {
        dot = entry.dll_name.rfind(".DLL");
        if (dot != std::string::npos) entry.dll_name.erase(dot);
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
    // We don't fully parse resources here — just consume the callback
    (void)r;
    (void)ctx;
    return 0;
}

// ── Helper: read BYTE at RVA from PE raw data ───────────────

/**
 * Read a single byte at a given Virtual Address from the parsed PE.
 * Returns false if the address is out of range.
 */
static bool read_byte_at_va(peparse::parsed_pe* pe, uint64_t va,
                            uint8_t& out) {
    peparse::VA va_struct;
    va_struct = va;
    (void)va_struct;
    return peparse::ReadByteAtVA(pe, peparse::VA(va), out);
}

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

PeLoader::PeLoader(const std::string& path, const std::vector<uint8_t>& data)
    : path_(path), data_(data) {

    if (data_.empty() && !path_.empty()) {
        std::ifstream ifs(path_, std::ios::binary | std::ios::ate);
        if (!ifs.is_open()) {
            throw std::runtime_error("Cannot open PE file: " + path_);
        }
        size_t fsize = static_cast<size_t>(ifs.tellg());
        ifs.seekg(0);
        data_.resize(fsize);
        ifs.read(reinterpret_cast<char*>(data_.data()), fsize);
    }

    if (data_.empty()) {
        throw std::runtime_error("No PE data to parse");
    }

    parse_pe();
}

void PeLoader::parse_pe() {
    auto* pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(data_.data()),
        static_cast<uint32_t>(data_.size()));

    if (!pe) {
        throw std::runtime_error("Failed to parse PE file");
    }

    ParseCtx ctx;

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

    // TLS callbacks — parse TLS directory
    auto tls_dir = pe->peHeader.nt.OptionalHeader.DataDirectory[9];
    if (tls_dir.VirtualAddress != 0) {
        uint64_t callbacks_rva = 0;
        int ptr_size = (ctx.arch == 64) ? 8 : 4;

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

    peparse::DestructParsedPE(pe);
}

LoadedImage PeLoader::make_image() {
    LoadedImage img;

    // Re-parse to build mapped image
    auto* pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(data_.data()),
        static_cast<uint32_t>(data_.size()));

    if (!pe) {
        // Return what we have from parse_pe
        img.name = path_.empty() ? "unknown" :
            path_.substr(path_.find_last_of("/\\") + 1);
        img.name = img.name.substr(0, img.name.find_last_of('.'));
        img.mapped_image = data_;
        img.arch = (metadata_.machine == 0x8664) ? 64 : 32;
        img.metadata = metadata_;
        img.imports = imports_;
        img.exports = exports_;
        img.sections = sections_;
        img.tls_callbacks = tls_callbacks_;
        return img;
    }

    uint64_t image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
    uint64_t image_size = pe->peHeader.nt.OptionalHeader.SizeOfImage;
    uint32_t section_align = pe->peHeader.nt.OptionalHeader.SectionAlignment;
    uint32_t file_align = pe->peHeader.nt.OptionalHeader.FileAlignment;

    // Copy PE headers
    uint32_t header_size = pe->peHeader.nt.OptionalHeader.SizeOfHeaders;
    img.mapped_image.assign(data_.begin(),
                            data_.begin() + std::min(header_size, static_cast<uint32_t>(data_.size())));

    // Pad to section alignment after header
    while (img.mapped_image.size() % section_align != 0) {
        img.mapped_image.push_back(0);
    }

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
    for (auto& sec : sec_raws) {
        // Pad to virtual address
        while (img.mapped_image.size() < sec.va) {
            img.mapped_image.push_back(0);
        }

        // Copy raw section data
        if (sec.raw_ptr > 0 && sec.raw_ptr < data_.size() && sec.raw_size > 0) {
            size_t copy_size = std::min(static_cast<size_t>(sec.raw_size),
                                        data_.size() - sec.raw_ptr);
            img.mapped_image.insert(img.mapped_image.end(),
                                    data_.begin() + sec.raw_ptr,
                                    data_.begin() + sec.raw_ptr + copy_size);
        }

        // Pad to virtual size
        while (img.mapped_image.size() < sec.va + sec.vsize) {
            img.mapped_image.push_back(0);
        }

        // Build memory region
        MemoryRegion region;
        region.base = image_base + sec.va;
        region.name = sec.name;
        auto end = region.name.find_last_not_of(" \t\0");
        if (end != std::string::npos) region.name.erase(end + 1);
        region.perms = perms_from_section_chars(sec.chars);
        if (sec.raw_size > 0 && sec.raw_ptr < data_.size()) {
            region.data.assign(data_.begin() + sec.raw_ptr,
                               data_.begin() + sec.raw_ptr +
                                   std::min(static_cast<size_t>(sec.raw_size),
                                            data_.size() - sec.raw_ptr));
        }
        img.regions.push_back(region);
    }

    // Ensure full image size
    while (img.mapped_image.size() < image_size) {
        img.mapped_image.push_back(0);
    }

    peparse::DestructParsedPE(pe);

    // Fill metadata
    img.name = path_.empty() ? "unknown" :
        path_.substr(path_.find_last_of("/\\") + 1);
    auto dot = img.name.rfind('.');
    if (dot != std::string::npos) img.name.erase(dot);

    img.emu_path = path_;
    img.image_size = image_size;
    img.base = image_base;
    img.ep = (sections_.empty()) ? 0 : 0;
    img.arch = (metadata_.machine == 0x8664) ? 64 : 32;
    img.is_driver = (metadata_.subsystem == 1);
    img.metadata = metadata_;
    img.imports = imports_;
    img.exports = exports_;
    img.sections = sections_;
    img.tls_callbacks = tls_callbacks_;

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

} // namespace speakeasy
