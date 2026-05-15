// loaders.h — PE file loader for emulated modules
//
// Maps to: speakeasy/windows/loaders.py
//
// Parses PE files and prepares memory images suitable for loading
// into the emulator's address space.  Handles section mapping,
// import resolution, and TLS callback discovery.

#ifndef SPEAKEASY_LOADERS_H
#define SPEAKEASY_LOADERS_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

namespace speakeasy {

// ── Data structures ──────────────────────────────────────────

struct ResourceEntry {
    int id = 0;
    uint32_t data_rva = 0;
    uint32_t size = 0;
    int type_id = 0;
    uint32_t entry_rva = 0;
    int lang_id = 0;
};

struct PeMetadata {
    uint32_t subsystem = 0;
    uint32_t timestamp = 0;
    uint16_t machine = 0;
    uint16_t magic = 0;
    std::vector<ResourceEntry> resources;
    std::map<int, std::string> string_table;  // for LoadString
};

struct MemoryRegion {
    uint64_t base = 0;
    std::vector<uint8_t> data;
    std::string name;
    uint32_t perms = 0;
};

struct SectionEntry {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t perms = 0;
};

struct ImportEntry {
    uint64_t iat_address = 0;
    std::string dll_name;
    std::string func_name;
};

struct ExportEntry {
    std::string name;
    uint64_t address = 0;
    uint32_t ordinal = 0;
    std::string execution_mode;  // "user" or "kernel"
};

struct LoadedImage {
    std::string name;
    std::string emu_path;
    uint64_t base = 0;
    uint64_t image_size = 0;
    uint64_t ep = 0;
    int arch = 0;                 // 32 or 64
    bool is_driver = false;
    std::vector<MemoryRegion> regions;
    std::vector<uint8_t> mapped_image;
    PeMetadata metadata;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;
    std::vector<SectionEntry> sections;
    std::vector<uint64_t> tls_callbacks;
};

// ── PE Loader ────────────────────────────────────────────────

/**
 * Parses PE files (EXE, DLL, SYS) and produces a LoadedImage ready
 * for mapping into the emulated address space.
 */
class PeLoader {
public:
    /**
     * Construct a loader from a file path or raw data.
     * @param path   File path (optional if data is provided).
     * @param data   Raw PE bytes.
     */
    explicit PeLoader(const std::string& path = "",
                      const std::vector<uint8_t>& data = {});

    /**
     * Parse the PE and produce a memory image suitable for loading.
     */
    LoadedImage make_image();

    /**
     * Get the parsed PE metadata.
     */
    const PeMetadata& get_metadata() const { return metadata_; }

    /**
     * Get the list of discovered imports.
     */
    const std::vector<ImportEntry>& get_imports() const { return imports_; }

    /**
     * Get the list of discovered exports.
     */
    const std::vector<ExportEntry>& get_exports() const { return exports_; }

    /**
     * Get TLS callback RVAs.
     */
    const std::vector<uint64_t>& get_tls_callbacks() const { return tls_callbacks_; }

private:
    std::string path_;
    std::vector<uint8_t> data_;
    PeMetadata metadata_;
    std::vector<ImportEntry> imports_;
    std::vector<ExportEntry> exports_;
    std::vector<SectionEntry> sections_;
    std::vector<uint64_t> tls_callbacks_;

    void parse_pe();
    uint32_t perms_from_section_chars(uint32_t chars);
    std::string get_prot_string(uint32_t perms);
};

/**
 * Convert section characteristics flags to memory permissions.
 */
inline uint32_t perms_from_section_chars(uint32_t chars) {
    // ImageSectionCharacteristics constants (common Windows values)
    const uint32_t IMAGE_SCN_MEM_READ    = 0x40000000;
    const uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000;
    const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;

    uint32_t perms = 0;  // PERM_MEM_NONE
    if (chars & IMAGE_SCN_MEM_READ)    perms |= 0x02;  // PERM_MEM_READ
    if (chars & IMAGE_SCN_MEM_WRITE)   perms |= 0x04;  // PERM_MEM_WRITE
    if (chars & IMAGE_SCN_MEM_EXECUTE) perms |= 0x10;  // PERM_MEM_EXEC
    return perms;
}

} // namespace speakeasy

#endif // SPEAKEASY_LOADERS_H
