// loaders.h  PE file loader for emulated modules
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

#include "common.h"

namespace speakeasy {

//  Data structures 

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

// struct ExportEntry {
//     std::string name;
//     uint64_t address = 0;
//     uint32_t ordinal = 0;
//     std::string execution_mode;  // "user" or "kernel"
// };

class Loader;  // forward declaration
struct LoadedImage {
    int arch = 0;                 // 32 or 64
    std::string module_type; // "exe", "dll", "driver", "decoy"
    std::string name;
    std::string emu_path;
    uint64_t base = 0;
    uint64_t image_size = 0;

    bool is_driver = false;
    bool is_dll = false;
    bool is_decoy = false;

    std::vector<MemoryRegion> regions;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;

    uint64_t ep = 0;
    bool visible_in_peb = true;
    int stack_size = 0x12000;  // default stack commit size for emulation

    std::vector<uint64_t> tls_callbacks;
    int tls_directory_va = 0;

    Loader* loader = nullptr;  // back-reference to the loader that created this image (for deferred lookups)
    std::vector<SectionEntry> sections;
    PeMetadata metadata;

    //std::vector<uint8_t> mapped_image;
};


//  RuntimeModule 
/**
 * Wraps a LoadedImage with runtime state tracked during emulation.
 * Mirrors Python speakeasy/windows/loaders.py class RuntimeModule (lines 109-167).
 */
class RuntimeModule {
public:
    // Constructed from a LoadedImage; the image pointer must remain valid.
    explicit RuntimeModule(std::shared_ptr<speakeasy::LoadedImage> image);

    std::shared_ptr<speakeasy::LoadedImage> image() { return _image_; }
    const std::shared_ptr<speakeasy::LoadedImage> image() const { return _image_; }

    // Type checks (Python: 129-139)
    bool is_exe() const;
    bool is_dll() const;
    bool is_driver() const;
    bool is_decoy() const;

    // Accessors (Python: 141-167)
    std::string get_base_name() const;                  // ntpath.basename(emu_path)
    uint64_t get_ep() const { return base + ep; }
    const std::vector<ExportEntry>& get_exports() const;
    const ExportEntry* get_export_by_name(const std::string& exp_name) const;
    const SectionEntry* get_section_for_addr(uint64_t addr) const;
    const std::vector<uint64_t>& get_tls_callbacks() const;
    const PeMetadata* get_pe_metadata() const;

    // Mirrored from LoadedImage for convenience (Python: 112-123)
    uint64_t base;
    uint64_t image_size;
    uint64_t ep;          // RVA, not absolute
    int arch;
    std::string emu_path;
    std::string path;
    std::string module_type; // "exe", "dll", "driver", "decoy"
    uint64_t stack_commit;
    bool visible_in_peb = true;
    void* loader = nullptr;
    std::string name;
    std::vector<SectionEntry> sections;
    // _image reference for deferred lookups
    std::vector<ExportEntry> exports_;
    std::vector<uint64_t> tls_callbacks_;
    PeMetadata metadata_;

    std::string to_string() const;

private:
    std::shared_ptr<speakeasy::LoadedImage> _image_;
};

//  PE Loader 

/**
 * Parses PE files (EXE, DLL, SYS) and produces a LoadedImage ready
 * for mapping into the emulated address space.
 */
//  Abstract Loader base class 
/**
 * Virtual base for all module loaders (PE, shellcode, API module, decoy).
 * Mirrors the Python duck-typing contract: every loader provides make_image().
 */
class Loader {
public:
    virtual ~Loader() = default;
    virtual std::shared_ptr<LoadedImage> make_image() = 0;
};

class PeLoader : public Loader {
public:
    /**
     * Construct a loader from a file path or raw data.
     * @param path   File path (optional if data is provided).
     * @param data   Raw PE bytes.
     */
    explicit PeLoader(const std::string& path = "",
                      const std::vector<uint8_t>& data = {},
                      int base_override = 0,
                      const std::string& emu_path = "");

    /**
     * Destructor to clean up parsed PE resources.
     */
    ~PeLoader();

    /**
     * Parse the PE and produce a memory image suitable for loading.
     */
    std::shared_ptr<LoadedImage> make_image();

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
    uint64_t base_override_ = 0;
    std::string emu_path_;

    std::vector<ImportEntry> imports_;
    std::vector<ExportEntry> exports_;
    std::vector<SectionEntry> sections_;
    std::vector<uint64_t> tls_callbacks_;
    uint64_t tls_directory_rva_ = 0;
    PeFile pefile;

    void parse_pe();
    uint32_t perms_from_section_chars(uint32_t chars);
    std::string get_prot_string(uint32_t perms);
};

/**
 * Convert section characteristics flags to memory permissions.
 */

//  Shellcode Loader 
/**
 * Wraps raw shellcode bytes as a LoadedImage.
 * Mirrors Python speakeasy/windows/loaders.py class ShellcodeLoader (lines 353-388).
 */
class ShellcodeLoader : public Loader {
public:
    explicit ShellcodeLoader(const std::vector<uint8_t>& data, int arch);
    std::shared_ptr<LoadedImage> make_image() override;
private:
    std::vector<uint8_t> data_;
    int arch_;
};

//  API Module Loader 
/**
 * Creates a synthetic PE image that exports API handler stubs.
 * Mirrors Python speakeasy/windows/loaders.py class ApiModuleLoader (lines 391-508).
 */
class ApiModuleLoader : public Loader {
public:
    explicit ApiModuleLoader(const std::string& name, void* api,
                             int arch, uint64_t base, const std::string& emu_path);
    std::shared_ptr<LoadedImage> make_image() override;
private:
    std::string name_;
    void* api_;
    int arch_;
    uint64_t base_;
    std::string emu_path_;
};

//  Decoy Loader 
/**
 * Creates a minimal LoadedImage for modules that only exist for
 * PEB visibility (e.g. ntdll.dll, kernel32.dll as decoys).
 * Mirrors Python speakeasy/windows/loaders.py class DecoyLoader (lines 511-540).
 */
class DecoyLoader : public Loader {
public:
    explicit DecoyLoader(const std::string& name, uint64_t base,
                         const std::string& emu_path, uint64_t image_size);
    std::shared_ptr<LoadedImage> make_image() override;
private:
    std::string name_;
    uint64_t base_;
    std::string emu_path_;
    uint64_t image_size_;
};

inline uint32_t perms_from_section_chars(uint32_t chars) {
    // ImageSectionCharacteristics constants (common Windows values)
    #ifndef IMAGE_SCN_MEM_READ
    const uint32_t IMAGE_SCN_MEM_READ    = 0x40000000;
    #endif
    #ifndef IMAGE_SCN_MEM_WRITE
    const uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000;
    #endif
    #ifndef IMAGE_SCN_MEM_EXECUTE
    const uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    #endif

    uint32_t perms = 0;  // PERM_MEM_NONE
    if (chars & IMAGE_SCN_MEM_READ)    perms |= 0x02;  // PERM_MEM_READ
    if (chars & IMAGE_SCN_MEM_WRITE)   perms |= 0x04;  // PERM_MEM_WRITE
    if (chars & IMAGE_SCN_MEM_EXECUTE) perms |= 0x10;  // PERM_MEM_EXEC
    return perms;
}

} // namespace speakeasy

#endif // SPEAKEASY_LOADERS_H
