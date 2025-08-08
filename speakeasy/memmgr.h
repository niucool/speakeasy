// memmgr.h
#ifndef MEMMGR_H
#define MEMMGR_H

#include <vector>
#include <string>
#include <memory>
#include <cstdint>

// Forward declarations
class Process;
class MemoryManager;

// Permission constants (assuming these would be defined elsewhere)
namespace common {
    const uint32_t PERM_MEM_RWX = 0x7; // Read, Write, Execute
    const uint32_t HOOK_MEM_MAP = 0x1;
}

/**
 * Class that defines a memory mapping (e.g. heap/pool alloc, binary image, etc.)
 */
class MemMap {
private:
    uint64_t base;
    uint64_t size;
    std::string tag;
    uint32_t prot;
    uint32_t flags;
    bool shared;
    bool free;
    Process* process;
    uint64_t block_base;
    uint64_t block_size;

public:
    /**
     * Constructor for MemMap
     */
    MemMap(uint64_t base, uint64_t size, const std::string& tag, uint32_t prot, 
           uint32_t flags, uint64_t block_base, uint64_t block_size,
           bool shared = false, Process* process = nullptr);

    /**
     * Set the tag for the memory mapping
     */
    void update_tag(const std::string& new_tag);

    /**
     * Get the process object associated with a memory map
     */
    Process* get_process() const;

    /**
     * Set the process object associated with a memory map
     */
    void set_process(Process* process);

    /**
     * Get the tag for the memory mapping
     */
    std::string get_tag() const;

    /**
     * Get the memory permissions for a map
     */
    uint32_t get_prot() const;

    /**
     * Get the memory flags for a map
     */
    uint32_t get_flags() const;

    /**
     * Get the byte size for the current memory mapping
     */
    uint64_t get_size() const;

    /**
     * Get the base address (lowest possible address) of the current memory map
     */
    uint64_t get_base() const;

    /**
     * Set the current mapping to be in an allocated state
     */
    void set_alloc();

    /**
     * Set the current mapping to be in a free state
     */
    void set_free();

    /**
     * Return the alloc state of a memory block
     */
    bool is_free() const;

    // Comparison operators
    bool operator==(const MemMap& other) const;
    bool operator!=(const MemMap& other) const;
};

/**
 * Primitive memory manager used to block OS sized allocation units into something more practical
 */
class MemoryManager {
private:
    std::vector<std::shared_ptr<MemMap>> maps;
    std::vector<std::shared_ptr<MemMap>> mem_reserves;
    uint64_t block_base;
    uint64_t block_size;
    uint64_t block_offset;
    uint64_t page_size;
    bool keep_memory_on_free;

    // Assuming these would be defined elsewhere
    void* emu_eng;
    void* hooks;
    Process* current_process;

    /**
     * Dispatch memory map hooks
     */
    void _hook_mem_map_dispatch(std::shared_ptr<MemMap> mm);

    /**
     * Get current process
     */
    Process* get_current_process();

    /**
     * Remove an entire memory region that may not have blocks allocated within it
     */
    void _mem_unmap_region(uint64_t base, uint64_t size);

    /**
     * Get runs of memory pages
     */
    std::vector<std::vector<uint64_t>> get_runs(const std::vector<uint64_t>& i);

public:
    /**
     * Constructor for MemoryManager
     */
    MemoryManager();

    /**
     * Map a block of memory with specified permissions and a tag
     */
    uint64_t mem_map(uint64_t size, uint64_t base = 0, uint32_t perms = common::PERM_MEM_RWX,
                     const std::string& tag = "", uint32_t flags = 0, bool shared = false,
                     Process* process = nullptr);

    /**
     * Free a block of memory, if all blocks in a block are set to free, unmap the entire block
     */
    void mem_free(uint64_t base);

    /**
     * Remap a block of emulated memory, and return the new address,
     * or -1 on error
     * Protections remain the same
     */
    int64_t mem_remap(uint64_t from, uint64_t to);

    /**
     * Free a block of emulated memory
     */
    void mem_unmap(uint64_t base, uint64_t size);

    /**
     * Write bytes into the emulated address space
     */
    void mem_write(uint64_t addr, const std::vector<uint8_t>& data);

    /**
     * Read bytes from the emulated address space
     */
    std::vector<uint8_t> mem_read(uint64_t addr, uint64_t size);

    /**
     * Change memory protections
     */
    void mem_protect(uint64_t addr, uint64_t size, uint32_t perms);

    /**
     * Get the "MemMap" object associated with a specific address
     */
    std::shared_ptr<MemMap> get_address_map(uint64_t address);

    /**
     * Get the "MemMap" object that was only reserved for a specific address
     */
    std::shared_ptr<MemMap> get_reserve_map(uint64_t address);

    /**
     * Was this address previously reserved or mapped?
     */
    bool is_address_valid(uint64_t address);

    /**
     * Get the tag for a supplied memory address
     */
    std::string get_address_tag(uint64_t address);

    /**
     * Reserve (but do not map) a block of memory
     */
    uint64_t mem_reserve(uint64_t size, uint64_t base = 0, uint32_t perms = 0,
                         const std::string& tag = "", uint32_t flags = 0, bool shared = false);

    /**
     * Unmap all current blocks of mapped memory
     */
    void purge_memory();

    /**
     * Get the listing of current memory maps
     */
    std::vector<std::shared_ptr<MemMap>> get_mem_maps();

    /**
     * Map a previously reserved block of memory
     */
    uint64_t mem_map_reserve(uint64_t mapped_base);

    /**
     * Get the current regions of mapped memory
     */
    std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> get_mem_regions();

    /**
     * Retrieve a valid address range that can satisfy the requested size.
     * Optionally, a base address can be specified to test if it can be used
     */
    std::pair<uint64_t, uint64_t> get_valid_ranges(uint64_t size, uint64_t addr = 0);
};

#endif // MEMMGR_H