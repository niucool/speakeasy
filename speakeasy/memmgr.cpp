// memmgr.cpp
#include "memmgr.h"
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <cstring>

/**
 * Constructor for MemMap
 */
MemMap::MemMap(uint64_t base, uint64_t size, const std::string& tag, uint32_t prot,
               uint32_t flags, uint64_t block_base, uint64_t block_size,
               bool shared, Process* process)
    : base(base), size(size), prot(prot), flags(flags), shared(shared),
      free(false), process(process), block_base(block_base), block_size(block_size) {

    std::string base_addr_tag = ".0x" + std::to_string(base);
    std::string new_tag = tag;
    
    if (!tag.empty() && tag.find(base_addr_tag) == std::string::npos) {
        new_tag += base_addr_tag;
    }

    if (!new_tag.empty()) {
        // Replace bad characters with underscores
        const std::string bad_chars = "\\?[]:]";
        for (char& c : new_tag) {
            if (bad_chars.find(c) != std::string::npos) {
                c = '_';
            }
        }
        this->tag = new_tag;
    }
}

/**
 * Set the tag for the memory mapping
 */
void MemMap::update_tag(const std::string& new_tag) {
    this->tag = new_tag;
}

/**
 * Get the process object associated with a memory map
 */
Process* MemMap::get_process() const {
    return this->process;
}

/**
 * Set the process object associated with a memory map
 */
void MemMap::set_process(Process* process) {
    this->process = process;
}

/**
 * Get the tag for the memory mapping
 */
std::string MemMap::get_tag() const {
    return this->tag;
}

/**
 * Get the memory permissions for a map
 */
uint32_t MemMap::get_prot() const {
    return this->prot;
}

/**
 * Get the memory flags for a map
 */
uint32_t MemMap::get_flags() const {
    return this->flags;
}

/**
 * Get the byte size for the current memory mapping
 */
uint64_t MemMap::get_size() const {
    return this->size;
}

/**
 * Get the base address (lowest possible address) of the current memory map
 */
uint64_t MemMap::get_base() const {
    return this->base;
}

/**
 * Set the current mapping to be in an allocated state
 */
void MemMap::set_alloc() {
    this->free = false;
}

/**
 * Set the current mapping to be in a free state
 */
void MemMap::set_free() {
    this->free = true;
}

/**
 * Return the alloc state of a memory block
 */
bool MemMap::is_free() const {
    return this->free;
}

/**
 * Equality operator
 */
bool MemMap::operator==(const MemMap& other) const {
    return other.base == this->base;
}

/**
 * Inequality operator
 */
bool MemMap::operator!=(const MemMap& other) const {
    return !(*this == other);
}

/**
 * Constructor for MemoryManager
 */
MemoryManager::MemoryManager() 
    : block_base(0), block_size(0), block_offset(0), page_size(0x1000), 
      keep_memory_on_free(false), emu_eng(nullptr), hooks(nullptr), current_process(nullptr) {
}

/**
 * Dispatch memory map hooks
 */
void MemoryManager::_hook_mem_map_dispatch(std::shared_ptr<MemMap> mm) {
    // Implementation would depend on the hook system
    // This is a placeholder for the actual hook dispatch logic
}

/**
 * Get current process
 */
Process* MemoryManager::get_current_process() {
    return this->current_process;
}

/**
 * Map a block of memory with specified permissions and a tag
 */
uint64_t MemoryManager::mem_map(uint64_t size, uint64_t base, uint32_t perms,
                                const std::string& tag, uint32_t flags, bool shared,
                                Process* process) {
    
    if (!process && !tag.empty() && tag.substr(0, 3) != "emu") {
        process = get_current_process();
    }

    if (base == 0) { // nullptr equivalent
        if (size < page_size && size % page_size) {
            uint64_t addr = this->block_base + this->block_offset;
            uint64_t pad_size = 0x10 - (size % 0x10);
            uint64_t adjusted_size = size + pad_size;
            
            if (!this->block_base || ((addr + adjusted_size) > this->block_base + this->page_size)) {
                auto block = get_valid_ranges(this->page_size);
                this->block_base = block.first;
                this->block_size = block.second;

                // Assuming emu_eng has a mem_map method
                // this->emu_eng->mem_map(this->block_base, this->block_size);
                this->block_offset = 0;
                addr = this->block_base + this->block_offset;
            }

            this->block_offset += adjusted_size;
            base = addr;

            auto mm = std::make_shared<MemMap>(base, adjusted_size, tag, perms, flags,
                                               this->block_base, this->block_size, shared, process);
            
            this->maps.push_back(mm);
            _hook_mem_map_dispatch(mm);
            return base;
        }
    }

    auto block = get_valid_ranges(size, base);
    base = block.first;
    uint64_t blockSize = block.second;

    uint64_t actual_block_size = this->block_size;
    if (blockSize > this->block_size) {
        actual_block_size = blockSize;
    }
    
    auto mm = std::make_shared<MemMap>(base, blockSize, tag, perms, flags, 
                                       base, actual_block_size, shared, process);
    
    // Assuming emu_eng has a mem_map method
    // this->emu_eng->mem_map(base, blockSize, perms);
    this->maps.push_back(mm);
    _hook_mem_map_dispatch(mm);
    return base;
}

/**
 * Free a block of memory, if all blocks in a block are set to free, unmap the entire block
 */
void MemoryManager::mem_free(uint64_t base) {
    auto mm = get_address_map(base);
    if (mm) {
        mm->set_free();

        // If we want to freeze memory, just return
        if (this->keep_memory_on_free) {
            return;
        }

        std::vector<std::shared_ptr<MemMap>> ml;
        for (const auto& m : get_mem_maps()) {
            if (m->block_base == mm->block_base) {
                ml.push_back(m);
            }
        }
        
        // if all blocks are free in the current block, free it from the emu engine
        bool all_free = true;
        for (const auto& m : ml) {
            if (!m->is_free()) {
                all_free = false;
                break;
            }
        }
        
        if (all_free) {
            this->block_base = 0;
            mem_unmap(mm->block_base, mm->block_size);
            for (const auto& m : ml) {
                // Remove from maps vector
                auto it = std::find(this->maps.begin(), this->maps.end(), m);
                if (it != this->maps.end()) {
                    this->maps.erase(it);
                }
            }
        }
    }
}

/**
 * Remap a block of emulated memory, and return the new address,
 * or -1 on error
 * Protections remain the same
 */
int64_t MemoryManager::mem_remap(uint64_t from, uint64_t to) {
    auto map = get_address_map(from);

    if (!map) {
        return -1;
    }

    uint32_t prot = map->get_prot();
    uint64_t size = map->get_size();

    // Exclude old memory region in tag name
    std::string tag = map->get_tag();
    size_t pos = tag.rfind(".");
    if (pos != std::string::npos) {
        tag = tag.substr(0, pos);
    }

    auto contents = mem_read(map->get_base(), size);

    // Will unmap as well
    mem_free(map->get_base());

    uint64_t newmem = mem_map(size, to, prot, tag);
    
    if (newmem != to) {
        return -1;
    }

    mem_write(newmem, contents);

    return newmem;
}

/**
 * Free a block of emulated memory
 */
void MemoryManager::mem_unmap(uint64_t base, uint64_t size) {
    // Assuming emu_eng has a mem_unmap method
    // this->emu_eng->mem_unmap(base, size);
}

/**
 * Write bytes into the emulated address space
 */
void MemoryManager::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    // Assuming emu_eng has a mem_write method
    // this->emu_eng->mem_write(addr, data);
}

/**
 * Read bytes from the emulated address space
 */
std::vector<uint8_t> MemoryManager::mem_read(uint64_t addr, uint64_t size) {
    // Assuming emu_eng has a mem_read method
    // return this->emu_eng->mem_read(addr, size);
    return std::vector<uint8_t>(size, 0); // Placeholder
}

/**
 * Change memory protections
 */
void MemoryManager::mem_protect(uint64_t addr, uint64_t size, uint32_t perms) {
    // Assuming emu_eng has a mem_protect method
    // this->emu_eng->mem_protect(addr, size, perms);
}

/**
 * Remove an entire memory region that may not have blocks allocated within it
 */
void MemoryManager::_mem_unmap_region(uint64_t base, uint64_t size) {
    // Assuming emu_eng has a mem_unmap method
    // this->emu_eng->mem_unmap(base, size);
}

/**
 * Get the "MemMap" object associated with a specific address
 */
std::shared_ptr<MemMap> MemoryManager::get_address_map(uint64_t address) {
    for (const auto& m : this->maps) {
        if (m->get_base() <= address && address <= (m->get_base() + m->get_size()) - 1) {
            return m;
        }
    }
    return nullptr;
}

/**
 * Get the "MemMap" object that was only reserved for a specific address
 */
std::shared_ptr<MemMap> MemoryManager::get_reserve_map(uint64_t address) {
    for (const auto& m : this->mem_reserves) {
        if (m->get_base() <= address && address <= (m->get_base() + m->get_size()) - 1) {
            return m;
        }
    }
    return nullptr;
}

/**
 * Was this address previously reserved or mapped?
 */
bool MemoryManager::is_address_valid(uint64_t address) {
    if (get_address_map(address)) {
        return true;
    }
    if (get_reserve_map(address)) {
        return true;
    }
    return false;
}

/**
 * Get the tag for a supplied memory address
 */
std::string MemoryManager::get_address_tag(uint64_t address) {
    for (const auto& m : this->maps) {
        if (address >= m->get_base() && address <= (m->get_base() + m->get_size()) - 1) {
            return m->get_tag();
        }
    }
    return "";
}

/**
 * Reserve (but do not map) a block of memory
 */
uint64_t MemoryManager::mem_reserve(uint64_t size, uint64_t base, uint32_t perms,
                                    const std::string& tag, uint32_t flags, bool shared) {
    if (base == 0) { // nullptr equivalent
        auto block = get_valid_ranges(size);
        base = block.first;
        size = block.second;
    }

    auto mm = std::make_shared<MemMap>(base, size, tag, perms, flags, 
                                       base, this->block_size, shared);

    this->mem_reserves.push_back(mm);
    return base;
}

/**
 * Unmap all current blocks of mapped memory
 */
void MemoryManager::purge_memory() {
    for (const auto& region : get_mem_regions()) {
        uint64_t base = std::get<0>(region);
        uint64_t end = std::get<1>(region);
        uint32_t perms = std::get<2>(region);
        uint64_t size = (end - base) + 1;
        _mem_unmap_region(base, size);
    }
}

/**
 * Get the listing of current memory maps
 */
std::vector<std::shared_ptr<MemMap>> MemoryManager::get_mem_maps() {
    return this->maps;
}

/**
 * Map a previously reserved block of memory
 */
uint64_t MemoryManager::mem_map_reserve(uint64_t mapped_base) {
    for (auto it = this->mem_reserves.begin(); it != this->mem_reserves.end(); ++it) {
        auto r = *it;
        if (mapped_base == r->get_base()) {
            this->mem_reserves.erase(it);
            return mem_map(r->get_size(), r->get_base(), r->get_prot(), r->get_tag());
        }
    }
    return 0; // nullptr equivalent
}

/**
 * Get the current regions of mapped memory
 */
std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> MemoryManager::get_mem_regions() {
    // Assuming emu_eng has a mem_regions method
    // return this->emu_eng->mem_regions();
    return {}; // Placeholder
}

/**
 * Get runs of memory pages
 */
std::vector<std::vector<uint64_t>> MemoryManager::get_runs(const std::vector<uint64_t>& i) {
    // Simplified implementation - would need more complex logic to match Python version
    std::vector<std::vector<uint64_t>> result;
    if (!i.empty()) {
        std::vector<uint64_t> run;
        run.push_back(i[0]);
        result.push_back(run);
    }
    return result;
}

/**
 * Retrieve a valid address range that can satisfy the requested size.
 * Optionally, a base address can be specified to test if it can be used
 */
std::pair<uint64_t, uint64_t> MemoryManager::get_valid_ranges(uint64_t size, uint64_t addr) {
    uint64_t page_size = this->page_size;

    // mem_map needs to be page aligned
    uint64_t total = size;

    // alloced address needs to also be on a page boundary
    if (addr == 0) { // nullptr equivalent
        addr = page_size;
    }
    uint64_t base = addr - (addr % page_size);

    if (total < page_size) {
        total = page_size;
    } else if (total % page_size) {
        total += (page_size - (total % page_size));
    }

    std::vector<uint64_t> curr;
    for (const auto& m : get_mem_regions()) {
        uint64_t start = std::get<0>(m);
        uint64_t end = std::get<1>(m);
        for (uint64_t i = start; i < end; i += page_size) {
            curr.push_back(i);
        }
    }

    // Add reserved memory so we don't accidentally allocate it
    for (const auto& res : this->mem_reserves) {
        for (uint64_t i = res->get_base(); i < (res->get_base() + res->get_size()); i += page_size) {
            curr.push_back(i);
        }
    }

    // Sort and remove duplicates
    std::sort(curr.begin(), curr.end());
    curr.erase(std::unique(curr.begin(), curr.end()), curr.end());

    int attempts = 9999;
    while (attempts > 0) {
        // This is a simplified version - full implementation would require
        // more complex set operations like in the Python version
        break; // Placeholder
        attempts--;
    }

    if (attempts == 0) {
        throw std::runtime_error("Failed to allocate emulator memory");
    }

    // Return a placeholder result
    return std::make_pair(base, total);
}