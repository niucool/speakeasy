// memmgr.cpp
#include "memmgr.h"
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <format>
#include <plog/Log.h>

/**
 * Constructor for MemMap
 */
MemMap::MemMap(uint64_t base, uint64_t size, const std::string& tag, uint32_t prot,
               uint32_t flags, uint64_t block_base, uint64_t block_size,
               bool shared, std::shared_ptr<Process> process)
    : base_(base), size_(size), prot_(prot), flags_(flags), shared_(shared),
      free_(false), process_(process), block_base_(block_base), block_size_(block_size) {

    std::string base_addr_tag = std::format(".0x{:x}", base);
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
        this->tag_ = new_tag;
    }
}

/**
 * Set the tag for the memory mapping
 */
void MemMap::update_tag(const std::string& new_tag) {
    this->tag_ = new_tag;
}

/**
 * Get the process object associated with a memory map
 */
std::shared_ptr<Process> MemMap::get_process() const {
    return this->process_;
}

/**
 * Set the process object associated with a memory map
 */
void MemMap::set_process(std::shared_ptr<Process> process) {
    this->process_ = process;
}

/**
 * Get the tag for the memory mapping
 */
std::string MemMap::get_tag() const {
    return this->tag_;
}

/**
 * Get the memory permissions for a map
 */
uint32_t MemMap::get_prot() const {
    return this->prot_;
}

/**
 * Get the memory flags for a map
 */
uint32_t MemMap::get_flags() const {
    return this->flags_;
}

/**
 * Get the byte size for the current memory mapping
 */
uint64_t MemMap::get_size() const {
    return this->size_;
}

/**
 * Get the base address (lowest possible address) of the current memory map
 */
uint64_t MemMap::get_base() const {
    return this->base_;
}

uint64_t MemMap::get_block_base() const {
    return this->block_base_;
}

uint64_t MemMap::get_block_size() const {
    return this->block_size_;
}


/**
 * Set the current mapping to be in an allocated state
 */
void MemMap::set_alloc() {
    this->free_ = false;
}

/**
 * Set the current mapping to be in a free state
 */
void MemMap::set_free() {
    this->free_ = true;
}

/**
 * Return the alloc state of a memory block
 */
bool MemMap::is_free() const {
    return this->free_;
}

/**
 * Equality operator
 */
bool MemMap::operator==(const MemMap& other) const {
    return other.base_ == this->base_;
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
    : block_base_(0), block_size_(0), block_offset_(0), page_size_(0x1000), 
      keep_memory_on_free_(false), emu_eng_(nullptr), curr_process_(nullptr) {
}

/**
 * Destructor for MemoryManager
 */
MemoryManager::~MemoryManager() {
    // Clean up any remaining memory maps
    for (const auto& mm : maps_) {
        mem_unmap(mm->get_base(), mm->get_size());
    }
    maps_.clear();
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
std::shared_ptr<Process> MemoryManager::get_current_process() {
    return this->curr_process_;
}

/**
 * Map a block of memory with specified permissions and a tag
 */
uint64_t MemoryManager::mem_map(uint64_t size, uint64_t base, uint32_t perms,
                                const std::string& tag, uint32_t flags, bool shared,
                                std::shared_ptr<Process> process) {
    
    if (!process && !tag.empty() && tag.substr(0, 3) != "emu") {
        process = get_current_process();
    }

    if (base == 0) { // nullptr equivalent
        if (size < page_size_ && size % page_size_) {
            uint64_t addr = this->block_base_ + this->block_offset_;
            uint64_t pad_size = 0x10 - (size % 0x10);
            uint64_t adjusted_size = size + pad_size;
            
            if (!this->block_base_ || ((addr + adjusted_size) > this->block_base_ + this->page_size_)) {
                auto block = get_valid_ranges(this->page_size_);
                this->block_base_ = block.first;
                this->block_size_ = block.second;

                if (this->emu_eng_) {
                    this->emu_eng_->mem_map(this->block_base_, this->block_size_);
                }
                this->block_offset_ = 0;
                addr = this->block_base_ + this->block_offset_;
            }

            this->block_offset_ += adjusted_size;
            base = addr;

            auto mm = std::make_shared<MemMap>(base, adjusted_size, tag, perms, flags,
                                               this->block_base_, this->block_size_, shared, process);
            PLOGD << "MemMap created: base=0x" << std::hex << base << ", size=0x" << adjusted_size << "(" << size << "), tag=" << tag;
            
            this->maps_.push_back(mm);
            _hook_mem_map_dispatch(mm);
            return base;
        }
    }

    auto block = get_valid_ranges(size, base);
    base = block.first;
    uint64_t blockSize = block.second;

    uint64_t actual_block_size = this->block_size_;
    if (blockSize > this->block_size_) {
        actual_block_size = blockSize;
    }

    auto mm = std::make_shared<MemMap>(base, blockSize, tag, perms, flags,
                                       base, actual_block_size, shared, process);
    // PLOGD << "MemMap created: base=0x" << std::hex << base << ", size=0x" << blockSize << ", tag=" << tag;

    if (this->emu_eng_) {
        this->emu_eng_->mem_map(base, blockSize, perms);
    }
    this->maps_.push_back(mm);
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
        if (this->keep_memory_on_free_) {
            return;
        }

        std::vector<std::shared_ptr<MemMap>> ml;
        for (const auto& m : get_mem_maps()) {
            if (m->get_block_base() == mm->get_block_base()) {
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
            this->block_base_ = 0;
            mem_unmap(mm->get_block_base(), mm->get_block_size());
            for (const auto& m : ml) {
                // Remove from maps vector
                auto it = std::find(this->maps_.begin(), this->maps_.end(), m);
                if (it != this->maps_.end()) {
                    this->maps_.erase(it);
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
    // Mark overlapping maps as free in internal tracking so get_valid_ranges()
    // returns the correct (original) base on the next mem_map call.
    // Without this, sentinel addresses drift because get_valid_ranges
    // thinks the old region is still occupied.
    uint64_t end = base + size;
    for (auto& m : maps_) {
        uint64_t m_end = m->get_base() + m->get_size();
        if (m->get_base() < end && m_end > base) {
            m->set_free();
        }
    }
    if (this->emu_eng_) {
        this->emu_eng_->mem_unmap(base, size);
    }
}

/**
 * Write bytes into the emulated address space
 */
void MemoryManager::mem_write(uint64_t addr, const std::vector<uint8_t>& data) {
    mem_write(addr, data.data(), data.size());
}

void MemoryManager::mem_write(uint64_t addr, const void* data, size_t size) {
    if (this->emu_eng_) {
        this->emu_eng_->mem_write(addr, data, size);
    }
}

/**
 * Read bytes from the emulated address space
 */
std::vector<uint8_t> MemoryManager::mem_read(uint64_t addr, uint64_t size) {
    std::vector<uint8_t> data(size);
    mem_read(addr, data.data(), size);
    return data;
}

void MemoryManager::mem_read(uint64_t addr, void* out_data, size_t size) {
    if (this->emu_eng_) {
        this->emu_eng_->mem_read(addr, out_data, size);
    }
}

/**
 * Change memory protections
 */
void MemoryManager::mem_protect(uint64_t addr, uint64_t size, uint32_t perms) {
    if (this->emu_eng_) {
        this->emu_eng_->mem_protect(addr, size, perms);
    }
}

/**
 * Remove an entire memory region that may not have blocks allocated within it
 */
void MemoryManager::_mem_unmap_region(uint64_t base, uint64_t size) {
    if (this->emu_eng_) {
        this->emu_eng_->mem_unmap(base, size);
    }
}

/**
 * Get the "MemMap" object associated with a specific address
 */
std::shared_ptr<MemMap> MemoryManager::get_address_map(uint64_t address) {
    for (const auto& m : this->maps_) {
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
    for (const auto& m : this->mem_reserves_) {
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
    for (const auto& m : this->maps_) {
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
                                       base, this->block_size_, shared);
    // PLOGD << "MemMap reserved: base=0x" << std::hex << base << ", size=0x" << size << ", tag=" << tag;

    this->mem_reserves_.push_back(mm);
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
    return this->maps_;
}

/**
 * Map a previously reserved block of memory
 */
uint64_t MemoryManager::mem_map_reserve(uint64_t mapped_base) {
    for (auto it = this->mem_reserves_.begin(); it != this->mem_reserves_.end(); ++it) {
        auto r = *it;
        if (mapped_base == r->get_base()) {
            this->mem_reserves_.erase(it);
            return mem_map(r->get_size(), r->get_base(), r->get_prot(), r->get_tag());
        }
    }
    return 0; // nullptr equivalent
}

/**
 * Get the current regions of mapped memory
 */
std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> MemoryManager::get_mem_regions() {
    std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> regions;
    if (!this->emu_eng_) return regions;
    uc_mem_region* uc_regions = nullptr;
    uint32_t count = 0;
    uc_err err = this->emu_eng_->mem_regions(&uc_regions, &count);
    if (err == UC_ERR_OK && uc_regions) {
        for (uint32_t i = 0; i < count; ++i) {
            regions.push_back(std::make_tuple(uc_regions[i].begin, uc_regions[i].end, uc_regions[i].perms));
        }
        uc_free(uc_regions);
    }
    return regions;
}

/**
 * Get runs of memory pages
 */
std::vector<std::vector<uint64_t>> MemoryManager::get_runs(const std::vector<uint64_t>& i) {
    std::vector<std::vector<uint64_t>> result;
    if (i.empty()) return result;
    
    std::vector<uint64_t> current_run;
    current_run.push_back(i[0]);
    for (size_t idx = 1; idx < i.size(); ++idx) {
        if (i[idx] - i[idx - 1] == page_size_) {
            current_run.push_back(i[idx]);
        } else {
            result.push_back(current_run);
            current_run.clear();
            current_run.push_back(i[idx]);
        }
    }
    if (!current_run.empty()) {
        result.push_back(current_run);
    }
    return result;
}

/**
 * Retrieve a valid address range that can satisfy the requested size.
 * Optionally, a base address can be specified to test if it can be used
 */
std::pair<uint64_t, uint64_t> MemoryManager::get_valid_ranges(uint64_t size, uint64_t addr) {
    uint64_t page_size = this->page_size_;
 
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
    for (const auto& res : this->mem_reserves_) {
        for (uint64_t i = res->get_base(); i < (res->get_base() + res->get_size()); i += page_size) {
            curr.push_back(i);
        }
    }
 
    // Add already mapped memory (skip free/erased maps)
    for (const auto& m : this->maps_) {
        if (m->is_free()) continue;
        for (uint64_t i = m->get_base(); i < (m->get_base() + m->get_size()); i += page_size) {
            curr.push_back(i);
        }
    }
 
    // Sort and remove duplicates
    std::sort(curr.begin(), curr.end());
    curr.erase(std::unique(curr.begin(), curr.end()), curr.end());
 
    int attempts = 9999;
    while (attempts > 0) {
        bool overlap = false;
        for (uint64_t p = base; p < base + total; p += page_size) {
            if (std::binary_search(curr.begin(), curr.end(), p)) {
                overlap = true;
                break;
            }
        }
        if (!overlap) {
            break;
        }
        if (attempts % 10 == 0) {
            base += page_size * 1000;
        } else {
            base += total;
        }
        attempts--;
    }
 
    if (attempts == 0) {
        throw std::runtime_error("Failed to allocate emulator memory");
    }
 
    return std::make_pair(base, total);
}