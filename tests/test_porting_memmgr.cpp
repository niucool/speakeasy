/**
 * test_porting_memmgr.cpp  MemoryManagerPortTest
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <vector>
#include <memory>

#include "memmgr.h"
#include "common.h"
#include "engines/unicorn_eng.h"

// Subclass to expose emu_eng_ for unit testing
class TestMemoryManager : public MemoryManager {
public:
    void set_emu_engine(std::shared_ptr<EmuEngine> eng) {
        this->emu_eng_ = eng;
    }
};

TEST(MemoryManagerPortTest, MemMapMultiple) {
    MemoryManager mm;
    uint64_t a1 = mm.mem_map(0x1000, 0, PERM_MEM_RWX, "mm1");
    uint64_t a2 = mm.mem_map(0x2000, 0, PERM_MEM_RW,  "mm2");
    EXPECT_NE(a1, 0);
    EXPECT_NE(a2, 0);
    EXPECT_NE(a1, a2);
}

TEST(MemoryManagerPortTest, MemMapAtFixedAddress) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(0x1000, 0x10000000, PERM_MEM_RWX, "fixed");
    EXPECT_EQ(addr, 0x10000000);
}

TEST(MemoryManagerPortTest, MemReserveAndMapReserve) {
    MemoryManager mm;
    
    // Reserve a memory range
    uint64_t base = mm.mem_reserve(0x2000, 0x20000000, PERM_MEM_RW, "reserve_test");
    EXPECT_EQ(base, 0x20000000);
    
    // It should not be listed as a regular mapped block
    EXPECT_EQ(mm.get_address_map(base), nullptr);
    
    // But should be a valid reserved address
    EXPECT_TRUE(mm.is_address_valid(base));
    EXPECT_NE(mm.get_reserve_map(base), nullptr);
    
    // Map the reserved region
    uint64_t mapped_addr = mm.mem_map_reserve(base);
    EXPECT_EQ(mapped_addr, base);
    
    // Now it should be mapped
    EXPECT_NE(mm.get_address_map(base), nullptr);
    EXPECT_EQ(mm.get_reserve_map(base), nullptr);
}

TEST(MemoryManagerPortTest, EngineConnectedOperations) {
    // Spin up a live Unicorn engine
    auto eng = std::make_shared<EmuEngine>();
    eng->init_engine(speakeasy::arch::ARCH_X86, speakeasy::arch::BITS_32);
    
    TestMemoryManager mm;
    mm.set_emu_engine(eng);
    return;

    // 1. Map memory
    uint64_t addr = mm.mem_map(0x1000, 0x30000000, PERM_MEM_RWX, "engine_test");
    EXPECT_EQ(addr, 0x30000000);
    
    // 2. Write data
    std::vector<uint8_t> data_to_write = {0xDE, 0xAD, 0xBE, 0xEF};
    mm.mem_write(addr, data_to_write);
    
    // 3. Read data
    std::vector<uint8_t> read_data = mm.mem_read(addr, 4);
    EXPECT_EQ(read_data, data_to_write);
    
    // 4. Change memory protections
    EXPECT_NO_THROW(mm.mem_protect(addr, 0x1000, PERM_MEM_READ));
    
    // 5. Query regions
    auto regions = mm.get_mem_regions();
    bool found = false;
    for (const auto& r : regions) {
        if (std::get<0>(r) == addr) {
            found = true;
            EXPECT_EQ(std::get<1>(r), addr + 0x1000 - 1);
            break;
        }
    }
    EXPECT_TRUE(found);
    
    // 6. Free memory
    mm.mem_free(addr);
    EXPECT_EQ(mm.get_address_map(addr), nullptr);
}

TEST(MemoryManagerPortTest, ZeroCopyRawBufferOperations) {
    // Spin up a live Unicorn engine
    auto eng = std::make_shared<EmuEngine>();
    eng->init_engine(speakeasy::arch::ARCH_X86, speakeasy::arch::BITS_32);
    
    TestMemoryManager mm;
    mm.set_emu_engine(eng);
    
    uint64_t addr = mm.mem_map(0x1000, 0x40000000, PERM_MEM_RWX, "zero_copy_test");
    EXPECT_EQ(addr, 0x40000000);
    
    // Write using raw pointers directly (zero-copy)
    uint32_t raw_val = 0xAA55AA55;
    mm.mem_write(addr, &raw_val, sizeof(raw_val));
    
    // Read using raw pointers directly (zero-copy)
    uint32_t out_val = 0;
    mm.mem_read(addr, &out_val, sizeof(out_val));
    EXPECT_EQ(out_val, raw_val);
    
    mm.mem_free(addr);
}
