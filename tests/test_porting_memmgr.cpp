/**
 * test_porting_memmgr.cpp  MemoryManagerPortTest
 */

#include <gtest/gtest.h>
#include <cstdint>

#include "memmgr.h"
#include "common.h"

TEST(MemoryManagerPortTest, MemMapMultiple) {
    MemoryManager mm;
    uint64_t a1 = mm.mem_map(0x1000, 0, PERM_MEM_RWX, "mm1");
    uint64_t a2 = mm.mem_map(0x2000, 0, PERM_MEM_RW,  "mm2");
    EXPECT_NE(a1, 0);
    EXPECT_NE(a2, 0);
}

TEST(MemoryManagerPortTest, MemMapAtFixedAddress) {
    MemoryManager mm;
    uint64_t addr = mm.mem_map(0x1000, 0x10000000, PERM_MEM_RWX, "fixed");
    EXPECT_EQ(addr, 0x10000000);
}
