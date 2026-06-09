/**
 * test_process_parameters.cpp  Port of test_process_parameters.py
 * Tests RTL_USER_PROCESS_PARAMETERS struct offsets and CURDIR sizes.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <vector>

#include "winenv/deffs/nt/ntoskrnl.h"

using namespace speakeasy::deffs::nt;

TEST(ProcessParametersTest, CurdirSizesX86) {
    EXPECT_EQ(sizeof(CURDIR_POD<4>), 12);  // x86 = UNICODE_STRING(8) + HANDLE(4)
}

TEST(ProcessParametersTest, CurdirSizesX64) {
    EXPECT_EQ(sizeof(CURDIR_POD<8>), 24);  // x64 = UNICODE_STRING(16) + HANDLE(8)
}

TEST(ProcessParametersTest, UnicodeStringSizes) {
    auto sz32 = sizeof(UNICODE_STRING_POD<4>);
    auto sz64 = sizeof(UNICODE_STRING_POD<8>);
    EXPECT_EQ(sz32, 8);
    EXPECT_EQ(sz64, 16);
}

TEST(ProcessParametersTest, StructSizeSanity) {
    EXPECT_GT(sizeof(RTL_USER_PROCESS_PARAMETERS_POD<4>), 0);
    EXPECT_GT(sizeof(RTL_USER_PROCESS_PARAMETERS_POD<8>), 0);
}

TEST(ProcessParametersTest, FieldAccessBytesX86) {
    RTL_USER_PROCESS_PARAMETERS_POD<4> params;
    memset(&params, 0, sizeof(params));

    params.Flags = 1;
    params.ConsoleHandle = 0xDEAD;
    params.StandardInput = 0xF001;
    params.ImagePathName.Length = 20;
    params.ImagePathName.Buffer = 0x1000;
    params.CurrentDirectory.DosPath.Length = 10;
    params.CurrentDirectory.DosPath.Buffer = 0x2000;

    auto* data = reinterpret_cast<const uint8_t*>(&params);
    size_t size = sizeof(params);
    ASSERT_GE(size, 0x44);

    auto read_u32 = [&](size_t off) -> uint32_t {
        return *reinterpret_cast<const uint32_t*>(data + off);
    };
    auto read_u16 = [&](size_t off) -> uint16_t {
        return *reinterpret_cast<const uint16_t*>(data + off);
    };

    // Offsets verified against Windows SDK
    EXPECT_EQ(read_u32(0x08), 1);       // Flags
    EXPECT_EQ(read_u32(0x10), 0xDEAD);  // ConsoleHandle
    EXPECT_EQ(read_u32(0x18), 0xF001);  // StandardInput
    EXPECT_EQ(read_u16(0x38), 20);      // ImagePathName.Length
    EXPECT_EQ(read_u32(0x3C), 0x1000);  // ImagePathName.Buffer
    EXPECT_EQ(read_u16(0x24), 10);      // CurrentDirectory.DosPath.Length
    EXPECT_EQ(read_u32(0x28), 0x2000);  // CurrentDirectory.DosPath.Buffer
}
