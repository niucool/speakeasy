/**
 * test_porting_ntdefs.cpp  NtDefTest (UNICODE_STRING, KSYSTEM_TIME)
 */

#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

#include "winenv/deffs/nt/ntoskrnl.h"

using namespace speakeasy;
constexpr int kPtrSize = sizeof(void*);

TEST(NtDefTest, UnicodeStringOffsets) {
    speakeasy::deffs::UNICODE_STRING<kPtrSize> us;
    EXPECT_EQ(us.sizeof_obj(), 16);  // x64: Len(2)+Max(2)+pad(4)+Buf(8)
}

TEST(NtDefTest, UnicodeStringBufferAtOffset8) {
    speakeasy::deffs::UNICODE_STRING<kPtrSize> us;
    us.Buffer = 0xDEADBEEFCAFEULL;
    auto bytes = us.get_bytes();
    EXPECT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[8], 0xFE);
    EXPECT_EQ(bytes[9], 0xCA);
}

TEST(NtDefTest, KSystemTimeLayout) {
    speakeasy::deffs::KSYSTEM_TIME kt;
    kt.LowPart   = 0xAABBCCDD;
    kt.High1Time = 0x11223344;
    kt.High2Time = 0x55667788;
    EXPECT_EQ(kt.sizeof_obj(), 12);
    auto bytes = kt.get_bytes();
    EXPECT_EQ(bytes.size(), 12);
    EXPECT_EQ(bytes[0],  0xDD);  // LowPart LSB
    EXPECT_EQ(bytes[3],  0xAA);  // LowPart MSB
    EXPECT_EQ(bytes[4],  0x44);  // High1Time LSB
    EXPECT_EQ(bytes[7],  0x11);  // High1Time MSB
    EXPECT_EQ(bytes[8],  0x88);  // High2Time LSB
    EXPECT_EQ(bytes[11], 0x55);  // High2Time MSB
}

TEST(NtDefTest, StringStruct) {
    speakeasy::deffs::STRING<kPtrSize> s;
    s.Length = 4;
    s.MaximumLength = 8;
    s.Buffer = 0x1000;
    auto bytes = s.get_bytes();
    EXPECT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[0], 4);   // Length
    EXPECT_EQ(bytes[2], 8);   // MaxLength
}
