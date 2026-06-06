/**
 * test_porting_ntdefs.cpp  NtDefTest (UNICODE_STRING, KSYSTEM_TIME)
 */

#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

#include "winenv/deffs/nt/ntoskrnl.h"

using namespace speakeasy;

//  Helper: returns true when the test is compiled for 64-bit (host platform)
static constexpr bool kIs64 = (sizeof(void*) == 8);

TEST(NtDefTest, UnicodeStringSizeForBothArchitectures) {
    // x86 (<4>): Length(2)+MaxLength(2)+Buffer(4) = 8
    // x64 (<8>): Length(2)+MaxLength(2)+pad(4)+Buffer(8) = 16
    EXPECT_EQ((speakeasy::deffs::nt::UNICODE_STRING<4>().sizeof_obj()),  8);
    EXPECT_EQ((speakeasy::deffs::nt::UNICODE_STRING<8>().sizeof_obj()), 16);
    // Host-native shortcut still works:
    EXPECT_EQ((speakeasy::deffs::nt::UNICODE_STRING<sizeof(void*)>().sizeof_obj()),
              kIs64 ? 16 : 8);
}

TEST(NtDefTest, UnicodeStringBufferAtCorrectOffset) {
    // <4>: Buffer at offset 4
    {
        speakeasy::deffs::nt::UNICODE_STRING<4> us;
        us.Buffer = 0xDEADBEEF;
        auto bytes = us.get_bytes();
        EXPECT_EQ(bytes.size(), 8);
        EXPECT_EQ(bytes[4], 0xEF);  // Buffer LSB at offset 4
    }
    // <8>: Buffer at offset 8 (after 4-byte padding)
    {
        speakeasy::deffs::nt::UNICODE_STRING<8> us;
        us.Buffer = 0xDEADBEEFCAFEULL;
        auto bytes = us.get_bytes();
        EXPECT_EQ(bytes.size(), 16);
        EXPECT_EQ(bytes[8], 0xFE);  // Buffer LSB at offset 8
        EXPECT_EQ(bytes[9], 0xCA);
    }
}

TEST(NtDefTest, KSystemTimeLayout) {
    speakeasy::deffs::nt::KSYSTEM_TIME kt;
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

TEST(NtDefTest, StringStructForBothArchitectures) {
    // <4>: sizeof = 8
    {
        speakeasy::deffs::nt::STRING<4> s;
        s.Length = 4;
        s.MaximumLength = 8;
        s.Buffer = 0x1000;
        auto bytes = s.get_bytes();
        EXPECT_EQ(bytes.size(), 8);
        EXPECT_EQ(bytes[0], 4);   // Length
        EXPECT_EQ(bytes[2], 8);   // MaxLength
    }
    // <8>: sizeof = 16
    {
        speakeasy::deffs::nt::STRING<8> s;
        s.Length = 4;
        s.MaximumLength = 8;
        s.Buffer = 0x1000;
        auto bytes = s.get_bytes();
        EXPECT_EQ(bytes.size(), 16);
        EXPECT_EQ(bytes[0], 4);   // Length
        EXPECT_EQ(bytes[2], 8);   // MaxLength
    }
}
