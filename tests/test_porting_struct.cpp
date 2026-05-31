/**
 * test_porting_struct.cpp  StructLayoutTest (EmuStruct byte layout, write_le)
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdint>
#include <vector>

#include "struct.h"
#include "windows/winemu.h"
#include "windows/win32.h"
#include "config.h"

using namespace speakeasy;

class DEEP_NEST : public EmuStruct {
public:
    uint32_t Field1 = 0;
    uint32_t Field2 = 0;
    uint8_t  DeepData[32] = {};
    size_t sizeof_obj() const override { return 40; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(40);
        write_le(b, 0, Field1, 4);
        write_le(b, 4, Field2, 4);
        memcpy(b.data() + 8, DeepData, 32);
        return b;
    }
};

struct SHALLOW_NEST : public EmuStruct {
    uint16_t Field1 = 0;
    DEEP_NEST DeepStruct;
    uint16_t Field2 = 0;
    size_t sizeof_obj() const override { return 44; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(44);
        write_le(b, 0, Field1, 2);
        auto deep_bytes = DeepStruct.get_bytes();
        memcpy(b.data() + 2, deep_bytes.data(), deep_bytes.size());
        write_le(b, 42, Field2, 2);
        return b;
    }
};

TEST(StructLayoutTest, NestedEmuStruct32bit) {
    DEEP_NEST deep;
    deep.Field1 = 0x06060606;
    deep.Field2 = 0x07070707;
    memset(deep.DeepData, 'A', 32);
    SHALLOW_NEST shallow;
    shallow.Field1 = 0x0505;
    shallow.DeepStruct = deep;
    shallow.Field2 = 0x0808;
    auto bytes = shallow.get_bytes();
    ASSERT_EQ(bytes.size(), 44);
    EXPECT_EQ(bytes[0], 0x05); EXPECT_EQ(bytes[1], 0x05);
    EXPECT_EQ(bytes[2], 0x06); EXPECT_EQ(bytes[5], 0x06);
    EXPECT_EQ(bytes[10], 'A'); EXPECT_EQ(bytes[41], 'A');
    EXPECT_EQ(bytes[42], 0x08); EXPECT_EQ(bytes[43], 0x08);
}

TEST(StructLayoutTest, DefaultValuesAreZero) {
    DEEP_NEST deep;
    auto b = deep.get_bytes();
    for (uint8_t byte : b) EXPECT_EQ(byte, 0);
}

TEST(StructLayoutTest, WriteLeUint32) {
    std::vector<uint8_t> buf(8, 0);
    write_le(buf, 0, 0xAABBCCDDUL, 4);
    EXPECT_EQ(buf[0], 0xDD);
    EXPECT_EQ(buf[3], 0xAA);
}

// Custom EmuStruct test subclass for verifying SFINAE polymorphism
class MockPolyStruct : public EmuStruct {
public:
    uint32_t val = 0xCCDDEEFF;
    size_t sizeof_obj() const override { return 100; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> data(100, 0xAB);
        write_le(data, 0, val, 4);
        return data;
    }
};

TEST(StructLayoutTest, PolymorphicStructSerialization) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    MockPolyStruct poly;

    // Verify polymorphic size resolved correctly via objsize template overload
    EXPECT_EQ(emu.objsize(poly), 100);

    // Verify polymorphic byte serialization resolved correctly via get_bytes template overload
    auto bytes = emu.get_bytes(poly);
    ASSERT_EQ(bytes.size(), 100);
    EXPECT_EQ(bytes[0], 0xFF);
    EXPECT_EQ(bytes[1], 0xEE);
    EXPECT_EQ(bytes[2], 0xDD);
    EXPECT_EQ(bytes[3], 0xCC);
    EXPECT_EQ(bytes[4], 0xAB); // filled byte
}

#pragma pack(push, 1)
struct SimplePod {
    uint32_t a;
    uint16_t b;
    uint8_t c;
};
#pragma pack(pop)

TEST(StructLayoutTest, DirectPodCastTest) {
    SimplePod pod;
    pod.a = 0xAABBCCDD;
    pod.b = 0x1122;
    pod.c = 0x99;

    std::vector<uint8_t> buf;
    // Serialize POD to buffer
    cast_to_bytes(buf, 0, pod);
    ASSERT_EQ(buf.size(), sizeof(SimplePod));

    // Verify raw byte ordering
    EXPECT_EQ(buf[0], 0xDD);
    EXPECT_EQ(buf[3], 0xAA);
    EXPECT_EQ(buf[4], 0x22);
    EXPECT_EQ(buf[5], 0x11);
    EXPECT_EQ(buf[6], 0x99);

    // Deserialize back and assert correctness
    auto deserialized = cast_from_bytes<SimplePod>(buf, 0);
    EXPECT_EQ(deserialized.a, 0xAABBCCDD);
    EXPECT_EQ(deserialized.b, 0x1122);
    EXPECT_EQ(deserialized.c, 0x99);

    // Test offset validation out of bounds throws
    EXPECT_THROW(cast_from_bytes<SimplePod>(buf, 1), EmuStructException);
}
