#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <cstdint>
#include <type_traits>
#include "struct.h"

namespace speakeasy {
} // namespace speakeasy

using namespace speakeasy;

#pragma pack(push, 1)

// 1. Simple POD structure
struct MockFixedStruct : public EmuStructHelper<MockFixedStruct> {
    uint32_t a = 0;
    uint16_t b = 0;
    uint8_t  c = 0;
};

// 2. Struct templated by pointer size (4 or 8)
template <int PtrSize>
struct MockDynamicStruct : public EmuStructHelper<MockDynamicStruct<PtrSize>> {
    using Ptr = typename std::conditional<PtrSize == 8, uint64_t, uint32_t>::type;
    uint32_t magic = 0x12345678;
    Ptr      ptr_val = 0;
    uint16_t ending = 0xAAAA;
};

// 3. Nested structures: using a nested POD struct (which does NOT have a vptr)
// to avoid inner vptr corruption and allow easy serialization.
struct InnerPod {
    uint32_t x = 0;
    uint32_t y = 0;
};

struct OuterStruct : public EmuStructHelper<OuterStruct> {
    uint32_t header = 0xFFFFFFFF;
    InnerPod inner;
    uint32_t footer = 0xEECCCCCC;
};

// 4. Structure with array of PODs
struct MockArrayStruct : public EmuStructHelper<MockArrayStruct> {
    uint32_t id = 0;
    uint8_t  payload[8] = {};
    uint16_t crc = 0;
};

// 5. Structure with custom virtual method override (polymorphic verification)
struct MockPolymorphicStruct : public EmuStructHelper<MockPolymorphicStruct> {
    uint32_t data_val = 0xDEADC0DE;
    std::string get_mem_tag() const override {
        return "mock_poly";
    }
};

// 6. Mock of a LIST_ENTRY structure templated by pointer size
template <int PtrSize>
struct MockListEntry : public EmuStructHelper<MockListEntry<PtrSize>> {
    using Ptr = typename std::conditional<PtrSize == 8, uint64_t, uint32_t>::type;
    Ptr Flink = 0;
    Ptr Blink = 0;

    std::string get_mem_tag() const override {
        return "list_entry";
    }
};

#pragma pack(pop)

TEST(EmuStructHelperTest, FixedSizeStruct) {
    MockFixedStruct obj;
    obj.a = 0x11223344;
    obj.b = 0x5566;
    obj.c = 0x77;

    // Check size: sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) = 7
    EXPECT_EQ(obj.sizeof_obj(), 7);

    auto bytes = obj.get_bytes();
    ASSERT_EQ(bytes.size(), 7);
    EXPECT_EQ(bytes[0], 0x44); // Little endian
    EXPECT_EQ(bytes[3], 0x11);
    EXPECT_EQ(bytes[4], 0x66);
    EXPECT_EQ(bytes[5], 0x55);
    EXPECT_EQ(bytes[6], 0x77);

    // Test deserialization
    MockFixedStruct obj2;
    std::vector<uint8_t> new_data = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x99};
    obj2.from_bytes(new_data);
    EXPECT_EQ(obj2.a, 0xDDCCBBAA);
    EXPECT_EQ(obj2.b, 0x2211);
    EXPECT_EQ(obj2.c, 0x99);

    // Verify vptr is intact by calling virtual function polymorphically
    EmuStruct* poly = &obj2;
    EXPECT_EQ(poly->sizeof_obj(), 7);
}

TEST(EmuStructHelperTest, DynamicSizeStruct32) {
    MockDynamicStruct<4> obj;
    obj.magic = 0x11223344;
    obj.ptr_val = 0xAABBCCDD;
    obj.ending = 0x5566;

    // Size: 4 (magic) + 4 (ptr) + 2 (ending) = 10
    EXPECT_EQ(obj.sizeof_obj(), 10);

    auto bytes = obj.get_bytes();
    ASSERT_EQ(bytes.size(), 10);
    EXPECT_EQ(bytes[0], 0x44);
    EXPECT_EQ(bytes[4], 0xDD);
    EXPECT_EQ(bytes[8], 0x66);

    MockDynamicStruct<4> obj2;
    obj2.from_bytes(bytes);
    EXPECT_EQ(obj2.magic, 0x11223344);
    EXPECT_EQ(obj2.ptr_val, 0xAABBCCDD);
    EXPECT_EQ(obj2.ending, 0x5566);
}

TEST(EmuStructHelperTest, DynamicSizeStruct64) {
    MockDynamicStruct<8> obj;
    obj.magic = 0x11223344;
    obj.ptr_val = 0x1122334455667788ULL;
    obj.ending = 0x5566;

    // Size: 4 (magic) + 8 (ptr) + 2 (ending) = 14
    EXPECT_EQ(obj.sizeof_obj(), 14);

    auto bytes = obj.get_bytes();
    ASSERT_EQ(bytes.size(), 14);
    EXPECT_EQ(bytes[0], 0x44);
    EXPECT_EQ(bytes[4], 0x88);
    EXPECT_EQ(bytes[12], 0x66);

    MockDynamicStruct<8> obj2;
    obj2.from_bytes(bytes);
    EXPECT_EQ(obj2.magic, 0x11223344);
    EXPECT_EQ(obj2.ptr_val, 0x1122334455667788ULL);
    EXPECT_EQ(obj2.ending, 0x5566);
}

TEST(EmuStructHelperTest, NestedPodStruct) {
    OuterStruct obj;
    obj.header = 0x11223344;
    obj.inner.x = 0x55667788;
    obj.inner.y = 0x99AABBCC;
    obj.footer = 0xDDEEFF00;

    // Size: 4 + 8 + 4 = 16
    EXPECT_EQ(obj.sizeof_obj(), 16);

    auto bytes = obj.get_bytes();
    ASSERT_EQ(bytes.size(), 16);
    EXPECT_EQ(bytes[0], 0x44);
    EXPECT_EQ(bytes[4], 0x88);
    EXPECT_EQ(bytes[8], 0xCC);
    EXPECT_EQ(bytes[12], 0x00);

    OuterStruct obj2;
    obj2.from_bytes(bytes);
    EXPECT_EQ(obj2.header, 0x11223344);
    EXPECT_EQ(obj2.inner.x, 0x55667788);
    EXPECT_EQ(obj2.inner.y, 0x99AABBCC);
    EXPECT_EQ(obj2.footer, 0xDDEEFF00);
}

TEST(EmuStructHelperTest, ArrayStructSerialization) {
    MockArrayStruct obj;
    obj.id = 0x99999999;
    std::memcpy(obj.payload, "ABCDEFGH", 8);
    obj.crc = 0x5555;

    // Size: 4 + 8 + 2 = 14
    EXPECT_EQ(obj.sizeof_obj(), 14);

    auto bytes = obj.get_bytes();
    ASSERT_EQ(bytes.size(), 14);

    MockArrayStruct obj2;
    obj2.from_bytes(bytes);
    EXPECT_EQ(obj2.id, 0x99999999);
    EXPECT_EQ(std::memcmp(obj2.payload, "ABCDEFGH", 8), 0);
    EXPECT_EQ(obj2.crc, 0x5555);
}

TEST(EmuStructHelperTest, PolymorphicMethodPreservation) {
    MockPolymorphicStruct obj;
    obj.data_val = 0x88888888;

    EmuStruct* poly_ptr = &obj;
    EXPECT_EQ(poly_ptr->get_mem_tag(), "mock_poly");
    EXPECT_EQ(poly_ptr->sizeof_obj(), 4);

    // Serialize
    auto bytes = poly_ptr->get_bytes();
    ASSERT_EQ(bytes.size(), 4);

    // Deserialize and check virtual method table still functions correctly
    MockPolymorphicStruct obj2;
    EmuStruct* poly_ptr2 = &obj2;
    poly_ptr2->from_bytes(bytes);

    EXPECT_EQ(obj2.data_val, 0x88888888);
    EXPECT_EQ(poly_ptr2->get_mem_tag(), "mock_poly");
}

TEST(EmuStructHelperTest, DeserializationBoundsChecking) {
    MockFixedStruct obj;
    std::vector<uint8_t> short_data = {1, 2, 3, 4}; // only 4 bytes, needs 7
    EXPECT_THROW(obj.from_bytes(short_data), EmuStructException);
}

TEST(EmuStructHelperTest, MockListEntryLayout32) {
    MockListEntry<4> le;
    le.Flink = 0x11111111;
    le.Blink = 0x22222222;

    EXPECT_EQ(le.sizeof_obj(), 8);
    EXPECT_EQ(le.get_mem_tag(), "list_entry");

    auto bytes = le.get_bytes();
    ASSERT_EQ(bytes.size(), 8);
    EXPECT_EQ(read_le(bytes, 0, 4), 0x11111111);
    EXPECT_EQ(read_le(bytes, 4, 4), 0x22222222);

    MockListEntry<4> le2;
    le2.from_bytes(bytes);
    EXPECT_EQ(le2.Flink, 0x11111111);
    EXPECT_EQ(le2.Blink, 0x22222222);
}

TEST(EmuStructHelperTest, MockListEntryLayout64) {
    MockListEntry<8> le;
    le.Flink = 0x1111111122222222ULL;
    le.Blink = 0x3333333344444444ULL;

    EXPECT_EQ(le.sizeof_obj(), 16);
    EXPECT_EQ(le.get_mem_tag(), "list_entry");

    auto bytes = le.get_bytes();
    ASSERT_EQ(bytes.size(), 16);
    EXPECT_EQ(read_le(bytes, 0, 8), 0x1111111122222222ULL);
    EXPECT_EQ(read_le(bytes, 8, 8), 0x3333333344444444ULL);

    MockListEntry<8> le2;
    le2.from_bytes(bytes);
    EXPECT_EQ(le2.Flink, 0x1111111122222222ULL);
    EXPECT_EQ(le2.Blink, 0x3333333344444444ULL);
}

#include "winenv/deffs/nt/ntoskrnl.h"
#include "winenv/deffs/ndis/ndis.h"
#include "winenv/deffs/usb.h"
#include "winenv/deffs/registry/reg.h"
#include "winenv/deffs/wdf.h"

using namespace speakeasy::defs::new_structs;

TEST(EmuStructHelperTest, NewListEntryLayout) {
    LIST_ENTRY<4> le32;
    EXPECT_EQ(le32.sizeof_obj(), 8);
    
    LIST_ENTRY<8> le64;
    EXPECT_EQ(le64.sizeof_obj(), 16);
}

TEST(EmuStructHelperTest, NewUnicodeStringLayout) {
    UNICODE_STRING<4> us32;
    EXPECT_EQ(us32.sizeof_obj(), 8); // USHORT + USHORT + Ptr(4) = 8
    
    UNICODE_STRING<8> us64;
    EXPECT_EQ(us64.sizeof_obj(), 16); // USHORT + USHORT + padding(4) + Ptr(8) = 16
}

TEST(EmuStructHelperTest, NewObjectAttributesLayout) {
    OBJECT_ATTRIBUTES<4> oa32;
    EXPECT_EQ(oa32.sizeof_obj(), 24);
    
    OBJECT_ATTRIBUTES<8> oa64;
    EXPECT_EQ(oa64.sizeof_obj(), 48);
}

TEST(EmuStructHelperTest, NewFixedStructures) {
    KSYSTEM_TIME kt;
    EXPECT_EQ(kt.sizeof_obj(), 12);
    
    LARGE_INTEGER li;
    EXPECT_EQ(li.sizeof_obj(), 8);
    
    SYSTEM_TIMEOFDAY_INFORMATION st;
    EXPECT_EQ(st.sizeof_obj(), 48);
    
    DISK_EXTENT de;
    EXPECT_EQ(de.sizeof_obj(), 24); // 4 + 4(padding) + 8 + 8 = 24
    
    VOLUME_DISK_EXTENTS vde;
    EXPECT_EQ(vde.sizeof_obj(), 32); // 4 + 4(padding) + 24 = 32
    
    NDIS_OBJECT_HEADER noh;
    EXPECT_EQ(noh.sizeof_obj(), 4);
    
    USB_DEVICE_DESCRIPTOR udd;
    EXPECT_EQ(udd.sizeof_obj(), 18);
    
    WDF_VERSION wv;
    EXPECT_EQ(wv.sizeof_obj(), 12);
}

