/**
 * test_porting_pefile.cpp  PE File Memory Mapped Image Tests
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "windows/loaders.h"
#include "struct.h"

using namespace speakeasy;

TEST(PeFileMemoryMappedImageTest, GetMemoryMappedImage) {
    std::string test_pe_path = "tests/bins/antidbg.exe";
    std::vector<uint8_t> empty_data;
    PeFile pe(test_pe_path, empty_data, 0, 0, test_pe_path, false);

    auto mapped = pe.get_memory_mapped_image(0xF0000000);
    EXPECT_GT(mapped.size(), 0);
    EXPECT_LE(mapped.size(), pe.image_size);

    auto sections = pe.get_sections();
    EXPECT_FALSE(sections.empty());
    for (auto& s : sections) {
        if (s.raw_size > 0 && s.virtual_address > 0) {
            EXPECT_LT(s.virtual_address, mapped.size());
            EXPECT_LE(s.virtual_address + s.raw_size, mapped.size());
        }
    }
}

TEST(PeFileMemoryMappedImageTest, GetTlsCallbacksAndReloc) {
    std::string test_pe_path = "tests/bins/antidbg.exe";
    std::vector<uint8_t> empty_data;
    PeFile pe(test_pe_path, empty_data, 0, 0, test_pe_path, false);

    auto callbacks = pe.get_tls_callbacks();
    bool has_relocs = pe.has_reloc_table();
    // antidbg.exe usually has a relocation table (standard build)
    EXPECT_TRUE(has_relocs);
}

TEST(PeFileMemoryMappedImageTest, RelocateImage) {
    std::string test_pe_path = "tests/bins/antidbg.exe";
    std::vector<uint8_t> empty_data;
    PeFile pe(test_pe_path, empty_data, 0, 0, test_pe_path, false);

    ASSERT_TRUE(pe.has_reloc_table());
    auto orig_mapped = pe.mapped_image;

    auto* parsed = pe.get_parsed_pe();
    ASSERT_NE(parsed, nullptr);

    auto reloc_dir = parsed->peHeader.nt.OptionalHeader.DataDirectory[5];
    ASSERT_GT(reloc_dir.Size, 0);
    ASSERT_GT(reloc_dir.VirtualAddress, 0);

    uint64_t reloc_rva = reloc_dir.VirtualAddress;
    uint32_t page_rva = static_cast<uint32_t>(speakeasy::read_le(orig_mapped, reloc_rva, 4));
    uint32_t block_size = static_cast<uint32_t>(speakeasy::read_le(orig_mapped, reloc_rva + 4, 4));

    ASSERT_GE(block_size, 8);

    uint32_t num_entries = (block_size - 8) / 2;
    uint64_t target_rva = 0;
    uint16_t target_type = 0;

    for (uint32_t i = 0; i < num_entries; ++i) {
        uint16_t descriptor = static_cast<uint16_t>(speakeasy::read_le(orig_mapped, reloc_rva + 8 + i * 2, 2));
        uint16_t type = descriptor >> 12;
        uint16_t offset = descriptor & 0x0FFF;
        if (type == 3 || type == 10) {
            target_rva = static_cast<uint64_t>(page_rva) + offset;
            target_type = type;
            break;
        }
    }

    ASSERT_GT(target_rva, 0);

    uint64_t orig_val = 0;
    if (target_type == 3) {
        orig_val = speakeasy::read_le(orig_mapped, target_rva, 4);
    } else {
        orig_val = speakeasy::read_le(orig_mapped, target_rva, 8);
    }

    uint64_t orig_base = parsed->peHeader.nt.OptionalHeader.ImageBase;
    uint64_t new_base = 0x20000000;
    uint64_t delta = new_base - orig_base;

    pe.rebase(new_base);

    auto new_mapped = pe.mapped_image;
    uint64_t new_val = 0;
    if (target_type == 3) {
        new_val = speakeasy::read_le(new_mapped, target_rva, 4);
        EXPECT_EQ(new_val, (orig_val + delta) & 0xFFFFFFFF);
    } else {
        new_val = speakeasy::read_le(new_mapped, target_rva, 8);
        EXPECT_EQ(new_val, orig_val + delta);
    }
}
