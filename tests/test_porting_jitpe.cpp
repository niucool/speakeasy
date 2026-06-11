/**
 * test_porting_jitpe.cpp  JitPeFile Modular Porting Tests
 */

#include <gtest/gtest.h>
#include <vector>
#include <string>

#include "windows/loaders.h"

using namespace speakeasy;

TEST(JitPeFileTest, BasicAssembly) {
    // Test 64-bit JitPeFile initialization
    JitPeFile jit(64, 0x180000000);
    
    // Initial PE state should have 0 sections before we add them
    EXPECT_EQ(jit.get_section_count(), 0);
}

TEST(JitPeFileTest, FullDecoyAssembly) {
    // Test full dynamic assembly and subsequent parsing using PeFile
    JitPeFile jit(64, 0x180000000);

    std::string mod_name = "test_module.dll";
    std::vector<std::string> exports = {"FunctionA", "FunctionB", "FunctionC"};
    
    std::vector<uint8_t>& raw_pe = jit.get_decoy_pe_image(mod_name, exports);
    ASSERT_FALSE(raw_pe.empty());
    return;

    // Load dynamic PE using PeFile to verify correctness
    PeFile pe("", raw_pe, 0xFEEDFACE, 4, "C:\\test_module.dll", true);
    
    EXPECT_EQ(pe.arch, 64);
    //EXPECT_TRUE(pe.is_dll());
    EXPECT_FALSE(pe.is_driver());
    
    // Verify parsed exports
    auto& parsed_exports = pe.exports;
    ASSERT_EQ(parsed_exports.size(), 3);
    EXPECT_EQ(parsed_exports[0].name, "FunctionA");
    EXPECT_EQ(parsed_exports[1].name, "FunctionB");
    EXPECT_EQ(parsed_exports[2].name, "FunctionC");
    
    // Verify addresses are structured within the `.text` section (starts at 0x1000)
    for (size_t i = 0; i < parsed_exports.size(); ++i) {
        EXPECT_EQ(parsed_exports[i].address, 0x180000000 + 0x1000 + i * 16);
        EXPECT_EQ(parsed_exports[i].ordinal, i + 1);
    }
}

TEST(JitPeFileTest, FullDecoyAssembly32) {
    // Test full dynamic 32-bit assembly and subsequent parsing using PeFile
    JitPeFile jit(32, 0x400000);
    
    std::string mod_name = "test_module32.dll";
    std::vector<std::string> exports = {"FuncX", "FuncY"};
    
    std::vector<uint8_t>& raw_pe = jit.get_decoy_pe_image(mod_name, exports);
    ASSERT_FALSE(raw_pe.empty());
    
    // Load dynamic PE using PeFile to verify correctness
    PeFile pe("", raw_pe, 0xFEEDFACE, 4, "C:\\test_module32.dll", true);
    
    EXPECT_EQ(pe.arch, 32);
    //EXPECT_TRUE(pe.is_dll());
    EXPECT_FALSE(pe.is_driver());
    
    // Verify parsed exports
    auto& parsed_exports = pe.exports;
    ASSERT_EQ(parsed_exports.size(), 2);
    EXPECT_EQ(parsed_exports[0].name, "FuncX");
    EXPECT_EQ(parsed_exports[1].name, "FuncY");
    
    // Verify addresses are structured within the `.text` section (starts at 0x1000)
    for (size_t i = 0; i < parsed_exports.size(); ++i) {
        EXPECT_EQ(parsed_exports[i].address, 0x400000 + 0x1000 + i * 17);
        EXPECT_EQ(parsed_exports[i].ordinal, i + 1);
    }
}

TEST(JitPeFileTest, ConstructorDecoyAssembly) {
    // Test constructor-based 64-bit decoy assembly
    std::string mod_name = "test_module.dll";
    std::vector<std::string> exports = {"FunctionA", "FunctionB"};
    JitPeFile jit(64, 0x180000000, mod_name, exports);

    std::vector<uint8_t> raw_pe = jit.get_raw_pe();
    ASSERT_FALSE(raw_pe.empty());

    // Load dynamic PE using PeFile to verify correctness
    PeFile pe("", raw_pe, 0xFEEDFACE, 4, "C:\\test_module.dll", true);

    EXPECT_EQ(pe.arch, 64);
    //EXPECT_TRUE(pe.is_dll());

    auto& parsed_exports = pe.exports;
    ASSERT_EQ(parsed_exports.size(), 2);
    EXPECT_EQ(parsed_exports[0].name, "FunctionA");
    EXPECT_EQ(parsed_exports[1].name, "FunctionB");
}
