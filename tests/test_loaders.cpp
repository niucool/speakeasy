/**
 * test_loaders.cpp  Port of test_loaders.py
 * Tests PE loader, API module loader, and RuntimeModule export handling.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "windows/loaders.h"
#include "windows/common.h"
#include "winenv/arch.h"

using namespace speakeasy;

namespace {

std::shared_ptr<LoadedImage> make_image(
    const std::string& module_type = "dll",
    uint64_t image_base = 0x400000,
    const std::vector<ExportEntry>& exports = {},
    const std::string& emu_path = "C:\\Windows\\System32\\kernel32.dll")
{
    auto img = std::make_shared<LoadedImage>();
    img->arch = speakeasy::arch::ARCH_X86;
    img->module_type = module_type;
    img->name = "kernel32";
    img->emu_path = emu_path;
    img->base = image_base;
    img->image_size = 0x10000;
    img->visible_in_peb = true;
    img->exports = exports;
    return img;
}

} // namespace

TEST(LoadersTest, RuntimeModuleExportLookupAndBaseName) {
    std::vector<ExportEntry> exports = {
        ExportEntry{"DllMain", 0x401000, "", 1, "intercepted"},
        ExportEntry{"Init", 0x402000, "", 2, "intercepted"},
    };
    auto img = make_image("dll", 0x400000, exports);
    RuntimeModule mod(img);

    EXPECT_EQ(mod.get_base_name(), "kernel32.dll");

    auto* found = mod.get_export_by_name("Init");
    EXPECT_NE(found, nullptr);
    EXPECT_EQ(found->address, 0x402000);

    auto* not_found = mod.get_export_by_name("NoSuchExport");
    EXPECT_EQ(not_found, nullptr);
}

TEST(LoadersTest, RuntimeModuleGetBaseNameUsesEmuPath) {
    auto img = make_image("dll", 0x400000, {},
                          "C:\\Windows\\System32\\ntdll.dll");
    img->name = "ntdll";
    RuntimeModule mod(img);
    EXPECT_EQ(mod.get_base_name(), "ntdll.dll");
}

TEST(LoadersTest, ImageFactoryCreatesValidImage) {
    auto img = make_image();
    EXPECT_EQ(img->arch, speakeasy::arch::ARCH_X86);
    EXPECT_EQ(img->module_type, "dll");
    EXPECT_EQ(img->name, "kernel32");
    EXPECT_EQ(img->base, 0x400000);
    EXPECT_GT(img->image_size, 0);
    EXPECT_TRUE(img->visible_in_peb);
}

TEST(LoadersTest, ExportEntryDefaultValues) {
    ExportEntry entry;
    EXPECT_EQ(entry.name, "");
    EXPECT_EQ(entry.address, 0);
    EXPECT_EQ(entry.forwarder, "");
    EXPECT_EQ(entry.ordinal, 0);
    EXPECT_EQ(entry.execution_mode, "");
}
