/*
 * test_scylla_wrapper.cpp — Tests for scylla_wrapper with Speakeasy emulator.
 */
#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>
#include <filesystem>

#include "speakeasy.h"
#include "config.h"
#include "scylla_wrapper/scylla_wrapper.h"
#include "scylla_wrapper/SpeakeasyAccess.h"
#include "scylla_wrapper/ProcessAccessHelp.h"
#include "test_helper.h"

using namespace speakeasy;
namespace fs = std::filesystem;

// ============================================================================
// Unit tests — no emulation needed, test API contract
// ============================================================================

TEST(ScyllaWrapperTest, SetEmulatorStoresPointer) {
    SpeakeasyConfig cfg;
    Speakeasy se(cfg);
    scylla_setEmulator(&se);
    EXPECT_EQ(SpeakeasyAccess::emulator(), &se);

    scylla_setEmulator(nullptr);
    EXPECT_EQ(SpeakeasyAccess::emulator(), nullptr);
}

TEST(ScyllaWrapperTest, DumpProcessWithoutEmulatorReturnsFalse) {
    scylla_setEmulator(nullptr);
    EXPECT_FALSE(scylla_dumpProcessA(0, "dummy.exe", 0x400000, 0x1000, "out.bin"));
    EXPECT_FALSE(scylla_dumpProcessW(0, L"dummy.exe", 0x400000, 0x1000, L"out.bin"));
}

TEST(ScyllaWrapperTest, ImportCountsStartAtZero) {
    scylla_setEmulator(nullptr);
    EXPECT_EQ(scylla_getModuleCount(), 0);
    EXPECT_EQ(scylla_getImportCount(), 0);
    EXPECT_TRUE(scylla_importsValid());
}

TEST(ScyllaWrapperTest, SearchIATWithoutEmulatorFails) {
    scylla_setEmulator(nullptr);
    DWORD_PTR iatStart = 0;
    DWORD iatSize = 0;
    int r = scylla_searchIAT(0, iatStart, iatSize, 0, false);
    EXPECT_EQ(r, SCY_ERROR_PROCOPEN);
}

TEST(ScyllaWrapperTest, GetImportsWithoutEmulatorFails) {
    scylla_setEmulator(nullptr);
    int r = scylla_getImports(0x2000, 0x100, 0);
    EXPECT_EQ(r, SCY_ERROR_PROCOPEN);
}

// ============================================================================
// Integration tests — require loaded PE + Speakeasy
// ============================================================================

class ScyllaWrapperEmuTest : public ::testing::Test {
protected:
    Speakeasy* speakeasy_ = nullptr;

    void SetUp() override {
        auto data = load_test_bin("argv_test_x86.exe");
        if (data.empty()) {
            GTEST_SKIP() << "argv_test_x86.exe not available";
        }

        speakeasy::SpeakeasyConfig cfg;
        speakeasy_ = new Speakeasy(cfg);

        try {
            auto module = speakeasy_->load_module("", data);
            ASSERT_NE(module, nullptr) << "Failed to load test binary";
        } catch (const std::exception& e) {
            GTEST_SKIP() << "Failed to load module: " << e.what();
        }

        scylla_setEmulator(speakeasy_);
    }

    void TearDown() override {
        scylla_setEmulator(nullptr);
        if (speakeasy_) {
            speakeasy_->shutdown();
            delete speakeasy_;
            speakeasy_ = nullptr;
        }
    }
};

TEST_F(ScyllaWrapperEmuTest, EmulatorAccessReadsMemory) {
    auto modules = speakeasy_->get_user_modules();
    ASSERT_FALSE(modules.empty());

    auto& mod = modules[0];
    BYTE buf[64] = {};
    bool ok = SpeakeasyAccess::readMemory(mod->base, sizeof(buf), buf);

    EXPECT_TRUE(ok);
    if (ok) {
        WORD* magic = reinterpret_cast<WORD*>(buf);
        EXPECT_EQ(*magic, IMAGE_DOS_SIGNATURE);
    }
}
TEST_F(ScyllaWrapperEmuTest, GetModulesReturnsModuleList) {
    std::vector<ModuleInfo> mods;
    bool ok = SpeakeasyAccess::getModules(mods);
    EXPECT_TRUE(ok);
    EXPECT_FALSE(mods.empty());
}

TEST_F(ScyllaWrapperEmuTest, GetMemoryRegionReturnsValidRange) {
    auto modules = speakeasy_->get_user_modules();
    ASSERT_FALSE(modules.empty());

    DWORD_PTR regionBase = 0;
    SIZE_T regionSize = 0;
    bool ok = SpeakeasyAccess::getMemoryRegion(
        modules[0]->base, &regionBase, &regionSize);

    EXPECT_TRUE(ok);
    if (ok) EXPECT_GT(regionSize, 0u);
}

TEST_F(ScyllaWrapperEmuTest, GetSizeOfImageReturnsNonZero) {
    auto modules = speakeasy_->get_user_modules();
    ASSERT_FALSE(modules.empty());

    SIZE_T imageSize = SpeakeasyAccess::getSizeOfImage(modules[0]->base);
    EXPECT_GT(imageSize, 0u);
}

TEST_F(ScyllaWrapperEmuTest, DumpProcessFromEmulatedMemory) {
    auto modules = speakeasy_->get_user_modules();
    ASSERT_FALSE(modules.empty());

    auto& mod = modules[0];
    auto tmpPath = fs::temp_directory_path() / "scylla_dump_test.exe";

    std::string pathStr = tmpPath.string();
    std::wstring dumpPathW(pathStr.begin(), pathStr.end());

    bool ok = scylla_dumpProcessW(
        0, nullptr, mod->base, mod->ep, dumpPathW.c_str());

    SUCCEED() << (ok ? "Dump succeeded" : "Dump returned false");

    std::error_code ec;
    fs::remove(tmpPath, ec);
}
