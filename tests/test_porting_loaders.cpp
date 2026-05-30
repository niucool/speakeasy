/**
 * test_porting_loaders.cpp  LoaderModuleClassificationTest
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#include "windows/loaders.h"

using namespace speakeasy;

TEST(LoaderModuleClassificationTest, SubsystemCUIExeClassification) {
    auto img = std::make_shared<LoadedImage>();
    img->is_driver = false;
    img->is_dll = false;
    img->is_decoy = false;
    img->metadata.subsystem = 3;  // IMAGE_SUBSYSTEM_WINDOWS_CUI
    img->base = 0x400000;
    img->image_size = 0x1000;
    img->ep = 0x1000;

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_exe());
    EXPECT_FALSE(mod.is_dll());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_FALSE(mod.is_decoy());
    EXPECT_EQ(mod.module_type, "exe");
}

TEST(LoaderModuleClassificationTest, DecoyLoaderClassification) {
    DecoyLoader loader("kernel32.dll", 0x77000000, "C:\\Windows\\System32\\kernel32.dll", 0x100000);
    auto img = loader.make_image();
    EXPECT_TRUE(img->is_decoy);
    EXPECT_FALSE(img->is_driver);

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_decoy());
    EXPECT_FALSE(mod.is_exe());
    EXPECT_FALSE(mod.is_dll());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_EQ(mod.module_type, "decoy");
}

TEST(LoaderModuleClassificationTest, ApiModuleLoaderClassification) {
    ApiModuleLoader loader("kernel32", nullptr, 64, 0x76000000, "C:\\Windows\\System32\\kernel32.dll");
    auto img = loader.make_image();
    EXPECT_TRUE(img->is_dll);
    EXPECT_FALSE(img->is_driver);
    EXPECT_FALSE(img->is_decoy);

    RuntimeModule mod(img);
    EXPECT_TRUE(mod.is_dll());
    EXPECT_FALSE(mod.is_exe());
    EXPECT_FALSE(mod.is_driver());
    EXPECT_FALSE(mod.is_decoy());
    EXPECT_EQ(mod.module_type, "dll");
}
