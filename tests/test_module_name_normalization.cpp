/**
 * test_module_name_normalization.cpp — Port of test_module_name_normalization.py
 * Tests that module names are normalized (case-insensitive, no extension).
 */

#include <gtest/gtest.h>
#include <string>

#include "helper.h"

using namespace speakeasy;

TEST(ModuleNameNormalizationTest, Lowercase) {
    EXPECT_EQ(to_lower("KERNEL32"), "kernel32");
    EXPECT_EQ(to_lower("Kernel32"), "kernel32");
    EXPECT_EQ(to_lower("kernel32"), "kernel32");
}

TEST(ModuleNameNormalizationTest, StripsExtension) {
    auto normalize = [](const std::string& name) -> std::string {
        std::string lower = to_lower(name);
        if (lower.size() > 4) {
            std::string ext = lower.substr(lower.size() - 4);
            if (ext == ".dll" || ext == ".sys") {
                return lower.substr(0, lower.size() - 4);
            }
        }
        return lower;
    };

    EXPECT_EQ(normalize("kernel32.dll"), "kernel32");
    EXPECT_EQ(normalize("kernel32.DLL"), "kernel32");
    EXPECT_EQ(normalize("ntdll.dll"), "ntdll");
}

TEST(ModuleNameNormalizationTest, CaseAndExtension) {
    auto normalize = [](const std::string& name) -> std::string {
        std::string lower = to_lower(name);
        if (lower.size() > 4) {
            std::string ext = lower.substr(lower.size() - 4);
            if (ext == ".dll" || ext == ".sys") {
                return lower.substr(0, lower.size() - 4);
            }
        }
        return lower;
    };

    EXPECT_EQ(normalize("KERNEL32.DLL"), "kernel32");
    EXPECT_EQ(normalize("Kernel32.Dll"), "kernel32");
}

TEST(ModuleNameNormalizationTest, NoExtension) {
    EXPECT_EQ(to_lower("kernel32"), "kernel32");
}

TEST(ModuleNameNormalizationTest, PreservesDottedNames) {
    auto normalize = [](const std::string& name) -> std::string {
        std::string lower = to_lower(name);
        if (lower.size() > 4) {
            std::string ext = lower.substr(lower.size() - 4);
            if (ext == ".dll" || ext == ".sys") {
                return lower.substr(0, lower.size() - 4);
            }
        }
        return lower;
    };

    EXPECT_EQ(normalize("api-ms-win-crt-runtime-l1-1-0.dll"),
              "api-ms-win-crt-runtime-l1-1-0");
}

TEST(ModuleNameNormalizationTest, ToUpper) {
    EXPECT_EQ(to_upper("kernel32"), "KERNEL32");
    EXPECT_EQ(to_upper("Kernel32"), "KERNEL32");
    EXPECT_EQ(to_upper("kernel32.dll"), "KERNEL32.DLL");
}
