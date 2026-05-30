/**
 * test_porting_module_name.cpp  NormalizeModNameTest
 */

#include <gtest/gtest.h>
#include <string>
#include <cctype>

static std::string normalize_mod_name(const std::string& name) {
    auto dot = name.find_last_of('.');
    std::string base = (dot != std::string::npos) ? name.substr(0, dot) : name;
    for (auto& c : base) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return base;
}

TEST(NormalizeModNameTest, Lowercase) {
    EXPECT_EQ(normalize_mod_name("KERNEL32"), "kernel32");
    EXPECT_EQ(normalize_mod_name("Kernel32"), "kernel32");
    EXPECT_EQ(normalize_mod_name("kernel32"), "kernel32");
}

TEST(NormalizeModNameTest, StripsExtension) {
    EXPECT_EQ(normalize_mod_name("kernel32.dll"), "kernel32");
    EXPECT_EQ(normalize_mod_name("kernel32.DLL"), "kernel32");
    EXPECT_EQ(normalize_mod_name("ntdll.dll"), "ntdll");
    EXPECT_EQ(normalize_mod_name("SHELL32.DLL"), "shell32");
}

TEST(NormalizeModNameTest, MixedCaseWithExtension) {
    EXPECT_EQ(normalize_mod_name("User32.DLL"), "user32");
    EXPECT_EQ(normalize_mod_name("ADVAPI32.dll"), "advapi32");
}

TEST(NormalizeModNameTest, NoExtension) {
    EXPECT_EQ(normalize_mod_name("kernel32"), "kernel32");
}
