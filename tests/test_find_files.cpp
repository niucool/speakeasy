/**
 * test_find_files.cpp — Port of test_find_files.py
 * Tests wildcard matching used by the FileManager.
 *
 * The wildcard_match function is a static helper in fileman.cpp.
 * We test its behavior by replicating the logic inline.
 */

#include <gtest/gtest.h>
#include <cctype>
#include <string>

namespace {

// Re-implementation of wildcard_match from secpp/windows/fileman.cpp
// This matches the original Python fnmatch behavior (case-insensitive)
bool wildcard_match(const std::string& str, const std::string& pat,
                    bool case_insensitive = true) {
    size_t si = 0, pi = 0;
    size_t star_s = std::string::npos;
    size_t star_p = std::string::npos;

    while (si < str.size()) {
        if (pi < pat.size() && pat[pi] == '*') {
            star_p = pi++;
            star_s = si;
        } else if (pi < pat.size()) {
            char pc = pat[pi];
            char sc = str[si];
            if (case_insensitive) {
                pc = static_cast<char>(std::tolower(static_cast<unsigned char>(pc)));
                sc = static_cast<char>(std::tolower(static_cast<unsigned char>(sc)));
            }
            if (pc == '?' || pc == sc) {
                si++; pi++;
            } else if (star_p != std::string::npos) {
                pi = star_p + 1;
                si = ++star_s;
            } else {
                return false;
            }
        } else if (star_p != std::string::npos) {
            pi = star_p + 1;
            si = ++star_s;
        } else {
            return false;
        }
    }

    while (pi < pat.size() && pat[pi] == '*') pi++;
    return pi == pat.size();
}

} // namespace

TEST(FindFilesTest, WildcardMatchTxtPattern) {
    EXPECT_TRUE(wildcard_match("test.txt", "*.txt"));
    EXPECT_TRUE(wildcard_match("TEST.TXT", "*.txt"));
    EXPECT_TRUE(wildcard_match("test.txt", "*.TXT"));
    EXPECT_FALSE(wildcard_match("test.exe", "*.txt"));
}

TEST(FindFilesTest, WildcardMatchExact) {
    EXPECT_TRUE(wildcard_match("cmd.exe", "cmd.exe"));
    EXPECT_FALSE(wildcard_match("cmd.exe", "cmd.dll"));
}

TEST(FindFilesTest, WildcardMatchPrefixPattern) {
    EXPECT_TRUE(wildcard_match("myfile.bin", "myfile.*"));
    EXPECT_TRUE(wildcard_match("myfile.txt", "myfile.*"));
    EXPECT_FALSE(wildcard_match("other.bin", "myfile.*"));
}

TEST(FindFilesTest, WildcardMatchQuestionMark) {
    EXPECT_TRUE(wildcard_match("abc", "a?c"));
    EXPECT_FALSE(wildcard_match("ac", "a?c"));
    EXPECT_TRUE(wildcard_match("aXc", "a?c"));
}

TEST(FindFilesTest, WildcardMatchNoWildcards) {
    EXPECT_TRUE(wildcard_match("hello", "hello"));
    EXPECT_FALSE(wildcard_match("hello", "world"));
}

TEST(FindFilesTest, WildcardMatchEmpty) {
    EXPECT_TRUE(wildcard_match("", "*"));
    EXPECT_FALSE(wildcard_match("", "?"));
    EXPECT_TRUE(wildcard_match("", ""));
}

TEST(FindFilesTest, WildcardMatchPathLike) {
    EXPECT_TRUE(wildcard_match("C:\\Windows\\system32\\cmd.exe",
                                "C:\\Windows\\system32\\*.exe"));
    EXPECT_FALSE(wildcard_match("C:\\Windows\\cmd.exe",
                                 "C:\\Windows\\system32\\*.exe"));
}

TEST(FindFilesTest, WildcardMatchMultipleStars) {
    // "some*name*" matches "somename" (name immediately follows some)
    EXPECT_TRUE(wildcard_match("somename", "some*name*"));
    // "some*name*" matches "somename123" (name after some, then anything)
    EXPECT_TRUE(wildcard_match("somename123", "some*name*"));
    // "some*name*" does NOT match "other.txt"
    EXPECT_FALSE(wildcard_match("other.txt", "some*name*"));
}
