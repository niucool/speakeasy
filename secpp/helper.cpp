#include "helper.h"
#include <algorithm>
#include <cctype>

namespace speakeasy {

std::string to_lower(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower;
}

std::string to_upper(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return upper;
}

std::filesystem::path parse_nt_path(std::string path_str) {
#if defined(_WIN32) || defined(_WIN64)
    // Windows natively handles both forward and backward slashes.
    return std::filesystem::path(path_str);
#else
    // Linux/macOS treat backslashes as literal characters, so we must normalize them.
    std::replace(path_str.begin(), path_str.end(), '\\', '/');
    return fs::path(path_str);
#endif
}

} // namespace speakeasy
