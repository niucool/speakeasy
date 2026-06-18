#ifndef SPEAKEASY_HELPER_H
#define SPEAKEASY_HELPER_H

#include <string>
#include <filesystem>

namespace speakeasy {

/**
 * Convert a string to lowercase.
 */
std::string to_lower(const std::string& str);

/**
 * Convert a string to uppercase.
 */
std::string to_upper(const std::string& str);


std::filesystem::path parse_nt_path(std::string path_str);

} // namespace speakeasy

#endif // SPEAKEASY_HELPER_H
