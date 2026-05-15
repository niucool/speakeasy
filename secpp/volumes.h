// volumes.h — Docker-style --volume support for mounting host files
//
// Maps to: speakeasy/volumes.py
//
// Parses "host_path:guest_path" volume specifications and expands
// directory trees into emulated-filesystem file entries.

#ifndef SPEAKEASY_VOLUMES_H
#define SPEAKEASY_VOLUMES_H

#include <string>
#include <vector>
#include <map>
#include <filesystem>

namespace speakeasy {

/**
 * Parse a "host:guest" volume specification.
 *
 * Handles Windows drive-letter colons on both sides (e.g.
 * "C:\\samples:C:\\guest"). The separator is the first ':'
 * that is NOT part of a drive-letter prefix.
 *
 * @return pair of (host_path, guest_path)
 * @throws std::invalid_argument on malformed specs
 */
std::pair<std::filesystem::path, std::string>
parse_volume_spec(const std::string& spec);

/**
 * Expand a host directory tree into file entries for the emulated
 * filesystem config. Each entry maps a host file to an emulated path.
 *
 * @return list of file-entry maps compatible with FileEntry config
 */
std::vector<std::map<std::string, std::string>>
expand_volume_to_entries(const std::filesystem::path& host_path,
                         const std::string& guest_path);

/**
 * Parse one or more volume specs and prepend the resulting entries
 * to the filesystem config map. Entries are prepended so they take
 * priority over default config entries.
 */
void apply_volumes(std::map<std::string, std::map<std::string, std::vector<std::map<std::string, std::string>>>>& config,
                   const std::vector<std::string>& volume_specs);

} // namespace speakeasy

#endif // SPEAKEASY_VOLUMES_H
