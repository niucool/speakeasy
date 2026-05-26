// volumes.cpp  Volume mount implementation

#include "volumes.h"
#include <stdexcept>
#include <algorithm>

namespace speakeasy {

std::pair<std::filesystem::path, std::string>
parse_volume_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::invalid_argument("Empty volume specification");
    }

    // Find the separator colon, skipping a leading drive letter (X:)
    size_t start = 0;
    if (spec.length() >= 2 && spec[1] == ':') {
        start = 2;
    }

    size_t idx = spec.find(':', start);
    if (idx == std::string::npos) {
        throw std::invalid_argument("Invalid volume spec (missing ':' separator): " + spec);
    }

    std::string host_str = spec.substr(0, idx);
    std::string guest_str = spec.substr(idx + 1);

    if (host_str.empty()) {
        throw std::invalid_argument("Empty host path in volume spec: " + spec);
    }
    if (guest_str.empty()) {
        throw std::invalid_argument("Empty guest path in volume spec: " + spec);
    }

    return {std::filesystem::path(host_str), guest_str};
}

std::vector<std::map<std::string, std::string>>
expand_volume_to_entries(const std::filesystem::path& host_path,
                         const std::string& guest_path) {
    namespace fs = std::filesystem;

    fs::path resolved = fs::absolute(host_path);
    if (!fs::exists(resolved)) {
        throw std::runtime_error("Volume host path does not exist: " + resolved.string());
    }

    std::vector<std::map<std::string, std::string>> entries;

    if (fs::is_regular_file(resolved)) {
        entries.push_back({
            {"mode", "full_path"},
            {"emu_path", guest_path},
            {"path", resolved.string()}
        });
    } else if (fs::is_directory(resolved)) {
        std::vector<fs::path> files;

        // Collect all regular files recursively
        for (auto it = fs::recursive_directory_iterator(resolved);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file()) {
                files.push_back(it->path());
            }
        }

        // Sort for deterministic output
        std::sort(files.begin(), files.end());

        for (const auto& child : files) {
            // Build guest path: guest_base + relative host path
            fs::path rel = fs::relative(child, resolved);
            std::string emu_path = guest_path;

            // Normalize guest path separator to backslash (Windows style)
            for (const auto& part : rel) {
                if (!emu_path.empty() && emu_path.back() != '\\') {
                    emu_path += '\\';
                }
                emu_path += part.string();
            }

            entries.push_back({
                {"mode", "full_path"},
                {"emu_path", emu_path},
                {"path", child.string()}
            });
        }
    }

    return entries;
}

void apply_volumes(
    std::map<std::string, std::map<std::string, std::vector<std::map<std::string, std::string>>>>& config,
    const std::vector<std::string>& volume_specs) {

    if (volume_specs.empty()) return;

    std::vector<std::map<std::string, std::string>> new_entries;

    for (const auto& spec : volume_specs) {
        auto [host_path, guest_path] = parse_volume_spec(spec);
        auto entries = expand_volume_to_entries(host_path, guest_path);
        new_entries.insert(new_entries.end(), entries.begin(), entries.end());
    }

    // Prepend new entries to existing filesystem.files config
    auto& fs = config["filesystem"];
    auto& existing = fs["files"];
    existing.insert(existing.begin(), new_entries.begin(), new_entries.end());
}

} // namespace speakeasy
