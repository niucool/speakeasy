// cli.h — Speakeasy CLI entry point
//
// Maps to: speakeasy/cli.py

#ifndef SPEAKEASY_CLI_H
#define SPEAKEASY_CLI_H

#include <string>
#include <vector>

namespace speakeasy {

/// Run the speakeasy CLI with the given arguments
int run_cli(int argc, const char* argv[]);

/// Emulate a binary file (exe/dll/sys/shellcode)
/// Returns the JSON report string
std::string emulate_binary(const std::string& target_path,
                           const std::string& config_path = "",
                           const std::vector<std::string>& extra_argv = {},
                           const std::vector<std::string>& volumes = {},
                           bool is_raw = false,
                           const std::string& arch = "",
                           size_t raw_offset = 0,
                           bool emulate_children = false,
                           bool verbose = false,
                           size_t entry_point = 0);

} // namespace speakeasy

#endif
