// cli.cpp — Speakeasy CLI implementation
//
// Maps to: speakeasy/cli.py

#include "cli.h"
#include "cli_config.h"
#include "speakeasy.h"
#include "version.h"
#include "volumes.h"
#include "config.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

namespace speakeasy {

int run_cli(int argc, const char* argv[]) {
    cxxopts::Options opts("speakeasy", "Speakeasy - Windows malware emulation framework");

    // Core options
    opts.add_options()
        ("t,target",    "Target file to emulate (exe/dll/sys/shellcode)", cxxopts::value<std::string>(), "PATH")
        ("o,output",    "Output JSON report file", cxxopts::value<std::string>(), "PATH")
        ("c,config",    "Configuration file path", cxxopts::value<std::string>(), "PATH")
        ("argv",        "Commandline parameters for emulated process (quoted string)",
                        cxxopts::value<std::string>()->default_value(""), "ARGS")
        ("volume",      "Mount host:guest volume (repeatable)", cxxopts::value<std::vector<std::string>>(), "HOST:GUEST")
        ("raw",         "Emulate as shellcode", cxxopts::value<bool>()->default_value("false"))
        ("raw-offset",  "Raw mode start offset (hex)", cxxopts::value<std::string>()->default_value("0"), "OFFSET")
        ("entry-point", "Entry point RVA (hex) to override PE default",
                            cxxopts::value<std::string>()->default_value("0"), "RVA")
        ("arch",        "Architecture for shellcode (x86/amd64)", cxxopts::value<std::string>(), "ARCH")
        ("emulate-children", "Emulate child processes", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose",   "Verbose output", cxxopts::value<bool>()->default_value("false"))
        ("h,help",      "Print usage");

    // Config overrides (same schema as Python's get_config_cli_field_specs)
    for (auto& spec : get_config_cli_field_specs()) {
        std::string desc = spec.description + " (default: " + spec.default_val + ")";
        cxxopts::OptionNames names = {spec.option};
        if (spec.kind == "bool") {
            opts.add_option("Config", "", names, desc, cxxopts::value<bool>(), "");
        } else if (spec.kind == "int") {
            opts.add_option("Config", "", names, desc, cxxopts::value<int>(), "N");
        } else if (spec.kind == "str") {
            opts.add_option("Config", "", names, desc, cxxopts::value<std::string>(), "S");
        }
    }

    try {
        auto args = opts.parse(argc, const_cast<char**>(argv));

        if (args.count("help")) {
            std::cout << opts.help() << std::endl;
            return 0;
        }

        if (!args.count("target")) {
            std::cerr << "Error: No target file supplied. Use -t <file>" << std::endl;
            return 1;
        }

        std::string target = args["target"].as<std::string>();
        std::string output = args.count("output") ? args["output"].as<std::string>() : "";
        std::string config_path = args.count("config") ? args["config"].as<std::string>() : "";
        bool is_raw = args["raw"].as<bool>();
        std::string arch = args.count("arch") ? args["arch"].as<std::string>() : "";
        bool emulate_children = args["emulate-children"].as<bool>();
        bool verbose = args["verbose"].as<bool>();

        // Parse argv for guest process
        std::vector<std::string> extra_argv;
        std::string argv_str = args["argv"].as<std::string>();
        if (!argv_str.empty()) {
            std::istringstream iss(argv_str);
            std::string token;
            while (iss >> token)
                extra_argv.push_back(token);
        }

        // Parse raw_offset
        size_t raw_offset = 0;
        std::string ro_str = args["raw-offset"].as<std::string>();
        if (!ro_str.empty())
            raw_offset = std::stoull(ro_str, nullptr, 16);

        // Parse entry_point (optional)
        size_t entry_point = 0;
        std::string ep_str = args["entry-point"].as<std::string>();
        if (!ep_str.empty())
            entry_point = std::stoull(ep_str, nullptr, 16);

        // Parse volumes
        std::vector<std::string> volumes;
        if (args.count("volume"))
            volumes = args["volume"].as<std::vector<std::string>>();

        if (verbose) {
            std::cerr << "Speakeasy v" << __version__ << " - Windows Malware Emulation Framework" << std::endl;
        }

        // Run emulation
        std::string report = emulate_binary(target, config_path, extra_argv, volumes,
                                            is_raw, arch, raw_offset, emulate_children,
                                            verbose, entry_point);

        // Write output
        if (!output.empty()) {
            std::ofstream ofs(output);
            if (ofs.is_open()) {
                ofs << report;
            }
        } else if (!report.empty()) {
            try {
                auto j = nlohmann::json::parse(report);
                std::cout << j.dump(2) << std::endl;
            } catch (...) {
                std::cout << report << std::endl;
            }
        }

        return 0;

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

std::string emulate_binary(const std::string& target_path,
                           const std::string& config_path,
                           const std::vector<std::string>& extra_argv,
                           const std::vector<std::string>& volumes,
                           bool is_raw, const std::string& arch,
                           size_t raw_offset, bool emulate_children,
                           bool verbose, size_t entry_point) {
    try {
        // ── 1. Build config (Python: get_default_config_dict + merge + apply volumes) ──
        nlohmann::json cfg;
        {
            // Start with default config
            cfg = nlohmann::json::object();
            cfg["timeout"] = 60;
            cfg["max_api_count"] = 10000;
            cfg["os_ver"] = {{"major", 6}, {"minor", 1}, {"build", 7601}};
            cfg["analysis"] = {{"memory_tracing", false}, {"strings", true}, {"coverage", false}};

            // Merge user config file if provided (Python: load + merge_config_dicts)
            if (!config_path.empty()) {
                std::ifstream f(config_path);
                if (!f.is_open())
                    throw std::runtime_error("Config file not found: " + config_path);
                nlohmann::json user_cfg;
                f >> user_cfg;
                cfg.merge_patch(user_cfg);
            }

            // Apply volumes (Python: apply_volumes)
            for (const auto& spec : volumes) {
                auto [host, guest] = parse_volume_spec(spec);
                nlohmann::json entry;
                entry["mode"] = "full_path";
                entry["emu_path"] = guest;
                entry["path"] = host.string();
                cfg["filesystem"]["files"].push_back(entry);
            }

            // Validate (Python: SpeakeasyConfig.model_validate)
            SpeakeasyConfig validated = cfg;
            validate_config(validated);
        }

        // ── 3. Initialise Speakeasy ──
        Speakeasy se(cfg, nullptr, extra_argv, false, nullptr);
        std::string report;

        if (is_raw) {
            // ── Shellcode mode (Python: load_shellcode + run_shellcode) ──
            std::string resolved_arch = arch.empty() ? "x86" : arch;
            std::transform(resolved_arch.begin(), resolved_arch.end(),
                           resolved_arch.begin(), ::tolower);
            if (resolved_arch == "amd64") resolved_arch = "x64";

            uint64_t sc_addr = se.load_shellcode(target_path, resolved_arch);
            se.run_shellcode(sc_addr, 0x4000, raw_offset);
        } else {
            // ── PE module mode (Python: load_module + run_module) ──
            auto* module = se.load_module(target_path);
            se.run_module(module, true, emulate_children);
        }

        report = se.get_json_report();
        return report;

    } catch (const std::exception& e) {
        nlohmann::json err;
        err["error"] = e.what();
        return err.dump();
    }
}

} // namespace speakeasy
