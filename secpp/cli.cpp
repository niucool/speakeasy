// cli.cpp — Speakeasy CLI implementation

#include "cli.h"
#include "cli_config.h"
#include "speakeasy.h"
#include "version.h"
#include "volumes.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

namespace speakeasy {

int run_cli(int argc, const char* argv[]) {
    cxxopts::Options opts("speakeasy", "Speakeasy - Windows malware emulation framework");

    // Core options
    opts.add_options()
        ("t,target",    "Target file to emulate (exe/dll/sys/shellcode)", cxxopts::value<std::string>(), "PATH")
        ("o,output",    "Output JSON report file", cxxopts::value<std::string>(), "PATH")
        ("c,config",    "Configuration file path", cxxopts::value<std::string>(), "PATH")
        ("volume",      "Mount host:guest volume (repeatable)", cxxopts::value<std::vector<std::string>>(), "HOST:GUEST")
        ("raw",         "Emulate as shellcode", cxxopts::value<bool>()->default_value("false"))
        ("arch",        "Architecture for shellcode (x86/amd64)", cxxopts::value<std::string>(), "ARCH")
        ("emulate-children", "Emulate child processes", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose",   "Verbose output", cxxopts::value<bool>()->default_value("false"))
        ("h,help",      "Print usage");

    // Add config CLI options
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

        if (verbose) {
            std::cerr << "Speakeasy v" << __version__ << " - Windows Malware Emulation Framework" << std::endl;
        }

        // Run emulation
        std::string report = emulate_binary(target, config_path, {}, {},
                                            is_raw, arch, 0, emulate_children, verbose);

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
                           size_t raw_offset, bool emulate_children, bool verbose) {
    (void)config_path; (void)extra_argv; (void)volumes;
    (void)raw_offset; (void)emulate_children; (void)verbose;

    try {
        Speakeasy se;
        std::string report;

        if (is_raw) {
            uint64_t sc_addr = se.load_shellcode(target_path, arch.empty() ? "x86" : arch);
            se.run_shellcode(sc_addr, 0x4000, 0);
        } else {
            auto* module = se.load_module(target_path);
            se.run_module(module, true, false);
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
