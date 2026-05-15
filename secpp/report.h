// report.h — Report data structures for emulation output
//
// Maps to: speakeasy/report.py (minimal subset)
//
// Defines core types used by the profiler, artifact store, and JSON
// report generation.  The full Pydantic model set from report.py (~855
// lines) is represented here by the most commonly used structures.
// Additional model types should be added as the profiler and API
// handlers mature.

#ifndef SPEAKEASY_REPORT_H
#define SPEAKEASY_REPORT_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "profiler_events.h"

namespace speakeasy {

// ── Data artifact ────────────────────────────────────────────

/**
 * A compressed/encoded data blob stored in the report's top-level
 * "data" section.  Used by ArtifactStore.
 */
struct DataArtifact {
    std::string compression;  // "zlib", "none", etc.
    std::string encoding;     // "base64", "hex", etc.
    size_t size = 0;           // original uncompressed size
    std::string data;          // encoded payload string

    nlohmann::json to_json() const {
        return {
            {"compression", compression},
            {"encoding", encoding},
            {"size", size},
            {"data", data}
        };
    }
};

// ── String collection ────────────────────────────────────────

struct StringCollection {
    std::vector<std::string> ansi;
    std::vector<std::string> unicode;

    nlohmann::json to_json() const {
        return {
            {"ansi", ansi},
            {"unicode", unicode}
        };
    }
};

// ── Run-level summary ────────────────────────────────────────

struct RunSummary {
    int run_id = 0;
    std::string type;           // "dll_export", "exe_entry", "shellcode", etc.
    uint64_t start_addr = 0;
    int instr_count = 0;
    int api_count = 0;
    double runtime_sec = 0.0;
    std::vector<events::Event*> events;  // non-owning pointers

    nlohmann::json to_json() const;
};

// ── Top-level report ─────────────────────────────────────────

struct EmuReport {
    // Metadata
    std::string sha256;
    std::string file_type;      // "exe", "dll", "sys", "shellcode"
    std::string arch;           // "x86", "amd64"
    std::string emu_version;
    std::string report_version;

    // Entry points discovered
    std::vector<std::map<std::string, std::string>> entry_points;

    // Run summaries
    std::vector<RunSummary> runs;

    // Extracted strings (static + runtime)
    StringCollection static_strings;
    StringCollection runtime_strings;

    // Data artifacts (keyed by SHA256 digest)
    std::map<std::string, DataArtifact> data;

    // Raw events (flat list for consumer processing)
    nlohmann::json event_list;

    /**
     * Serialize the full report to a nlohmann::json object.
     */
    nlohmann::json to_json() const;

    /**
     * Serialize the full report to a compact JSON string.
     */
    std::string to_json_string() const;
};

/**
 * Helper: format an integer as a hex string, e.g. "0x7c000000".
 */
inline std::string hex_format(uint64_t value) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(value));
    return std::string(buf);
}

// ── Inline implementations ───────────────────────────────────

inline nlohmann::json RunSummary::to_json() const {
    nlohmann::json j;
    j["run_id"]        = run_id;
    j["type"]          = type;
    j["start_addr"]    = hex_format(start_addr);
    j["instr_count"]   = instr_count;
    j["api_count"]     = api_count;
    j["runtime_sec"]   = runtime_sec;

    nlohmann::json evts = nlohmann::json::array();
    for (auto* e : events) {
        if (e) evts.push_back(e->to_json());
    }
    j["events"] = evts;
    return j;
}

inline nlohmann::json EmuReport::to_json() const {
    nlohmann::json j;
    j["sha256"]          = sha256;
    j["file_type"]       = file_type;
    j["arch"]            = arch;
    j["emu_version"]     = emu_version;
    j["report_version"]  = report_version;
    j["entry_points"]    = entry_points;

    nlohmann::json runs_json = nlohmann::json::array();
    for (const auto& r : runs) {
        runs_json.push_back(r.to_json());
    }
    j["runs"] = runs_json;

    j["static_strings"]  = static_strings.to_json();
    j["runtime_strings"] = runtime_strings.to_json();

    nlohmann::json data_json = nlohmann::json::object();
    for (const auto& [digest, artifact] : data) {
        data_json[digest] = artifact.to_json();
    }
    j["data"] = data_json;

    j["event_list"] = event_list;
    return j;
}

inline std::string EmuReport::to_json_string() const {
    return to_json().dump();
}

} // namespace speakeasy

#endif // SPEAKEASY_REPORT_H
