// report.h  Report data structures for emulation output
//
// Ported from: speakeasy/report.py (855 lines, 21 Pydantic models)
// Porting status: 21/21 models | 0 gaps
// Last sync: 2026-05-17
//
// Python model hierarchy (bottom-up):
//   HexInt/HexIntOptional/Base64Bytes   => helper types
//   StringCollection                     => static + in-memory strings
//   StringsReport                        => groups StringCollection
//   RegionInfo                           => memory region descriptor
//   ErrorInfo                            => per-run error context
//   SymAccessReport                      => symbol access counters
//   DynamicCodeSegment                   => dynamic code region
//   DataArtifact                         => compressed binary payload
//   DroppedFile                          => file artifact
//   MemoryAccesses                       => R/W/X counters
//   MemoryRegion                         => memory layout entry
//   ModuleSegment                        => PE section descriptor
//   LoadedModule                         => loaded module entry
//   MemoryLayout                         => region + module snapshot
//   EntryPoint                           => per-run execution record
//   Report                               => top-level output
//   FileManifestEntry                    => archive manifest
//   MemoryBlock                          => dumped memory block
//   ProcessMemoryManifest                => grouped dump manifest
//
// Design decisions:
//   - All fields use to_json() for nlohmann::json serialization
//   - HexInt = uint64_t with hex_format() for 0x-prefixed JSON output
//   - Base64Bytes = string with base64 encoding (ArtifactStore)
//   - Optional fields use std::optional (C++17) with null skip in to_json()
//   - Python Field(default=None) => std::optional<T>
//   - Python Field(default_factory=list) => std::vector<T>

#ifndef SPEAKEASY_REPORT_H
#define SPEAKEASY_REPORT_H

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>
#include <nlohmann/json.hpp>
#include "profiler_events.h"

namespace speakeasy {

// === Helper functions ===

inline std::string hex_format(uint64_t v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(buf);
}

template<typename T>
inline void json_set_if(nlohmann::json& j, const std::string& key, const std::optional<T>& val) {
    if (val.has_value()) j[key] = val.value();
}

template<typename T>
inline void json_set_if_vec(nlohmann::json& j, const std::string& key, const std::optional<std::vector<T>>& val,
                            const std::function<nlohmann::json(const T&)>& to_json_fn) {
    if (val.has_value()) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& v : val.value()) arr.push_back(to_json_fn(v));
        j[key] = arr;
    }
}

inline nlohmann::json void_to_json(const void*) { return nullptr; }

// === RegionInfo (Python:122-130) ===
struct RegionInfo {
    std::string tag;
    uint64_t base = 0;
    uint64_t size = 0;
    std::optional<std::string> prot;

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["tag"]  = tag;
        j["base"] = hex_format(base);
        j["size"] = hex_format(size);
        json_set_if(j, "prot", prot);
        return j;
    }
};

// === ErrorInfo (Python:133-219) ===
struct ErrorInfo {
    std::string type;
    std::optional<uint64_t> pc;
    std::optional<std::string> instr;
    std::optional<uint64_t> address;
    std::optional<std::string> access_type;
    std::optional<std::map<std::string, std::string>> regs;
    std::optional<std::vector<std::string>> stack;
    std::optional<std::string> pc_module;
    std::optional<RegionInfo> address_region;
    std::optional<std::vector<RegionInfo>> nearby_regions;
    std::optional<int> thread_id;
    std::optional<int> process_id;
    std::optional<std::string> context_summary;
    std::optional<std::string> traceback;
    std::optional<std::string> api_name;
    std::optional<int> count;
    std::optional<std::string> last_api;
    std::optional<int> interrupt_num;

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["type"] = type;
        json_set_if(j, "pc", pc); json_set_if(j, "instr", instr);
        json_set_if(j, "address", address); json_set_if(j, "access_type", access_type);
        json_set_if(j, "regs", regs); json_set_if(j, "stack", stack);
        json_set_if(j, "pc_module", pc_module);
        json_set_if(j, "thread_id", thread_id); json_set_if(j, "process_id", process_id);
        json_set_if(j, "context_summary", context_summary); json_set_if(j, "traceback", traceback);
        json_set_if(j, "api_name", api_name); json_set_if(j, "count", count);
        json_set_if(j, "last_api", last_api); json_set_if(j, "interrupt_num", interrupt_num);
        if (address_region.has_value()) j["address_region"] = address_region->to_json();
        if (nearby_regions.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& r : *nearby_regions) arr.push_back(r.to_json());
            j["nearby_regions"] = arr;
        }
        return j;
    }
};

// === SymAccessReport (Python:222-258) ===
struct SymAccessReport {
    std::string symbol;
    int reads = 0, writes = 0, execs = 0;
    nlohmann::json to_json() const {
        return {{"symbol", symbol}, {"reads", reads}, {"writes", writes}, {"execs", execs}};
    }
};

// === DynamicCodeSegment (Python:261-290) ===
struct DynamicCodeSegment {
    std::string tag;
    uint64_t base = 0, size = 0;
    nlohmann::json to_json() const {
        return {{"tag", tag}, {"base", hex_format(base)}, {"size", hex_format(size)}};
    }
};

// === DataArtifact (Python:293-307) ===
struct DataArtifact {
    std::string compression, encoding, data;
    size_t size = 0;
    nlohmann::json to_json() const {
        return {{"compression", compression}, {"encoding", encoding}, {"size", size}, {"data", data}};
    }
};

// === DroppedFile (Python:309-339) ===
struct DroppedFile {
    std::string path, sha256;
    size_t size = 0;
    std::optional<std::string> data_ref;
    nlohmann::json to_json() const {
        nlohmann::json j = {{"path", path}, {"size", size}, {"sha256", sha256}};
        json_set_if(j, "data_ref", data_ref);
        return j;
    }
};

// === MemoryAccesses (Python:341-368) ===
struct MemoryAccesses {
    int reads = 0, writes = 0, execs = 0;
    nlohmann::json to_json() const {
        return {{"reads", reads}, {"writes", writes}, {"execs", execs}};
    }
};

// === MemoryRegion (Python:371-425) ===
struct MemoryRegionModel {
    std::string tag, prot;
    uint64_t address = 0, size = 0;
    bool is_free = false;
    std::optional<MemoryAccesses> accesses;
    std::optional<std::string> data_ref;
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["tag"] = tag; j["address"] = hex_format(address); j["size"] = hex_format(size);
        j["prot"] = prot; j["is_free"] = is_free;
        if (accesses.has_value()) j["accesses"] = accesses->to_json();
        json_set_if(j, "data_ref", data_ref);
        return j;
    }
};

// === ModuleSegment (Python:428-457) ===
struct ModuleSegment {
    std::string name, prot;
    uint64_t address = 0, size = 0;
    nlohmann::json to_json() const {
        return {{"name", name}, {"address", hex_format(address)}, {"size", hex_format(size)}, {"prot", prot}};
    }
};

// === LoadedModule (Python:460-494) ===
struct LoadedModule {
    std::string name, path;
    uint64_t base = 0, size = 0;
    std::vector<ModuleSegment> segments;
    nlohmann::json to_json() const {
        nlohmann::json j = {{"name", name}, {"path", path}, {"base", hex_format(base)}, {"size", hex_format(size)}};
        nlohmann::json segs = nlohmann::json::array();
        for (const auto& s : segments) segs.push_back(s.to_json());
        j["segments"] = segs;
        return j;
    }
};

// === MemoryLayout (Python:497-520) ===
struct MemoryLayout {
    std::vector<MemoryRegionModel> layout;
    std::vector<LoadedModule> modules;
    nlohmann::json to_json() const {
        nlohmann::json j;
        nlohmann::json lay = nlohmann::json::array();
        for (const auto& r : layout) lay.push_back(r.to_json());
        j["layout"] = lay;
        nlohmann::json mods = nlohmann::json::array();
        for (const auto& m : modules) mods.push_back(m.to_json());
        j["modules"] = mods;
        return j;
    }
};

// === StringCollection (Python:63-91) ===
struct StringCollection {
    std::vector<std::string> ansi, unicode;
    nlohmann::json to_json() const {
        return {{"ansi", ansi}, {"unicode", unicode}};
    }
};

// === StringsReport (Python:93-119) ===
struct StringsReport {
    StringCollection static_strings, in_memory;
    nlohmann::json to_json() const {
        return {{"static", static_strings.to_json()}, {"in_memory", in_memory.to_json()}};
    }
};

// === EntryPoint (Python:523-637) ===
struct EntryPoint {
    std::string ep_type, apihash;
    uint64_t start_addr = 0;
    std::vector<uint64_t> ep_args;
    std::optional<int> pid, tid, instr_count;
    std::optional<uint64_t> ret_val;
    std::optional<ErrorInfo> error;
    std::optional<std::vector<events::Event*>> events;
    std::optional<std::vector<SymAccessReport>> sym_accesses;
    std::optional<std::vector<DynamicCodeSegment>> dynamic_code_segments;
    std::optional<std::vector<uint64_t>> coverage;
    std::optional<std::vector<DroppedFile>> dropped_files;
    std::optional<MemoryLayout> memory;

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["ep_type"] = ep_type; j["start_addr"] = hex_format(start_addr);
        nlohmann::json args_arr = nlohmann::json::array();
        for (auto a : ep_args) args_arr.push_back(hex_format(a));
        j["ep_args"] = args_arr;
        json_set_if(j, "pid", pid); json_set_if(j, "tid", tid); json_set_if(j, "instr_count", instr_count);
        j["apihash"] = apihash;
        if (ret_val.has_value()) j["ret_val"] = hex_format(*ret_val);
        if (error.has_value()) j["error"] = error->to_json();
        if (events.has_value()) {
            nlohmann::json evts = nlohmann::json::array();
            for (auto* e : *events) if (e) evts.push_back(e->to_json());
            j["events"] = evts;
        }
        auto vec_to_json = [](auto& dest, const auto& src, auto fn) {
            if (src.has_value()) {
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& v : *src) arr.push_back((v.*fn)());
                dest = arr;
            }
        };
        if (sym_accesses.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& s : *sym_accesses) arr.push_back(s.to_json());
            j["sym_accesses"] = arr;
        }
        if (dynamic_code_segments.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& d : *dynamic_code_segments) arr.push_back(d.to_json());
            j["dynamic_code_segments"] = arr;
        }
        if (coverage.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (auto c : *coverage) arr.push_back(hex_format(c));
            j["coverage"] = arr;
        }
        if (dropped_files.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& f : *dropped_files) arr.push_back(f.to_json());
            j["dropped_files"] = arr;
        }
        if (memory.has_value()) j["memory"] = memory->to_json();
        return j;
    }
};

// === Report (Python:640-741) ===
struct Report {
    std::string report_version = "3.0.0";
    double emulation_total_runtime = 0.0;
    int64_t timestamp = 0;
    std::optional<std::string> arch, filepath, sha256, filetype;
    std::optional<int> size;
    std::optional<uint64_t> image_base;
    std::optional<std::vector<ErrorInfo>> errors;
    std::optional<StringsReport> strings;
    std::optional<std::map<std::string, DataArtifact>> data;
    std::vector<EntryPoint> entry_points;
    // Owns typed Event objects; raw pointers in EntryPoint::events point here.
    std::vector<std::unique_ptr<events::Event>> event_store;

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["report_version"] = report_version;
        j["emulation_total_runtime"] = emulation_total_runtime;
        j["timestamp"] = timestamp;
        json_set_if(j, "arch", arch); json_set_if(j, "filepath", filepath);
        json_set_if(j, "sha256", sha256); json_set_if(j, "size", size);
        json_set_if(j, "filetype", filetype);
        if (image_base.has_value()) j["image_base"] = hex_format(*image_base);
        if (errors.has_value()) {
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& e : *errors) arr.push_back(e.to_json());
            j["errors"] = arr;
        }
        if (strings.has_value()) j["strings"] = strings->to_json();
        if (data.has_value()) {
            nlohmann::json d = nlohmann::json::object();
            for (const auto& [k, v] : *data) d[k] = v.to_json();
            j["data"] = d;
        }
        nlohmann::json eps = nlohmann::json::array();
        for (const auto& ep : entry_points) eps.push_back(ep.to_json());
        j["entry_points"] = eps;
        return j;
    }

    std::string to_json_string() const { return to_json().dump(); }
};

// === FileManifestEntry (Python:744-774) ===
struct FileManifestEntry {
    std::string path, file_name, sha256;
    size_t size = 0;
    nlohmann::json to_json() const {
        return {{"path", path}, {"file_name", file_name}, {"size", size}, {"sha256", sha256}};
    }
};

// === MemoryBlock (Python:777-818) ===
struct MemoryBlock {
    std::string tag, sha256, file_name;
    uint64_t base = 0, size = 0;
    bool is_free = false;
    nlohmann::json to_json() const {
        return {{"tag", tag}, {"base", hex_format(base)}, {"size", hex_format(size)},
                {"is_free", is_free}, {"sha256", sha256}, {"file_name", file_name}};
    }
};

// === ProcessMemoryManifest (Python:820-855) ===
struct ProcessMemoryManifest {
    int pid = 0;
    std::string process_name, arch;
    std::vector<MemoryBlock> memory_blocks;
    nlohmann::json to_json() const {
        nlohmann::json j = {{"pid", pid}, {"process_name", process_name}, {"arch", arch}};
        nlohmann::json blks = nlohmann::json::array();
        for (const auto& b : memory_blocks) blks.push_back(b.to_json());
        j["memory_blocks"] = blks;
        return j;
    }
};

} // namespace speakeasy
#endif // SPEAKEASY_REPORT_H
