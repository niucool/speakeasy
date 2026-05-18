// profiler.cpp — Execution profiler and report generation
// Ported from: speakeasy/profiler.py (796 lines)
// Python docstrings embedded as C++ comments on each method.
// Reference: // Python:<line> points to the Python source line.

#include "profiler.h"
#include "windows/fileman.h"
#include <nlohmann/json.hpp>
#include <picosha2.h>
#include <cmath>
#include <cctype>

using namespace speakeasy;

// Python:91-131 — Run class implementation
// class Run:
//     """Represents the basic execution primative for the emulation engine.
//     A "run" can represent any form of execution: a thread, a callback,
//     an exported function, or even a child process."""
//     def __init__(self):
Run::Run() : instr_cnt(0), ret_val(nullptr), process_context(nullptr),
             thread(nullptr), start_addr(0), num_apis(0) {
    network["dns"] = std::vector<std::map<std::string, std::string>>();
    network["traffic"] = std::vector<std::map<std::string, std::string>>();
    dyn_code["mmap"] = std::vector<std::map<std::string, std::string>>();
    dyn_code["base_addrs"] = {};
    exec_cache = std::deque<uint64_t>(4);
    read_cache = std::deque<uint64_t>(4);
    write_cache = std::deque<uint64_t>(4);
}

// Python:126-130
// def get_api_count(self):
//     """Get the number of APIs that were called during the run"""
//     return self.num_apis
int Run::get_api_count() {
    return num_apis;
}

// Python:133-151 — Profiler class implementation
// class Profiler:
//     """The profiler class exists to generate an execution report
//     for all runs that occur within a binary emulation."""
//     def __init__(self):
//         self.start_time: float = 0
//         self.strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
//         self.decoded_strings: dict[str, list[str]] = {"ansi": [], "unicode": []}
//         self.last_data: list[int] = [0, 0]
//         self.last_event: AnyEvent | dict[str, Any] = {}
//         self.set_start_time()
//         self.runtime: float = 0
//         self.meta: dict[str, Any] = {}
//         self.runs: list[Run] = []
//         self.artifact_store = ArtifactStore()
Profiler::Profiler() : start_time(0), runtime(0) {
    set_start_time();
    strings["ansi"] = std::vector<std::string>();
    strings["unicode"] = std::vector<std::string>();
    decoded_strings["ansi"] = std::vector<std::string>();
    decoded_strings["unicode"] = std::vector<std::string>();
    last_data = {0, 0};
}

// Python:153-158
// def add_input_metadata(self, meta):
//     """Add top level profiler fields containing metadata for the
//     module that will be emulated"""
//     self.meta = meta
void Profiler::add_input_metadata(const std::map<std::string, std::string>& meta_input) {
    this->meta = meta_input;
}

// Python:160-164
// def set_start_time(self):
//     """Get the start time for a sample so we can time the execution length"""
//     self.start_time = time.time()
void Profiler::set_start_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    start_time = nanoseconds.count() / 1000000000.0;
}

// Python:166-170
// def get_run_time(self):
//     """Get the time spent emulating a specific "run\""""
//     return time.time() - self.start_time
double Profiler::get_run_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    double current_time = nanoseconds.count() / 1000000000.0;
    return current_time - start_time;
}

// Python:172-176
// def stop_run_clock(self):
//     """Stop the runtime clock to include in the report"""
//     self.runtime = self.get_run_time()
void Profiler::stop_run_clock() {
    runtime = get_run_time();
}

// Python:178-182
// def get_epoch_time(self):
//     """Get the current time in epoch format"""
//     return int(time.time())
long Profiler::get_epoch_time() {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
}

// Python:184-188
// def add_run(self, run: Run) -> None:
//     """Add a new run to the captured run list"""
//     self.runs.append(run)
void Profiler::add_run(std::shared_ptr<Run> run) {
    runs.push_back(run);
}

// Internal helper: store binary data to artifact store
std::string Profiler::handle_binary_data(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    return artifact_store.put_bytes(data);
}

// Python:190-195
// def put_binary_data(self, data: bytes, limit: int | None = None) -> str | None:
//     """Store binary data and return its artifact reference."""
//     if not data: return None
//     payload = data[:limit] if limit is not None else data
//     return self.artifact_store.put_bytes(payload)
std::string Profiler::put_binary_data(const std::vector<uint8_t>& data, int limit) {
    if (data.empty()) return "";
    std::vector<uint8_t> payload_buf;
    const std::vector<uint8_t>& payload = (limit > 0) ?
        (payload_buf = std::vector<uint8_t>(data.begin(), data.begin() + std::min((size_t)limit, data.size())), payload_buf) : data;
    return artifact_store.put_bytes(payload);
}

// Python:197-206
// def merge_binary_data(self, artifact_ref: str | None, data: bytes, limit: int | None = None) -> str | None:
//     """Append raw bytes to an existing artifact payload and store the merged result."""
//     if not artifact_ref: return self.put_binary_data(data, limit=limit)
//     merged = self.artifact_store.get_bytes(artifact_ref)
//     merged.extend(data)
//     if limit is not None and len(merged) > limit: merged = merged[:limit]
//     return self.artifact_store.put_bytes(merged)
std::string Profiler::merge_binary_data(const std::string& ref, const std::vector<uint8_t>& data, int limit) {
    if (ref.empty()) return put_binary_data(data, limit);
    std::vector<uint8_t> merged = artifact_store.get_bytes(ref);
    merged.insert(merged.end(), data.begin(), data.end());
    if (limit > 0 && (int)merged.size() > limit) merged.resize(limit);
    return artifact_store.put_bytes(merged);
}

// Python:214-225 — log dropped files from an emulation run
// def record_dropped_files_event(self, run, files):
//     for f in files:
//         run.dropped_files.append({
//             "name": f.get_name(), "hash": f.get_hash(), "path": f.get_path(),
//         })
void Profiler::log_dropped_files(std::shared_ptr<Run> run, const std::vector<void*>& files) {
    record_dropped_files_event(run, files);
}

// Python:214-225 — log dropped files from an emulation run
// def record_dropped_files_event(self, run, files):
//     for f in files:
//         data = f.get_data()
//         if data is None:
//             continue
//         _hash = f.get_hash()
//         data_ref = None
//         if len(data) <= MAX_EMBEDDED_FILE_SIZE:
//             data_ref = self.artifact_store.put_bytes(data)
//         entry = {"path": f.path, "size": len(data), "sha256": _hash, "data_ref": data_ref}
//         run.dropped_files.append(entry)
void Profiler::record_dropped_files_event(std::shared_ptr<Run> run, const std::vector<void*>& files) {
    for (void* f_ptr : files) {
        if (!f_ptr) continue;
        // The void* elements are File* pointers from get_dropped_files()
        auto* f = static_cast<File*>(f_ptr);
        if (!f) continue;

        auto data = f->get_data();
        if (data.empty()) continue;

        std::string hash = f->get_hash();
        std::string path = f->get_path();

        // Build entry matching Python: {"path", "size", "sha256", "data_ref"}
        std::map<std::string, std::string> entry;
        entry["path"] = path;
        entry["size"] = std::to_string(data.size());
        entry["sha256"] = hash;
        // data_ref only set for small files; for now, store a placeholder
        entry["data_ref"] = (data.size() <= MAX_EMBEDDED_FILE_SIZE) ? hash : "";

        run->dropped_files.push_back(entry);
    }
}

// Python:208-212
// def record_error_event(self, error: ErrorInfo) -> None:
//     """Log a top level emulator error for the emulation report."""
//     self.meta.setdefault("errors", []).append(error.to_dict())
void Profiler::record_error_event(const speakeasy::ErrorInfo& error) {
    if (meta.find("errors") == meta.end()) {
        meta["errors"] = "[]";
    }
    std::string err_json = error.to_json().dump();
    if (meta["errors"].size() <= 2) meta["errors"] = err_json;
    else {
        std::string val = meta["errors"];
        val.pop_back();
        if (val.size() > 1) val += ",";
        val += err_json + "]";
        meta["errors"] = val;
    }
}

// Legacy string-based error logging (Python compat)
void Profiler::log_error(const std::string& error) {
    speakeasy::ErrorInfo ei;
    ei.type = "internal_error";
    ei.context_summary = error;
    record_error_event(ei);
}

// Python:227-259
// def record_api_event(self, run, pos: TracePosition, name, ret, argv):
//     """Log a call to an OS API. This includes arguments, return address, and return value"""
void Profiler::log_api(std::shared_ptr<Run> run, uint64_t pc, const std::string& name,
                       void* ret, const std::vector<std::string>& argv,
                       const std::vector<std::string>& ctx) {
    run->num_apis += 1;

    // Build lowercase version for hash
    std::string lower_name = name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

    if (std::find(run->unique_apis.begin(), run->unique_apis.end(), name) == run->unique_apis.end()) {
        run->api_hash_data += lower_name;
        run->unique_apis.push_back(name);
    }

    std::stringstream pc_stream;
    pc_stream << "0x" << std::hex << pc;

    std::string ret_val;
    if (ret != nullptr) {
        std::stringstream ret_stream;
        ret_stream << "0x" << std::hex << reinterpret_cast<uint64_t>(ret);
        ret_val = ret_stream.str();
    }

    // Process args: convert numeric strings to hex
    std::vector<std::string> args = argv;
    for (auto& arg : args) {
        if (!arg.empty()) {
            bool is_number = true;
            for (char c : arg) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    is_number = false;
                    break;
                }
            }
            if (is_number) {
                try {
                    uint64_t num = std::stoull(arg);
                    std::stringstream hex_s;
                    hex_s << "0x" << std::hex << num;
                    arg = hex_s.str();
                } catch (...) {
                }
            }
        }
    }

    std::map<std::string, std::string> entry;
    entry["pc"] = pc_stream.str();
    entry["api_name"] = name;

    nlohmann::json args_json = nlohmann::json::array();
    for (const auto& a : args) {
        args_json.push_back(a);
    }
    entry["args"] = args_json.dump();

    entry["ret_val"] = ret_val;

    if (!ctx.empty()) {
        nlohmann::json ctx_json = nlohmann::json::array();
        for (const auto& c : ctx) {
            ctx_json.push_back(c);
        }
        entry["ctx"] = ctx_json.dump();
    }

    // Dedup against last 3 API entries (Python: self.events[-3:] logic)
    bool is_duplicate = false;
    int start_idx = std::max(0, (int)run->apis.size() - 3);
    for (int i = start_idx; i < (int)run->apis.size(); i++) {
        if (run->apis[i] == entry) {
            is_duplicate = true;
            break;
        }
    }

    if (!is_duplicate) {
        run->apis.push_back(entry);
    }
}

// Python:261-338
// def record_file_access_event(self, run, pos, path, event_type, data=None, handle=0,
//                               disposition=[], access=[], buffer=0, size=None):
//     """Log file access events. This will include things like handles being opened,
//     data reads, and data writes."""
void Profiler::log_file_access(std::shared_ptr<Run> run, const std::string& path,
                               const std::string& event_type,
                               const std::vector<uint8_t>& data,
                               int handle,
                               const std::vector<std::string>& disposition,
                               const std::vector<std::string>& access,
                               uint64_t buffer, int size) {
    std::string enc;
    if (!data.empty()) {
        std::vector<uint8_t> sub_data(data.begin(),
                                      data.begin() + std::min(1024, (int)data.size()));
        enc = handle_binary_data(sub_data);
    }

    // Merge with existing write/read for same path
    for (const std::string& et : {"write", "read"}) {
        if (event_type == et) {
            for (auto it = run->file_access.rbegin(); it != run->file_access.rend(); ++it) {
                auto& fa = *it;
                if (fa["path"] == path && fa["event"] == et) {
                    if (size != -1) {
                        int existing = 0;
                        if (fa.find("size") != fa.end())
                            existing = std::stoi(fa["size"]);
                        fa["size"] = std::to_string(existing + size);
                    }
                    if (!enc.empty()) {
                        fa["data"] += enc;
                    }
                    return;
                }
            }
        }
    }

    std::map<std::string, std::string> event;
    event["event"] = event_type;
    event["path"] = path;
    if (!enc.empty()) event["data"] = enc;
    if (handle != 0) event["handle"] = "0x" + hex_str(handle, false);
    if (size != -1)  event["size"] = std::to_string(size);
    if (buffer != 0) event["buffer"] = "0x" + hex_str(buffer, false);

    if (!disposition.empty()) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& d : disposition) j.push_back(d);
        event["disposition"] = j.dump();
    }
    if (!access.empty()) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& a : access) j.push_back(a);
        event["access"] = j.dump();
    }

    // Dedup against last entry
    if (run->file_access.empty() || run->file_access.back() != event) {
        run->file_access.push_back(event);
    }
}

// Python:340-416
// def record_registry_access_event(self, run, pos, path, event_type, value_name=None,
//                                   data=None, handle=0, disposition=[], access=[],
//                                   buffer=0, size=None):
//     """Log registry access events that occur during emulation including values being read/written"""
void Profiler::log_registry_access(std::shared_ptr<Run> run, const std::string& path,
                                   const std::string& event_type,
                                   const std::string& value_name,
                                   const std::vector<uint8_t>& data,
                                   int handle,
                                   const std::vector<std::string>& disposition,
                                   const std::vector<std::string>& access,
                                   uint64_t buffer, int size) {
    std::string enc;
    if (!data.empty()) {
        std::vector<uint8_t> sub_data(data.begin(),
                                      data.begin() + std::min(1024, (int)data.size()));
        enc = handle_binary_data(sub_data);
    }

    std::map<std::string, std::string> event;
    event["event"] = event_type;
    event["path"] = path;
    if (!value_name.empty()) event["value_name"] = value_name;
    if (!enc.empty())        event["data"] = enc;
    if (handle != 0)         event["handle"] = "0x" + hex_str(handle, false);
    if (size != -1)          event["size"] = std::to_string(size);
    if (buffer != 0)         event["buffer"] = "0x" + hex_str(buffer, false);

    if (!disposition.empty()) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& d : disposition) j.push_back(d);
        event["disposition"] = j.dump();
    }
    if (!access.empty()) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& a : access) j.push_back(a);
        event["access"] = j.dump();
    }

    if (run->registry_access.empty() || run->registry_access.back() != event) {
        run->registry_access.push_back(event);
    }
}

// Python:418-522
// def record_process_event(self, run, pos: TracePosition, proc, event_type, kwargs):
//     """Log process events (create, exit, memory alloc/free/protect, thread create/inject)
//     that are created within another process."""
void Profiler::log_process_event(std::shared_ptr<Run> run, void* proc,
                                 const std::string& event_type,
                                 const std::map<std::string, std::string>& kwargs) {
    (void)proc;

    std::map<std::string, std::string> event;
    event["event"] = event_type;
    for (const auto& [key, val] : kwargs) {
        event[key] = val;
    }

    // MEM_WRITE/MEM_READ merge: combine sequential adjacent writes
    if (event_type == MEM_WRITE || event_type == MEM_READ) {
        if (!run->process_events.empty() &&
            last_event_type == event_type &&
            last_data.size() >= 2 &&
            kwargs.count("base") && kwargs.count("size")) {
            uint64_t last_base = last_data[0];
            uint64_t last_size = last_data[1];
            uint64_t new_base = 0, new_size = 0;
            try { new_base = std::stoull(kwargs.at("base")); } catch (...) {}
            try { new_size = std::stoull(kwargs.at("size")); } catch (...) {}

            if ((last_base + last_size) == new_base) {
                auto& last_evt = run->process_events.back();
                int combined = 0;
                if (last_evt.find("size") != last_evt.end())
                    try { combined = std::stoi(last_evt["size"]); } catch (...) {}
                combined += (int)new_size;
                last_evt["size"] = std::to_string(combined);

                if (kwargs.count("data") && last_evt.find("data") != last_evt.end()) {
                    std::string existing_ref = last_evt["data"];
                    std::string new_data_str = kwargs.at("data");
                    std::vector<uint8_t> new_data(new_data_str.begin(), new_data_str.end());
                    std::vector<uint8_t> merged = artifact_store.get_bytes(existing_ref);
                    merged.insert(merged.end(), new_data.begin(), new_data.end());
                    if (merged.size() > 1024) merged.resize(1024);
                    last_evt["data"] = artifact_store.put_bytes(merged);
                }

                last_data = {new_base, new_size};
                return;
            }
        }
        if (kwargs.count("base") && kwargs.count("size")) {
            try {
                last_data = {std::stoull(kwargs.at("base")),
                             std::stoull(kwargs.at("size"))};
            } catch (...) {
                last_data = {0, 0};
            }
        }
    }

    last_event_type = event_type;
    run->process_events.push_back(event);
}

// Python:524-537
// def record_dns_event(self, run, pos: TracePosition, domain, ip=""):
//     """Log DNS name lookups for the emulation report"""
void Profiler::log_dns(std::shared_ptr<Run> run, const std::string& domain,
                       const std::string& ip) {
    for (const auto& evt : run->network["dns"]) {
        auto q = evt.find("query");
        auto r = evt.find("response");
        if (q != evt.end() && q->second == domain &&
            r != evt.end() && r->second == ip) {
            return;
        }
    }
    std::map<std::string, std::string> entry;
    entry["query"] = domain;
    if (!ip.empty()) entry["response"] = ip;
    run->network["dns"].push_back(entry);
}

// Python:539-567
// def record_http_event(self, run, pos, server, port, proto, headers, body, secure):
//     """Log HTTP traffic that occur during emulation"""
void Profiler::log_http(std::shared_ptr<Run> run, const std::string& server, int port,
                        const std::string& /*proto*/,
                        const std::string& headers,
                        const std::vector<uint8_t>& body, bool secure) {
    std::string proto_str = secure ? "https" : "http";
    std::string body_ref = handle_binary_data(body);

    std::map<std::string, std::string> entry;
    entry["server"] = server;
    entry["port"] = std::to_string(port);
    entry["proto"] = "tcp." + proto_str;
    if (!headers.empty())  entry["headers"] = headers;
    if (!body_ref.empty()) entry["body_ref"] = body_ref;

    // Dedup
    for (const auto& evt : run->network["traffic"]) {
        if (evt.find("server") != evt.end() && evt.at("server") == server &&
            evt.find("port") != evt.end() && evt.at("port") == std::to_string(port) &&
            evt.find("proto") != evt.end() && evt.at("proto") == ("tcp." + proto_str) &&
            evt.find("headers") != evt.end() && evt.at("headers") == headers) {
            return;
        }
    }

    run->network["traffic"].push_back(entry);
}

// Python:569-576
// def record_dyn_code_event(self, run, tag, base, size):
//     """Log code that is generated at runtime and then executed"""
//     if base not in run.base_addrs:
//         run.dyn_code["mmap"].append({"tag": tag, "base": hex(base), ...})
//         run.base_addrs.add(base)
void Profiler::log_dyn_code(std::shared_ptr<Run> run, const std::string& tag,
                            uint64_t base, uint64_t size) {
    if (run->base_addrs.find(base) == run->base_addrs.end()) {
        std::map<std::string, std::string> entry;
        entry["tag"] = tag;
        entry["base"] = "0x" + hex_str(base, false);
        entry["size"] = "0x" + hex_str(size, false);
        run->dyn_code["mmap"].push_back(entry);
        run->base_addrs.insert(base);
    }
}

// Python:578-595
// def record_network_event(self, run, pos, server, port, typ, proto, data, method):
//     """Log network activity for an emulation run"""
void Profiler::log_network(std::shared_ptr<Run> run, const std::string& server, int port,
                           const std::string& typ,
                           const std::string& proto,
                           const std::vector<uint8_t>& data,
                           const std::string& method) {
    std::string data_ref = handle_binary_data(data);

    std::map<std::string, std::string> entry;
    entry["server"] = server;
    entry["port"] = std::to_string(port);
    entry["proto"] = proto;
    if (typ != "unknown") entry["type"] = typ;
    if (!data_ref.empty()) entry["data_ref"] = data_ref;
    if (!method.empty())   entry["method"] = method;

    run->network["traffic"].push_back(entry);
}

// Python:597-620 — handled exception event
// def record_exception_event(self, run, pos, exc_va, handler_va, code, ...):
//     """Log an exception that was generated during emulation"""
void Profiler::log_exception(std::shared_ptr<Run> run, const std::map<std::string,std::string>& info) {
    run->handled_exceptions.push_back(info);
}

// Python:622-633 — module load event
// def record_module_load_event(self, run, pos, name, path, base, size):
//     """Log a module being loaded into the emulated process"""
void Profiler::log_module_load(std::shared_ptr<Run> run, const std::string& name,
                               const std::string& path, uint64_t base, uint64_t size) {
    std::map<std::string, std::string> entry;
    entry["name"] = name;  entry["path"] = path;
    entry["base"] = "0x" + hex_str(base, false);
    entry["size"] = "0x" + hex_str(size, false);
    entry["event"] = "module_load";
    run->process_events.push_back(entry);
}

// Python:642-796
// def get_report(self) -> Report:
//     """Build the full emulation report from all runs and metadata"""
speakeasy::Report Profiler::get_report() const {
    speakeasy::Report rpt;
    rpt.report_version = __report_version__;
    rpt.emulation_total_runtime = std::round(runtime * 1000.0) / 1000.0;
    rpt.timestamp = static_cast<int64_t>(start_time);
    if (meta.count("arch"))      rpt.arch = meta.at("arch");
    if (meta.count("filepath"))  rpt.filepath = meta.at("filepath");
    if (meta.count("sha256"))    rpt.sha256 = meta.at("sha256");
    if (meta.count("size"))      rpt.size = std::stoi(meta.at("size"));
    if (meta.count("filetype"))  rpt.filetype = meta.at("filetype");
    if (meta.count("image_base")) rpt.image_base = std::stoull(meta.at("image_base"));

    // Build entry points from runs
    for (auto& run : runs) {
        speakeasy::EntryPoint ep;
        ep.ep_type = run->type;
        ep.start_addr = run->start_addr;
        for (auto& a : run->args) {
            try { ep.ep_args.push_back(std::stoull(a, nullptr, 0)); }
            catch (...) { ep.ep_args.push_back(0); }
        }
        ep.instr_count = run->instr_cnt > 0 ? std::optional<int>(run->instr_cnt) : std::nullopt;
        if (!run->api_hash_data.empty())
            ep.apihash = picosha2::hash256_hex_string(run->api_hash_data);
        if (run->ret_val)
            ep.ret_val = reinterpret_cast<uint64_t>(run->ret_val);
        if (!run->error.empty()) {
            speakeasy::ErrorInfo ei;
            ei.type = run->error.count("type") ? run->error.at("type") : "error";
            ei.context_summary = run->error.count("message") ? run->error.at("message") : "";
            ep.error = ei;
        }
        rpt.entry_points.push_back(ep);
    }

    // Strings report
    auto ansi_it = strings.find("ansi");
    auto uni_it = strings.find("unicode");
    auto dansi_it = decoded_strings.find("ansi");
    auto duni_it = decoded_strings.find("unicode");
    if ((ansi_it != strings.end() && !ansi_it->second.empty()) ||
        (uni_it != strings.end() && !uni_it->second.empty()) ||
        (dansi_it != decoded_strings.end() && !dansi_it->second.empty()) ||
        (duni_it != decoded_strings.end() && !duni_it->second.empty())) {
        speakeasy::StringsReport sr;
        if(ansi_it != strings.end())
            sr.static_strings.ansi = ansi_it->second;
        if (uni_it != strings.end())
            sr.static_strings.unicode = uni_it->second;
        if (dansi_it != decoded_strings.end())
            sr.in_memory.ansi = dansi_it->second;
        if (duni_it != decoded_strings.end())
            sr.in_memory.unicode = duni_it->second;
        rpt.strings = sr;
    }

    // Data artifacts
    auto art_data = artifact_store.to_report_data();
    if (!art_data.empty()) {
        std::map<std::string, speakeasy::DataArtifact> data_map;
        for (auto& [digest, a] : art_data) {
            speakeasy::DataArtifact da;
            da.compression = a.compression;
            da.encoding    = a.encoding;
            da.size        = a.size;
            da.data        = a.data;
            data_map[digest] = da;
        }
        rpt.data = data_map;
    }

    return rpt;
}

// Python:635-641
// def get_json_report(self) -> str:
//     return json.dumps(self.get_report().to_dict(), indent=4, default=str, ensure_ascii=False)
nlohmann::json Profiler::get_json_report() const {
    return get_report().to_json();
}

std::string Profiler::get_json_report_string() const {
    return get_json_report().dump(4);
}

std::map<std::string, std::string> Profiler::get_profile_summary() const {
    std::map<std::string, std::string> profile;
    profile["report_version"] = __report_version__;
    profile["runtime"] = std::to_string(runtime);
    profile["num_runs"] = std::to_string(runs.size());
    int total_apis = 0;
    for (auto& run : runs) total_apis += run->num_apis;
    profile["total_apis"] = std::to_string(total_apis);
    return profile;
}
