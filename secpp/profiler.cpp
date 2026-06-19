// profiler.cpp  Execution profiler and report generation
// Ported from: speakeasy/profiler.py (796 lines)
//
// All record_*_event methods create typed Event subclass instances and push them to
// run->events, matching Python's list[AnyEvent] pattern.  get_report() reads directly
// from run->events instead of converting from parallel map<string,string> vectors.

#include "profiler.h"
#include "windows/fileman.h"
#include <nlohmann/json.hpp>
#include "picosha2.h"
#include "helper.h"
#include <windows.h>
#include <cmath>
#include <cctype>
#include <iomanip>


using namespace speakeasy;
using namespace speakeasy::events;

// Python:91-131  Run class implementation
Run::Run() : instr_cnt(0), ret_val(nullptr), process_context(nullptr),
             thread(nullptr), start_addr(0), num_apis(0) {
    exec_cache = std::deque<uint64_t>(4);
    read_cache = std::deque<uint64_t>(4);
    write_cache = std::deque<uint64_t>(4);
}

// Python:126-130
int Run::get_api_count() {
    return num_apis;
}

// Python:133-151  Profiler class implementation
Profiler::Profiler() : start_time(0), runtime(0) {
    set_start_time();
    strings_["ansi"] = std::vector<std::string>();
    strings_["unicode"] = std::vector<std::string>();
    decoded_strings_["ansi"] = std::vector<std::string>();
    decoded_strings_["unicode"] = std::vector<std::string>();
    last_data = {0, 0};
}

// Python:153-158
void Profiler::add_input_metadata(const std::map<std::string, std::string>& meta_input) {
    this->meta = meta_input;
}

// Python:160-164
void Profiler::set_start_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    start_time = nanoseconds.count() / 1000000000.0;
}

// Python:166-170
double Profiler::get_run_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    double current_time = nanoseconds.count() / 1000000000.0;
    return current_time - start_time;
}

// Python:172-176
void Profiler::stop_run_clock() {
    runtime = get_run_time();
}

// Python:178-182
long Profiler::get_epoch_time() {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
}

// Python:184-188
void Profiler::add_run(std::shared_ptr<Run> run) {
    runs.push_back(run);
}

// Internal helper: store binary data to artifact store
std::string Profiler::handle_binary_data(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    return artifact_store.put_bytes(data);
}

// Python:190-195
std::string Profiler::put_binary_data(const std::vector<uint8_t>& data, int limit) {
    if (data.empty()) return "";
    std::vector<uint8_t> payload_buf;
    const std::vector<uint8_t>& payload = (limit > 0) ?
        (payload_buf = std::vector<uint8_t>(data.begin(), data.begin() + std::min((size_t)limit, data.size())), payload_buf) : data;
    return artifact_store.put_bytes(payload);
}

// Python:197-206
std::string Profiler::merge_binary_data(const std::string& ref, const std::vector<uint8_t>& data, int limit) {
    if (ref.empty()) return put_binary_data(data, limit);
    std::vector<uint8_t> merged = artifact_store.get_bytes(ref);
    merged.insert(merged.end(), data.begin(), data.end());
    if (limit > 0 && (int)merged.size() > limit) merged.resize(limit);
    return artifact_store.put_bytes(merged);
}

// Python:214-225  log dropped files  uses DroppedFileEvent in run->events
void Profiler::record_dropped_files_event(std::shared_ptr<Run> run, const std::vector<std::shared_ptr<File>>& files) {
    for (const auto& f : files) {
        if (!f) continue;
        auto data = f->get_data();
        if (data.empty()) continue;

        std::string hash = f->get_hash();
        std::string path = f->get_path();

        auto evt = std::make_shared<DroppedFileEvent>();
        evt->path = path;
        evt->size = data.size();
        evt->sha256 = hash;
        if (data.size() <= MAX_EMBEDDED_FILE_SIZE)
            evt->data_ref = artifact_store.put_bytes(data);
        run->events.push_back(evt);
    }
}

// Python:208-212
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

void Profiler::record_error_event(const std::string& error) {
    speakeasy::ErrorInfo ei;
    ei.type = "internal_error";
    ei.context_summary = error;
    record_error_event(ei);
}

// Python:227-259  record_api_event  creates typed ApiEvent, push to run->events
void Profiler::record_api_event(std::shared_ptr<Run> run, const events::TracePosition& pos, const std::string& name,
    uint64_t ret, const ArgList& argv,
                       const std::vector<std::string>& ctx) {
    run->num_apis += 1;

    std::string lower_name = to_lower(name);
    if (std::find(run->unique_apis.begin(), run->unique_apis.end(), name) == run->unique_apis.end()) {
        run->api_hash_data += lower_name;
        run->unique_apis.push_back(name);
    }

    // Build typed ApiEvent (matches Python's ApiEvent(pos=pos, api_name=name, args=args, ret_val=ret_str))
    auto evt = std::make_shared<ApiEvent>();
    evt->pos = pos;
    evt->api_name = name;

    // Convert ArgList to display strings (Python: isinstance(arg, int) → hex(arg), strings → quoted)
    for (const auto& arg : argv) {
        if (arg.is_string()) {
            std::string escaped;
            escaped.reserve(arg.as_string().size() + 2);
            escaped += '"';
            for (char c : arg.as_string()) {
                if (c == '\n') escaped += "\\n";
                else if (c == '\r') escaped += "\\r";
                else if (c == '\t') escaped += "\\t";
                else if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else escaped += c;
            }
            escaped += '"';
            //evt->args.push_back(escaped);
            evt->args.push_back(arg.as_string());
        } else if (arg.is_uint64()) {
            std::stringstream hex_s;
            hex_s << "0x" << std::hex << static_cast<uint64_t>(arg);
            evt->args.push_back(hex_s.str());
        } else {
            // blob or pointer — use hex representation
            std::stringstream hex_s;
            hex_s << "0x" << std::hex << static_cast<uint64_t>(arg);
            evt->args.push_back(hex_s.str());
        }
    }

    std::stringstream ret_stream;
    ret_stream << "0x" << std::hex << ret;
    evt->ret_val = ret_stream.str();

    // Dedup against last 3 ApiEvents (Python: last 3 isinstance(e, ApiEvent))
    int start_idx = std::max(0, static_cast<int>(run->events.size()) - 3);
    for (int i = start_idx; i < static_cast<int>(run->events.size()); i++) {
        if (run->events[i]->event != API)
            continue;
        auto* existing = dynamic_cast<ApiEvent*>(run->events[i].get());
        if (existing && existing->pos.pc == evt->pos.pc &&
            existing->api_name == evt->api_name &&
            existing->args == evt->args &&
            existing->ret_val == evt->ret_val) {
            return; // duplicate
        }
    }
    (void)ctx;

    run->events.push_back(evt);
}

// Python:261-338  record_file_access_event  typed File*Event to run->events
void Profiler::record_file_access_event(std::shared_ptr<Run> run, const std::string& path,
                               const std::string& event_type,
                               const std::vector<uint8_t>& data,
                               int handle,
                               const std::vector<std::string>& disposition,
                               const std::vector<std::string>& access,
                               uint64_t buffer, int size) {
    (void)handle; (void)disposition; (void)access; (void)buffer; (void)size;
    std::string data_ref;
    if (!data.empty()) {
        std::vector<uint8_t> sub_data(data.begin(),
                                      data.begin() + std::min(1024, (int)data.size()));
        data_ref = handle_binary_data(sub_data);
    }

    // Merge adjacent write/read for same path (Python: reverse scan for FILE_WRITE/FILE_READ)
    if (event_type == FILE_WRITE || event_type == FILE_READ) {
        for (auto it = run->events.rbegin(); it != run->events.rend(); ++it) {
            if (event_type == FILE_WRITE) {
                auto* existing = dynamic_cast<FileWriteEvent*>(it->get());
                if (existing && existing->path == path) {
                    if (!data_ref.empty())
                        existing->data_ref = merge_binary_data(existing->data_ref, data, 1024);
                    return;
                }
            } else if (event_type == FILE_READ) {
                auto* existing = dynamic_cast<FileReadEvent*>(it->get());
                if (existing && existing->path == path) {
                    if (!data_ref.empty())
                        existing->data_ref = merge_binary_data(existing->data_ref, data, 1024);
                    return;
                }
            }
        }
    }

    // Create typed event
    std::shared_ptr<speakeasy::events::Event> evt;
    if (event_type == FILE_CREATE) {
        auto e = std::make_shared<FileCreateEvent>();
        e->path = path;
        evt = e;
    } else if (event_type == FILE_WRITE) {
        auto e = std::make_shared<FileWriteEvent>();
        e->path = path;
        e->data_ref = data_ref;
        evt = e;
    } else if (event_type == FILE_OPEN) {
        auto e = std::make_shared<FileOpenEvent>();
        e->path = path;
        evt = e;
    } else if (event_type == FILE_READ) {
        auto e = std::make_shared<FileReadEvent>();
        e->path = path;
        e->data_ref = data_ref;
        evt = e;
    } else {
        return; // unknown event type
    }

    // Dedup against last event
    if (!run->events.empty()) {
        auto* last = run->events.back().get();
        if (last->event == evt->event) {
            // Compare paths for same event type
            bool same = false;
            if (auto* le = dynamic_cast<FileCreateEvent*>(last)) {
                auto* ne = dynamic_cast<FileCreateEvent*>(evt.get());
                if (ne && le->path == ne->path) same = true;
            } else if (auto* le = dynamic_cast<FileOpenEvent*>(last)) {
                auto* ne = dynamic_cast<FileOpenEvent*>(evt.get());
                if (ne && le->path == ne->path) same = true;
            }
            if (same) return;
        }
    }

    run->events.push_back(evt);
}

// Python:340-416  record_registry_access_event  typed Reg*Event to run->events
void Profiler::record_registry_access_event(std::shared_ptr<Run> run, const std::string& path,
                                   const std::string& event_type,
                                   const std::string& value_name,
                                   const std::vector<uint8_t>& data,
                                   int handle,
                                   const std::vector<std::string>& disposition,
                                   const std::vector<std::string>& access,
                                   uint64_t buffer, int size) {
    (void)handle; (void)disposition; (void)access; (void)buffer; (void)size;
    std::string data_str;
    if (!data.empty()) {
        std::vector<uint8_t> sub_data(data.begin(),
                                      data.begin() + std::min(1024, (int)data.size()));
        // Store registry data inline as hex/string for small values
        if (sub_data.size() <= 64) {
            bool all_printable = true;
            for (auto b : sub_data)
                if (b < 0x20 || b > 0x7E) { all_printable = false; break; }
            if (all_printable)
                data_str = std::string(sub_data.begin(), sub_data.end());
            else {
                std::stringstream hx;
                hx << "hex:";
                for (auto b : sub_data) hx << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                data_str = hx.str();
            }
        }
    }

    std::shared_ptr<speakeasy::events::Event> evt;
    if (event_type == REG_OPEN) {
        auto e = std::make_shared<RegOpenEvent>();
        e->key = path;
        evt = e;
    } else if (event_type == REG_READ) {
        auto e = std::make_shared<RegReadEvent>();
        e->key = path;
        e->value = value_name;
        evt = e;
    } else if (event_type == REG_WRITE) {
        auto e = std::make_shared<RegWriteEvent>();
        e->key = path;
        e->value = value_name;
        e->data = data_str;
        evt = e;
    } else if (event_type == REG_LIST) {
        auto e = std::make_shared<RegListEvent>();
        e->key = path;
        evt = e;
    } else if (event_type == REG_CREATE) {
        auto e = std::make_shared<RegCreateEvent>();
        e->key = path;
        evt = e;
    } else {
        return;
    }

    // Dedup against last event
    if (!run->events.empty() && run->events.back()->event == evt->event) {
        auto* last = run->events.back().get();
        if (auto* le = dynamic_cast<RegOpenEvent*>(last)) {
            if (le->key == path) return;
        } else if (auto* le = dynamic_cast<RegReadEvent*>(last)) {
            if (le->key == path && le->value == value_name) return;
        }
    }

    run->events.push_back(evt);
}

// Python:418-522  record_process_event  typed process events to run->events
void Profiler::record_process_event(std::shared_ptr<Run> run, void* proc,
                                 const std::string& event_type,
                                 const std::map<std::string, std::string>& kwargs) {
    (void)proc;

    std::shared_ptr<speakeasy::events::Event> evt;
    if (event_type == PROC_CREATE) {
        auto e = std::make_shared<ProcessCreateEvent>();
        auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
        auto cit = kwargs.find("cmdline"); if (cit != kwargs.end()) e->cmdline = cit->second;
        evt = e;
    } else if (event_type == MEM_ALLOC) {
        auto e = std::make_shared<MemAllocEvent>();
        auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
        auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
        auto sit = kwargs.find("size"); if (sit != kwargs.end()) e->size = sit->second;
        auto prt = kwargs.find("protect"); if (prt != kwargs.end()) e->protect = prt->second;
        evt = e;
    } else if (event_type == MEM_WRITE || event_type == MEM_READ) {
        // Merge adjacent same-type events (Python: last_base + last_size == base)
        if (!run->events.empty() &&
            last_event_type == event_type &&
            last_data.size() >= 2 &&
            kwargs.count("base") && kwargs.count("size")) {
            uint64_t last_base = last_data[0];
            uint64_t last_size = last_data[1];
            uint64_t new_base = 0, new_size = 0;
            try { new_base = std::stoull(kwargs.at("base")); } catch (...) {}
            try { new_size = std::stoull(kwargs.at("size")); } catch (...) {}

            if ((last_base + last_size) == new_base) {
                auto* last = run->events.back().get();
                if (event_type == MEM_WRITE) {
                    if (auto* le = dynamic_cast<MemWriteEvent*>(last)) {
                        le->size += static_cast<int>(new_size);
                        if (kwargs.count("data")) {
                            std::string new_data_str = kwargs.at("data");
                            std::vector<uint8_t> nd(new_data_str.begin(), new_data_str.end());
                            le->data_ref = merge_binary_data(le->data_ref, nd, 1024);
                        }
                    }
                } else {
                    if (auto* le = dynamic_cast<MemReadEvent*>(last)) {
                        le->size += static_cast<int>(new_size);
                        if (kwargs.count("data")) {
                            std::string new_data_str = kwargs.at("data");
                            std::vector<uint8_t> nd(new_data_str.begin(), new_data_str.end());
                            le->data_ref = merge_binary_data(le->data_ref, nd, 1024);
                        }
                    }
                }
                last_data = {new_base, new_size};
                return;
            }
        }

        if (event_type == MEM_WRITE) {
            auto e = std::make_shared<MemWriteEvent>();
            auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
            auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
            auto sit = kwargs.find("size"); if (sit != kwargs.end()) e->size = static_cast<int>(std::stoull(sit->second));
            auto dit = kwargs.find("data"); if (dit != kwargs.end()) {
                std::vector<uint8_t> d(dit->second.begin(), dit->second.end());
                e->data_ref = handle_binary_data(d);
            }
            evt = e;
        } else {
            auto e = std::make_shared<MemReadEvent>();
            auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
            auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
            auto sit = kwargs.find("size"); if (sit != kwargs.end()) e->size = static_cast<int>(std::stoull(sit->second));
            auto dit = kwargs.find("data"); if (dit != kwargs.end()) {
                std::vector<uint8_t> d(dit->second.begin(), dit->second.end());
                e->data_ref = handle_binary_data(d);
            }
            evt = e;
        }

        if (kwargs.count("base") && kwargs.count("size")) {
            try { last_data = {std::stoull(kwargs.at("base")), std::stoull(kwargs.at("size"))}; }
            catch (...) { last_data = {0, 0}; }
        }
    } else if (event_type == MEM_PROTECT) {
        auto e = std::make_shared<MemProtectEvent>();
        auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
        auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
        auto sit = kwargs.find("size"); if (sit != kwargs.end()) e->size = sit->second;
        auto oit = kwargs.find("old_protect"); if (oit != kwargs.end()) e->old_protect = oit->second;
        auto nit = kwargs.find("new_protect"); if (nit != kwargs.end()) e->new_protect = nit->second;
        evt = e;
    } else if (event_type == MEM_FREE_STR) {
        auto e = std::make_shared<MemFreeEvent>();
        auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
        auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
        auto sit = kwargs.find("size"); if (sit != kwargs.end()) e->size = sit->second;
        evt = e;
    } else if (event_type == THREAD_CREATE) {
        auto e = std::make_shared<ThreadCreateEvent>();
        auto tit = kwargs.find("thread_id"); if (tit != kwargs.end()) e->thread_id = std::stoi(tit->second);
        auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
        evt = e;
    } else if (event_type == THREAD_INJECT) {
        auto e = std::make_shared<ThreadInjectEvent>();
        auto pit = kwargs.find("path"); if (pit != kwargs.end()) e->path = pit->second;
        auto bit = kwargs.find("base"); if (bit != kwargs.end()) e->base = bit->second;
        evt = e;
    } else {
        return; // unknown
    }

    last_event_type = event_type;
    run->events.push_back(evt);
}

// Python:524-537  record_dns_event  NetDnsEvent
void Profiler::record_dns_event(std::shared_ptr<Run> run, const std::string& domain,
                       const std::string& ip) {
    // Dedup by query+response (Python: same logic)
    for (const auto& evt : run->events) {
        auto* existing = dynamic_cast<NetDnsEvent*>(evt.get());
        if (existing && existing->query == domain && existing->result == ip) {
            return;
        }
    }
    auto evt = std::make_shared<NetDnsEvent>();
    evt->query = domain;
    evt->result = ip.empty() ? "" : ip;
    run->events.push_back(evt);
}

// Python:539-567  record_http_event  NetHttpEvent
void Profiler::record_http_event(std::shared_ptr<Run> run, const std::string& server, int port,
                        const std::string& proto,
                        const std::string& headers,
                        const std::vector<uint8_t>& body, bool secure) {
    std::string proto_str = secure ? "https" : "http";
    std::string body_ref = handle_binary_data(body);

    auto http_evt = std::make_shared<NetHttpEvent>();
    http_evt->server = server;
    http_evt->port = port;
    http_evt->proto = proto;
    http_evt->headers = headers;
    http_evt->body_ref = body_ref;

    // Dedup by server+port+proto+headers (Python: same logic)
    for (const auto& evt : run->events) {
        if (evt->event == NET_HTTP) {
            auto* existing = dynamic_cast<NetHttpEvent*>(evt.get());
            if (existing && (*http_evt.get() == *existing)) {
                return;
            }
        }
    }

    run->events.push_back(http_evt);
}

// Python:569-576  record_dyn_code_event  stored separately (not in events list)
void Profiler::record_dyn_code_event(std::shared_ptr<Run> run, const std::string& tag,
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

// Python:578-595  record_network_event  NetTrafficEvent
void Profiler::record_network_event(std::shared_ptr<Run> run, const std::string& server, int port,
                           const std::string& typ,
                           const std::string& proto,
                           const std::vector<uint8_t>& data,
                           const std::string& method) {
    std::string data_ref = handle_binary_data(data);

    auto evt = std::make_shared<NetTrafficEvent>();
    evt->protocol = proto;
    evt->src = server + ":" + std::to_string(port);
    evt->dst = typ;
    if (!data_ref.empty()) evt->data_ref = data_ref;
    run->events.push_back(evt);
}

// Python:597-620  record_exception_event  ExceptionEvent
void Profiler::record_exception_event(std::shared_ptr<Run> run, const std::map<std::string,std::string>& info) {
    auto evt = std::make_shared<ExceptionEvent>();
    auto tit = info.find("type");     if (tit != info.end()) evt->exception_type = tit->second;
    auto pit = info.find("pc");       if (pit != info.end()) evt->pc = pit->second;
    auto iit = info.find("info");     if (iit != info.end()) evt->info = iit->second;
    run->events.push_back(evt);
}

// Python:622-633  record_module_load_event  ModuleLoadEvent
void Profiler::record_module_load_event(std::shared_ptr<Run> run, const std::string& name,
                               const std::string& path, uint64_t base, uint64_t size) {
    auto evt = std::make_shared<ModuleLoadEvent>();
    evt->module_name = name;
    evt->path = path;
    evt->base = "0x" + hex_str(base, false);
    evt->size = "0x" + hex_str(size, false);
    run->events.push_back(evt);
}

// Python:642-796  get_report  reads directly from run->events (matches Python)
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
        ep.instr_count = run->instr_cnt > 0 ? std::optional<int>(static_cast<int>(run->instr_cnt)) : std::nullopt;
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
        if (!run->coverage.empty()) {
            ep.coverage = std::vector<uint64_t>(run->coverage.begin(), run->coverage.end());
        }

        // Pass run->events directly (matches Python's ep.events = events)
        if (!run->events.empty()) {
            ep.events = run->events;
        }

        rpt.entry_points.push_back(ep);
    }

    // Strings report
    auto ansi_it = strings_.find("ansi");
    auto uni_it = strings_.find("unicode");
    auto dansi_it = decoded_strings_.find("ansi");
    auto duni_it = decoded_strings_.find("unicode");
    if ((ansi_it != strings_.end() && !ansi_it->second.empty()) ||
        (uni_it != strings_.end() && !uni_it->second.empty()) ||
        (dansi_it != decoded_strings_.end() && !dansi_it->second.empty()) ||
        (duni_it != decoded_strings_.end() && !duni_it->second.empty())) {
        speakeasy::StringsReport sr;
        if(ansi_it != strings_.end())
            sr.static_strings.ansi = ansi_it->second;
        if (uni_it != strings_.end())
            sr.static_strings.unicode = uni_it->second;
        if (dansi_it != decoded_strings_.end())
            sr.in_memory.ansi = dansi_it->second;
        if (duni_it != decoded_strings_.end())
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
