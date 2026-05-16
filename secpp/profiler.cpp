// profiler.cpp
#include "profiler.h"
#include <nlohmann/json.hpp>
#include <picosha2.h>
#include <cctype>

using namespace speakeasy;

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

int Run::get_api_count() {
    return num_apis;
}

Profiler::Profiler() : start_time(0), runtime(0) {
    set_start_time();
    strings["ansi"] = std::vector<std::string>();
    strings["unicode"] = std::vector<std::string>();
    decoded_strings["ansi"] = std::vector<std::string>();
    decoded_strings["unicode"] = std::vector<std::string>();
    last_data = {0, 0};
}

void Profiler::add_input_metadata(const std::map<std::string, std::string>& meta_input) {
    this->meta = meta_input;
}

void Profiler::set_start_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    start_time = nanoseconds.count() / 1000000000.0;
}

double Profiler::get_run_time() {
    auto now = std::chrono::high_resolution_clock::now();
    auto duration = now.time_since_epoch();
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);
    double current_time = nanoseconds.count() / 1000000000.0;
    return current_time - start_time;
}

void Profiler::stop_run_clock() {
    runtime = get_run_time();
}

long Profiler::get_epoch_time() {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
}

void Profiler::add_run(std::shared_ptr<Run> run) {
    runs.push_back(run);
}

std::string Profiler::handle_binary_data(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    return artifact_store.put_bytes(data);
}

void Profiler::log_error(const std::string& error) {
    if (meta.find("errors") == meta.end()) {
        meta["errors"] = "";
    }
    meta["errors"] += error + ";";
}

void Profiler::log_dropped_files(std::shared_ptr<Run> /*run*/, const std::vector<void*>& files) {
    for (void* f : files) {
        (void)f;
        // When a FileData C++ class is implemented, this will iterate,
        // call get_data()/get_hash(), and populate run->dropped_files.
    }
}

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

    // Dedup against last 3 API entries
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

nlohmann::json Profiler::get_json_report() const {
    nlohmann::json report;
    report["report_version"] = __report_version__;

    if (!meta.empty()) {
        report["input"] = meta;
    }

    nlohmann::json runs_array = nlohmann::json::array();
    for (auto& run : runs) {
        nlohmann::json r;
        r["start_addr"] = hex_str(run->start_addr);
        r["instr_cnt"] = run->instr_cnt;
        r["num_apis"] = run->num_apis;

        // Compute API hash from accumulated data
        if (!run->api_hash_data.empty()) {
            r["api_hash"] = picosha2::hash256_hex_string(run->api_hash_data);
        }

        if (!run->apis.empty())              r["apis"] = run->apis;
        if (!run->file_access.empty())       r["file_access"] = run->file_access;
        if (!run->registry_access.empty())   r["registry_access"] = run->registry_access;
        if (!run->process_events.empty())    r["process_events"] = run->process_events;
        if (!run->dropped_files.empty())     r["dropped_files"] = run->dropped_files;
        if (!run->dyn_code["mmap"].empty())  r["dyn_code"] = run->dyn_code;
        if (!run->network["dns"].empty() || !run->network["traffic"].empty()) {
            r["network"] = run->network;
        }

        runs_array.push_back(r);
    }
    report["runs"] = runs_array;

    if (!strings.empty())         report["static_strings"] = strings;
    if (!decoded_strings.empty()) report["decoded_strings"] = decoded_strings;
    if (meta.count("errors"))     report["errors"] = meta.at("errors");

    auto artifact_data = artifact_store.to_report_data();
    if (!artifact_data.empty()) {
        nlohmann::json data_json = nlohmann::json::object();
        for (const auto& [digest, artifact] : artifact_data) {
            data_json[digest] = artifact.to_json();
        }
        report["data"] = data_json;
    }

    return report;
}

std::string Profiler::get_json_report_string() const {
    return get_json_report().dump();
}

std::map<std::string, std::string> Profiler::get_report() {
    std::map<std::string, std::string> profile;
    profile["report_version"] = __report_version__;
    profile["runtime"] = std::to_string(runtime);
    profile["num_runs"] = std::to_string(runs.size());
    int total_apis = 0;
    for (auto& run : runs) {
        total_apis += run->num_apis;
    }
    profile["total_apis"] = std::to_string(total_apis);
    return profile;
}
