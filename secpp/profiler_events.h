// profiler_events.h  Event type constants and structures for the Speakeasy profiler
//
// Maps to: speakeasy/profiler_events.py
//
// This header defines event type string constants and POD structs for
// each event payload type emitted during emulation.  Consumers use the
// "event" field to discriminate between payloads.

#ifndef SPEAKEASY_PROFILER_EVENTS_H
#define SPEAKEASY_PROFILER_EVENTS_H

#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace speakeasy {
namespace events {

//  Event type discriminator constants 

// Process events
inline const std::string PROC_CREATE   = "process_create";
inline const std::string MEM_ALLOC     = "mem_alloc";
inline const std::string MEM_WRITE     = "mem_write";
inline const std::string MEM_READ      = "mem_read";
inline const std::string MEM_PROTECT   = "mem_protect";
inline const std::string MEM_FREE      = "mem_free";
inline const std::string MODULE_LOAD   = "module_load";
inline const std::string THREAD_INJECT = "thread_inject";
inline const std::string THREAD_CREATE = "thread_create";

// File events
inline const std::string FILE_CREATE = "file_create";
inline const std::string FILE_WRITE  = "file_write";
inline const std::string FILE_OPEN   = "file_open";
inline const std::string FILE_READ   = "file_read";

// Registry events
inline const std::string REG_OPEN   = "reg_open_key";
inline const std::string REG_READ   = "reg_read_value";
inline const std::string REG_WRITE  = "reg_write_value";
inline const std::string REG_LIST   = "reg_list_subkeys";
inline const std::string REG_CREATE = "reg_create_key";

// Network events
inline const std::string NET_DNS     = "net_dns";
inline const std::string NET_TRAFFIC = "net_traffic";
inline const std::string NET_HTTP    = "net_http";

// Exception events
inline const std::string EXCEPTION = "exception";

// API events
inline const std::string API = "api";

//  Execution position 

struct TracePosition {
    int tick = 0;           // instruction-count tick
    int tid = 0;            // thread id
    int pid = 0;            // process id
    int pc = -1;            // program counter; -1 when unavailable

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["tick"] = tick;
        j["tid"]  = tid;
        j["pid"]  = pid;
        if (pc != -1) j["pc"] = pc;
        return j;
    }
};

//  Base event 

struct Event {
    TracePosition pos;
    std::string event;   // discriminator

    virtual ~Event() = default;
    virtual nlohmann::json to_json() const {
        nlohmann::json j;
        j["pos"]   = pos.to_json();
        j["event"] = event;
        return j;
    }
};

//  Concrete event types 

struct ApiEvent : Event {
    std::string api_name;
    std::vector<std::string> args;
    std::string ret_val;   // empty when not captured

    ApiEvent() { event = API; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["api_name"] = api_name;
        j["args"]     = args;
        if (!ret_val.empty()) j["ret_val"] = ret_val;
        return j;
    }
};

struct ProcessCreateEvent : Event {
    std::string path;
    std::string cmdline;

    ProcessCreateEvent() { event = PROC_CREATE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"]    = path;
        j["cmdline"] = cmdline;
        return j;
    }
};

struct MemAllocEvent : Event {
    std::string path;       // target process path
    std::string base;       // hex string
    std::string size;       // hex string
    std::string protect;    // optional

    MemAllocEvent() { event = MEM_ALLOC; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        j["base"] = base;
        j["size"] = size;
        if (!protect.empty()) j["protect"] = protect;
        return j;
    }
};

struct MemWriteEvent : Event {
    std::string path;
    std::string base;       // hex string
    int size = 0;
    std::string data_ref;   // optional

    MemWriteEvent() { event = MEM_WRITE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        j["base"] = base;
        j["size"] = size;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

struct MemReadEvent : Event {
    std::string path;
    std::string base;
    int size = 0;
    std::string data_ref;

    MemReadEvent() { event = MEM_READ; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        j["base"] = base;
        j["size"] = size;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

struct MemProtectEvent : Event {
    std::string path;
    std::string base;
    std::string size;
    std::string old_protect;
    std::string new_protect;

    MemProtectEvent() { event = MEM_PROTECT; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"]        = path;
        j["base"]        = base;
        j["size"]        = size;
        j["old_protect"] = old_protect;
        j["new_protect"] = new_protect;
        return j;
    }
};

struct MemFreeEvent : Event {
    std::string path;
    std::string base;
    std::string size;

    MemFreeEvent() { event = MEM_FREE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        j["base"] = base;
        j["size"] = size;
        return j;
    }
};

struct ModuleLoadEvent : Event {
    std::string module_name;
    std::string base;
    std::string size;
    std::string path;

    ModuleLoadEvent() { event = MODULE_LOAD; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["module_name"] = module_name;
        j["base"]        = base;
        j["size"]        = size;
        j["path"]        = path;
        return j;
    }
};

struct ThreadCreateEvent : Event {
    int thread_id = 0;
    std::string base;       // stack base

    ThreadCreateEvent() { event = THREAD_CREATE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["thread_id"] = thread_id;
        j["base"]      = base;
        return j;
    }
};

struct ThreadInjectEvent : Event {
    std::string path;
    std::string base;

    ThreadInjectEvent() { event = THREAD_INJECT; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        j["base"] = base;
        return j;
    }
};

// File events
struct FileCreateEvent : Event {
    std::string path;

    FileCreateEvent() { event = FILE_CREATE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        return j;
    }
};

struct FileWriteEvent : Event {
    std::string path;
    std::string data_ref;   // optional

    FileWriteEvent() { event = FILE_WRITE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

struct FileOpenEvent : Event {
    std::string path;

    FileOpenEvent() { event = FILE_OPEN; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        return j;
    }
};

struct FileReadEvent : Event {
    std::string path;
    std::string data_ref;

    FileReadEvent() { event = FILE_READ; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["path"] = path;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

// Registry events
struct RegOpenEvent : Event {
    std::string key;

    RegOpenEvent() { event = REG_OPEN; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["key"] = key;
        return j;
    }
};

struct RegReadEvent : Event {
    std::string key;
    std::string value;

    RegReadEvent() { event = REG_READ; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["key"]   = key;
        j["value"] = value;
        return j;
    }
};

struct RegWriteEvent : Event {
    std::string key;
    std::string value;
    std::string data;

    RegWriteEvent() { event = REG_WRITE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["key"]   = key;
        j["value"] = value;
        if (!data.empty()) j["data"] = data;
        return j;
    }
};

struct RegListEvent : Event {
    std::string key;

    RegListEvent() { event = REG_LIST; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["key"] = key;
        return j;
    }
};

struct RegCreateEvent : Event {
    std::string key;

    RegCreateEvent() { event = REG_CREATE; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["key"] = key;
        return j;
    }
};

// Network events
struct NetDnsEvent : Event {
    std::string query;
    std::string result;

    NetDnsEvent() { event = NET_DNS; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["query"]  = query;
        j["result"] = result;
        return j;
    }
};

struct NetTrafficEvent : Event {
    std::string protocol;   // tcp, udp
    std::string src;
    std::string dst;
    std::string data_ref;

    NetTrafficEvent() { event = NET_TRAFFIC; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["protocol"] = protocol;
        j["src"]      = src;
        j["dst"]      = dst;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

struct NetHttpEvent : Event {
    std::string verb;
    std::string url;
    std::string data_ref;

    NetHttpEvent() { event = NET_HTTP; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["verb"] = verb;
        j["url"]  = url;
        if (!data_ref.empty()) j["data_ref"] = data_ref;
        return j;
    }
};

// Exception event
struct ExceptionEvent : Event {
    std::string exception_type;  // e.g. ACCESS_VIOLATION, ILLEGAL_INSTRUCTION
    std::string pc;              // hex string
    std::string info;            // extra context

    ExceptionEvent() { event = EXCEPTION; }

    nlohmann::json to_json() const override {
        nlohmann::json j = Event::to_json();
        j["exception_type"] = exception_type;
        j["pc"]             = pc;
        j["info"]           = info;
        return j;
    }
};

//  Event factory 

/**
 * Create the appropriate event struct based on the event type string.
 * Returns nullptr for unknown event types.
 */
inline std::unique_ptr<Event> make_event(const std::string& event_type) {
    if (event_type == API)              return std::make_unique<ApiEvent>();
    if (event_type == PROC_CREATE)      return std::make_unique<ProcessCreateEvent>();
    if (event_type == MEM_ALLOC)        return std::make_unique<MemAllocEvent>();
    if (event_type == MEM_WRITE)        return std::make_unique<MemWriteEvent>();
    if (event_type == MEM_READ)         return std::make_unique<MemReadEvent>();
    if (event_type == MEM_PROTECT)      return std::make_unique<MemProtectEvent>();
    if (event_type == MEM_FREE)         return std::make_unique<MemFreeEvent>();
    if (event_type == MODULE_LOAD)      return std::make_unique<ModuleLoadEvent>();
    if (event_type == THREAD_CREATE)    return std::make_unique<ThreadCreateEvent>();
    if (event_type == THREAD_INJECT)    return std::make_unique<ThreadInjectEvent>();
    if (event_type == FILE_CREATE)      return std::make_unique<FileCreateEvent>();
    if (event_type == FILE_WRITE)       return std::make_unique<FileWriteEvent>();
    if (event_type == FILE_OPEN)        return std::make_unique<FileOpenEvent>();
    if (event_type == FILE_READ)        return std::make_unique<FileReadEvent>();
    if (event_type == REG_OPEN)         return std::make_unique<RegOpenEvent>();
    if (event_type == REG_READ)         return std::make_unique<RegReadEvent>();
    if (event_type == REG_WRITE)        return std::make_unique<RegWriteEvent>();
    if (event_type == REG_LIST)         return std::make_unique<RegListEvent>();
    if (event_type == REG_CREATE)       return std::make_unique<RegCreateEvent>();
    if (event_type == NET_DNS)          return std::make_unique<NetDnsEvent>();
    if (event_type == NET_TRAFFIC)      return std::make_unique<NetTrafficEvent>();
    if (event_type == NET_HTTP)         return std::make_unique<NetHttpEvent>();
    if (event_type == EXCEPTION)        return std::make_unique<ExceptionEvent>();
    return nullptr;
}

} // namespace events
} // namespace speakeasy

#endif // SPEAKEASY_PROFILER_EVENTS_H
