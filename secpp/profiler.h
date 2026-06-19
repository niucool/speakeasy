// profiler.h  Execution profiler and report generation
// Ported from: speakeasy/profiler.py (796 lines)
// Porting status: 23/23 methods declared | 21 full impl + 2 stubs
//   - record_dropped_files_event: stub (needs FileData C++ class)
//   - Run.section_access: not ported (dict[(section_base,section_size), MemAccess])
//   - Profiler.last_event: C++ stores last_event_type only (string vs full Python AnyEvent)
// Last sync: 2026-05-17
//
// Python class hierarchy: ProfileError, MemAccess, Run, Profiler
// Design: C++ stores typed map<string,string> entries per event category
//   (apis/file_access/registry_access/process_events) parallel to Python's
//   list[AnyEvent]. get_json_report() wraps via speakeasy::Report model.
//
// Python docstrings synced to C++ comments for all class/method declarations.
// Reference lines noted via // Python:<line>

#ifndef PROFILER_H
#define PROFILER_H

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <memory>
#include <chrono>
#include <algorithm>
#include <functional>
#include <optional>
#include <nlohmann/json.hpp>
#include <exception>

//#include "const.h"
#include "struct.h"
#include "artifacts.h"
#include "report.h"
#include "windows/objman.h"
#include "profiler_events.h"
#include "winenv/api/api.h"

const std::string __report_version__ = "3.0.0";

class File;

// Python:73-74
// class ProfileError(Exception): pass
class ProfileError : public std::exception {
    std::string message;
public:
    explicit ProfileError(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};

// Python:77-88
// class MemAccess:
//     """Represents a symbolicated chunk of memory that can be tracked"""
//     def __init__(self, base=None, sym=None, size=0):
//         self.base = base
//         self.size = size
//         self.sym = sym
//         self.reads = 0
//         self.writes = 0
//         self.execs = 0
class MemAccess {
public:
    uint64_t base; uint64_t size; std::string sym;
    int reads = 0, writes = 0, execs = 0;
    MemAccess(uint64_t b = 0, uint64_t sz = 0, const std::string& s = "")
        : base(b), size(sz), sym(s), reads(0), writes(0), execs(0) {}
};

class Run; class Profiler;

// Python:91-131
// class Run:
//     """
//     This class represents the basic execution primative for the emulation engine
//     A "run" can represent any form of execution: a thread, a callback, an exported function,
//     or even a child process.
//     """
//     def __init__(self):
class Run {
public:
    uint64_t instr_cnt = 0;            // Python:99  self.instr_cnt: int = 0
    void* ret_val = nullptr;           // Python:100  self.ret_val: int | None = None
    std::vector<std::shared_ptr<speakeasy::events::Event>> events;  // Python:101  self.events: list[AnyEvent]
    std::map<std::string,MemAccess> sym_access;                    // Python:102
    // Python:103  self.dropped_files: list[dict]  stored as DroppedFileEvent in events
    std::map<std::string,MemAccess> mem_access;                    // Python:104
    // Python:105  self.section_access: dict[tuple[int, int], MemAccess] = {}  NOT PORTED
    std::map<std::string,std::vector<std::map<std::string,std::string>>> dyn_code; // Python:106
    std::set<uint64_t> base_addrs;                                 // Python:106
    std::shared_ptr<Process> process_context = nullptr;   // Python:107
    std::shared_ptr<Thread> thread = nullptr;            // Python:108
    std::vector<std::string> unique_apis;                          // Python:109
    std::string api_hash_data;         // Python:110 accumulated lowercase names (SHA-256)
    // Python:111  self.stack: MemAccess | None = None  stored externally
    MemAccess stack;
    std::deque<uint64_t> exec_cache{4};  // Python:113
    std::deque<uint64_t> read_cache{4};  // Python:114
    std::deque<uint64_t> write_cache{4}; // Python:115
    std::vector<std::string> args;     // Python:117
    std::vector<uint64_t> args_values;
    uint64_t start_addr = 0;           // Python:118
    std::string type;                  // Python:119
    std::map<std::string,std::string> error; // Python:120
    int num_apis = 0;                  // Python:121
    // Python: run.api_callbacks = [(pc, orig_func, args), ...]
    // Stores (return_pc, callback_fn, original_args) for API_CALLBACK_HANDLER_ADDR dispatch
    std::vector<std::tuple<uint64_t, std::function<void()>, std::vector<uint64_t>>> api_callbacks;
    std::set<uint64_t> coverage;       // Python:122
    std::vector<std::map<std::string,std::string>> memory_regions;   // Python:123
    std::vector<std::map<std::string,std::string>> loaded_modules;   // Python:124
    Run();
    // """Get the number of APIs that were called during the run"""  (Python:126-130)
    int get_api_count();
};

// Python:133-796
// class Profiler:
//     """
//     The profiler class exists to generate an execution report
//     for all runs that occur within a binary emulation.
//     """
//     def __init__(self):
class Profiler {
public:
    /** Set extracted strings for profiling (ansi/unicode) */
    void set_strings(const std::string& key, const std::vector<std::string>& vals) {
        strings_[key] = vals;
    }
    /** Get strings by category */
    const std::vector<std::string>& get_strings(const std::string& key) const {
        static const std::vector<std::string> empty;
        auto it = strings_.find(key);
        return (it != strings_.end()) ? it->second : empty;
    }
private:
    double start_time = 0;             // Python:142  self.start_time: float = 0
    std::map<std::string,std::vector<std::string>> strings_;       // Python:143
    std::map<std::string,std::vector<std::string>> decoded_strings_; // Python:144
    std::vector<uint64_t> last_data;   // Python:145  [base, size] for process merge tracking
    // Python:146  self.last_event: AnyEvent | dict[str, Any] = {}  only type tracked
    std::string last_event_type;       // Python:146 type name only (vs full Python AnyEvent)
    double runtime = 0;                // Python:148  self.runtime: float = 0
    std::map<std::string,std::string> meta; // Python:149  self.meta: dict[str, Any] = {}
    std::vector<std::shared_ptr<Run>> runs; // Python:150  self.runs: list[Run] = []
    speakeasy::ArtifactStore artifact_store; // Python:151
public:
    Profiler();
    // Python:153-158
    // """Add top level profiler fields containing metadata for the module that will be emulated"""
    void add_input_metadata(const std::map<std::string,std::string>& m);
    // Python:160-164
    // """Get the start time for a sample so we can time the execution length"""
    void set_start_time();
    // Python:166-170
    // """Get the time spent emulating a specific "run\""""
    double get_run_time();
    // Python:172-176
    // """Stop the runtime clock to include in the report"""
    void stop_run_clock();
    // Python:178-182
    // """Get the current time in epoch format"""
    long get_epoch_time();
    // Python:184-188
    // """Add a new run to the captured run list"""
    void add_run(std::shared_ptr<Run> run);
    // Python:190-206
    // """Store binary data and return its artifact reference."""
    std::string handle_binary_data(const std::vector<uint8_t>& data);
    std::string put_binary_data(const std::vector<uint8_t>& data, int limit = 0);
    // """Append raw bytes to an existing artifact payload and store the merged result."""
    std::string merge_binary_data(const std::string& ref, const std::vector<uint8_t>& data, int limit = 0);
    // Python:208-212
    // """Log a top level emulator error for the emulation report."""
    void record_error_event(const speakeasy::ErrorInfo& error);
    // Python:214-225  log dropped files from an emulation run
    void record_dropped_files_event(std::shared_ptr<Run> run, const std::vector<std::shared_ptr<File>>& files);
    // Python:227-259
    // """Log a call to an OS API. This includes arguments, return address, and return value"""
    void record_api_event(std::shared_ptr<Run> run, const speakeasy::events::TracePosition& pos, const std::string& name, uint64_t ret,
                 const ArgList& argv, const std::vector<std::string>& ctx = {});
    // Python:261-338
    // """Log file access events. This will include things like handles being opened,
    //    data reads, and data writes."""
    void record_file_access_event(std::shared_ptr<Run> run, const std::string& path, const std::string& event_type,
                         const std::vector<uint8_t>& data = {}, int handle = 0,
                         const std::vector<std::string>& disposition = {},
                         const std::vector<std::string>& access = {}, uint64_t buffer = 0, int size = -1);
    // Python:340-416
    // """Log registry access events that occur during emulation including values being read/written"""
    void record_registry_access_event(std::shared_ptr<Run> run, const std::string& path, const std::string& event_type,
                             const std::string& value_name = "", const std::vector<uint8_t>& data = {},
                             int handle = 0, const std::vector<std::string>& disposition = {},
                             const std::vector<std::string>& access = {}, uint64_t buffer = 0, int size = -1);
    // Python:418-522
    // """Log process events (create, exit, memory alloc/free/protect, thread create/inject)
    //    that are created within another process."""
    void record_process_event(std::shared_ptr<Run> run, void* proc, const std::string& event_type,
                           const std::map<std::string,std::string>& kwargs);
    // Python:524-537
    // """Log DNS name lookups for the emulation report"""
    void record_dns_event(std::shared_ptr<Run> run, const std::string& domain, const std::string& ip = "");
    // Python:539-567
    // """Log HTTP traffic that occur during emulation"""
    void record_http_event(std::shared_ptr<Run> run, const std::string& server, int port,
                  const std::string& proto = "http", const std::string& headers = "",
                  const std::vector<uint8_t>& body = {}, bool secure = false);
    // Python:569-576
    // """Log code that is generated at runtime and then executed"""
    void record_dyn_code_event(std::shared_ptr<Run> run, const std::string& tag, uint64_t base, uint64_t size);
    // Python:578-595
    // """Log network activity for an emulation run"""
    void record_network_event(std::shared_ptr<Run> run, const std::string& server, int port,
                     const std::string& typ = "unknown", const std::string& proto = "unknown",
                     const std::vector<uint8_t>& data = {}, const std::string& method = "");
    // Python:597-620  TODO: full impl with ExceptionEvent typed events
    void record_exception_event(std::shared_ptr<Run> run, const std::map<std::string,std::string>& info);
    // Python:622-633  TODO: full impl with ModuleLoadEvent typed events
    void record_module_load_event(std::shared_ptr<Run> run, const std::string& name, const std::string& path,
                         uint64_t base, uint64_t size);
    // Python:635-796  build full speakeasy::Report
    speakeasy::Report get_report() const;
    nlohmann::json get_json_report() const;
    std::string get_json_report_string() const;
    // Legacy string-based error logging (Python compat)
    std::map<std::string,std::string> get_profile_summary() const;
    void record_error_event(const std::string& error);
};

#endif // PROFILER_H
