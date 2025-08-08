// profiler.h
#ifndef PROFILER_H
#define PROFILER_H

// Data format versioning
const std::string __report_version__ = "1.1.0";

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <memory>
#include <chrono>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <cstring>
#include <exception>

// TODO: Need to define constants like PROC_CREATE, MEM_ALLOC, etc.
// #include "const.h"

// Custom exception class for profiler errors
class ProfileError : public std::exception {
private:
    std::string message;
    
public:
    explicit ProfileError(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};

// Represents a symbolicated chunk of memory that can be tracked
class MemAccess {
public:
    uint64_t base;
    uint64_t size;
    std::string sym;
    int reads;
    int writes;
    int execs;
    
    MemAccess(uint64_t base = 0, const std::string& sym = "", uint64_t size = 0) 
        : base(base), size(size), sym(sym), reads(0), writes(0), execs(0) {}
};

// Forward declarations
class Run;
class Profiler;

// This class represents the basic execution primitive for the emulation engine
// A "run" can represent any form of execution: a thread, a callback, an exported function,
// or even a child process.
class Run {
public:
    uint64_t instr_cnt;
    void* ret_val;
    std::vector<std::map<std::string, std::string>> apis;
    std::map<std::string, MemAccess> sym_access;
    std::map<std::string, std::vector<std::map<std::string, std::string>>> network;
    std::vector<std::map<std::string, std::string>> file_access;
    std::vector<std::map<std::string, std::string>> dropped_files;
    std::vector<std::map<std::string, std::string>> registry_access;
    std::vector<std::map<std::string, std::string>> process_events;
    std::map<std::string, MemAccess> mem_access;
    std::map<std::string, std::vector<std::map<std::string, std::string>>> dyn_code;
    std::set<uint64_t> base_addrs;
    void* process_context;
    void* thread;
    std::vector<std::string> unique_apis;
    // TODO: Replace with proper hash implementation
    // std::hash<std::string> api_hash;
    std::vector<std::map<std::string, std::string>> handled_exceptions;
    void* stack;
    std::vector<std::function<void()>> api_callbacks;
    std::deque<uint64_t> exec_cache;
    std::deque<uint64_t> read_cache;
    std::deque<uint64_t> write_cache;
    
    std::vector<std::string> args;
    uint64_t start_addr;
    std::string type;
    std::map<std::string, std::string> error;
    int num_apis;
    
    Run();
    
    // Get the number of APIs that were called during the run
    int get_api_count();
};

// The profiler class exists to generate an execution report
// for all runs that occur within a binary emulation.
class Profiler {
private:
    double start_time;
    std::map<std::string, std::vector<std::string>> strings;
    std::map<std::string, std::vector<std::string>> decoded_strings;
    std::vector<int> last_data;
    std::map<std::string, std::string> last_event;
    double runtime;
    std::map<std::string, std::string> meta;
    std::vector<std::shared_ptr<Run>> runs;
    
public:
    Profiler();
    
    // Add top level profiler fields containing metadata for the
    // module that will be emulated
    void add_input_metadata(const std::map<std::string, std::string>& meta);
    
    // Get the start time for a sample so we can time the execution length
    void set_start_time();
    
    // Get the time spent emulating a specific "run"
    double get_run_time();
    
    // Stop the runtime clock to include in the report
    void stop_run_clock();
    
    // Get the current time in epoch format
    long get_epoch_time();
    
    // Add a new run to the captured run list
    void add_run(std::shared_ptr<Run> run);
    
    // Compress and encode binary data to be included in a report
    std::string handle_binary_data(const std::vector<uint8_t>& data);
    
    // Log a top level emulator error for the emulation report
    void log_error(const std::string& error);
    
    void log_dropped_files(std::shared_ptr<Run> run, const std::vector<void*>& files);
    
    // Log a call to an OS API. This includes arguments, return address, and return value
    void log_api(std::shared_ptr<Run> run, uint64_t pc, const std::string& name, 
                 void* ret, const std::vector<std::string>& argv, 
                 const std::vector<std::string>& ctx = {});
    
    // Log file access events. This will include things like handles being opened,
    // data reads, and data writes.
    void log_file_access(std::shared_ptr<Run> run, const std::string& path, 
                         const std::string& event_type, 
                         const std::vector<uint8_t>& data = {},
                         int handle = 0, 
                         const std::vector<std::string>& disposition = {},
                         const std::vector<std::string>& access = {},
                         uint64_t buffer = 0, int size = -1);
    
    // Log registry access events. This includes values and keys being accessed and
    // being read/written
    void log_registry_access(std::shared_ptr<Run> run, const std::string& path,
                             const std::string& event_type, 
                             const std::string& value_name = "",
                             const std::vector<uint8_t>& data = {},
                             int handle = 0,
                             const std::vector<std::string>& disposition = {},
                             const std::vector<std::string>& access = {},
                             uint64_t buffer = 0, int size = -1);
    
    // Log events related to a process accessing another process. This includes:
    // creating a child process, reading/writing to a process, or creating a thread
    // within another process.
    void log_process_event(std::shared_ptr<Run> run, void* proc, 
                           const std::string& event_type, 
                           const std::map<std::string, std::string>& kwargs);
    
    // Log DNS name lookups for the emulation report
    void log_dns(std::shared_ptr<Run> run, const std::string& domain, 
                 const std::string& ip = "");
    
    // Log HTTP traffic that occur during emulation
    void log_http(std::shared_ptr<Run> run, const std::string& server, int port, 
                  const std::string& proto = "http",
                  const std::string& headers = "", 
                  const std::vector<uint8_t>& body = {}, bool secure = false);
    
    // Log code that is generated at runtime and then executed
    void log_dyn_code(std::shared_ptr<Run> run, const std::string& tag, 
                      uint64_t base, uint64_t size);
    
    // Log network activity for an emulation run
    void log_network(std::shared_ptr<Run> run, const std::string& server, int port, 
                     const std::string& typ = "unknown", 
                     const std::string& proto = "unknown", 
                     const std::vector<uint8_t>& data = {}, 
                     const std::string& method = "");
    
    // Retrieve the execution profile for the emulator as a json string
    std::string get_json_report();
    
    // Retrieve the execution profile for the emulator
    std::map<std::string, std::string> get_report();
};

#endif // PROFILER_H