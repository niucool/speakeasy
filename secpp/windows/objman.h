// objman.h
#ifndef OBJMAN_H
#define OBJMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>

#include "../winenv/arch.h"
#include "loaders.h"

// Forward declarations
class WindowsEmulator;
class BinaryEmulator;

/**
 * Represents a console window object
 */
class Console {
private:
    static int curr_handle_;
    int handle_;
    int window_;

public:
    Console();
    int get_handle();
    void set_window(int window);
    int get_window();
};

/**
 * Implements the structures needed to support SEH handling during emulation
 */
class SEH {
public:
    /**
     * Scope record for SEH
     */
    class ScopeRecord {
    public:
        void* record;
        bool filter_called;
        bool handler_called;

        ScopeRecord(void* rec);
    };

    /**
     * Frame for SEH
     */
    class Frame {
    public:
        void* entry;
        void* scope_table;
        std::vector<ScopeRecord> scope_records;
        bool searched;

        Frame(void* entry, void* scope_table, std::vector<void*> records);
    };

private:
    void* context_;
    int context_address_;
    void* record_;
    std::vector<Frame> frames_;
    void* last_func_;
    int last_exception_code_;
    int exception_ptrs_;
    void* handler_ret_val_;

public:
    SEH();
    void set_context(void* context, int address = 0);
    void* get_context();
    void set_last_func(void* func);
    void set_record(void* record, int address = 0);
    void set_current_frame(Frame frame);
    std::vector<Frame> get_frames();
    void clear_frames();
    void add_frame(void* entry, void* scope_table, std::vector<void*> records);

    void*& get_context_ref() { return context_; }
    int& get_context_address_ref() { return context_address_; }
    void*& get_record_ref() { return record_; }
    std::vector<Frame>& get_frames_ref() { return frames_; }
    void*& get_last_func_ref() { return last_func_; }
    int& get_last_exception_code_ref() { return last_exception_code_; }
    int& get_exception_ptrs_ref() { return exception_ptrs_; }
    void*& get_handler_ret_val_ref() { return handler_ret_val_; }
};

/**
 * Base class for Kernel objects managed by the object manager
 */
class KernelObject {
protected:
    void* emu_;
    uint64_t address_;
    std::string name_;
    void* object_;
    int arch_;

public:
    static int curr_handle;
    static int curr_id;
    int ref_cnt;
    std::vector<int> handles;
    int id;

public:
    KernelObject(void* emu);
    KernelObject() : emu_(nullptr), address_(0), object_(nullptr),
                     ref_cnt(0), arch_(0), id(0) {
        id = KernelObject::curr_id;
        KernelObject::curr_id += 4;
    }
    virtual ~KernelObject() = default;

    int sizeof_obj(void* obj = nullptr);
    void* get_bytes(void* obj = nullptr);
    virtual KernelObject read_back();
    void write_back();
    int get_id();
    void set_id(int oid);
    std::string get_class_name();
    std::string get_mem_tag();
    int get_handle();
    virtual std::string get_obj_name() const { return name_; }
    virtual void set_obj_name(const std::string namel) { name_ = namel; }
    void* get_object() const { return object_; }
    uint64_t get_address() const { return address_; }
    void set_address(uint64_t addr) { address_ = addr; }
};

/**
 * Class that represents DRIVER_OBJECTs created by the Windows kernel
 */
class Driver : public KernelObject {
private:
    std::shared_ptr<speakeasy::RuntimeModule> pe_;
    std::vector<void*> mj_funcs_;
    void* on_unload_;
    bool unload_called_;
public:
    std::vector<void*> devices;
    int reg_path_ptr;
    std::string reg_path;
    std::string basename;

    // Driver entry point (DriverInit) and unload routine addresses
    uint64_t driver_init_addr = 0;
    uint64_t driver_unload_addr = 0;

    static std::vector<void*> ldr_entries;

public:
    Driver(void* emu);

    void create_reg_path(const std::string& name);
    std::string get_basename();
    std::string get_reg_path();
    void* init_driver_section();
    void init_driver_object(const std::string& name = "", std::shared_ptr<speakeasy::RuntimeModule> pe = nullptr, bool is_decoy = true);
    KernelObject read_back() override;
};

/**
 * Represents a DEVICE_OBJECT created by the windows kernel
 */
class Device : public KernelObject {
private:
    void* file_object_;
    void* driver_;

public:
    Device(void* emu);
    void* get_parent_driver();
    void init_device(const std::string& name, uint32_t dev_type,
                     uint32_t chars, void* drv);
};

/**
 * Represents a FILE_OBJECT created by the windows kernel
 */
class FileObject : public KernelObject {
public:
    FileObject(void* emu);
};

/**
 * Represents a IO_STACK_LOCATION struct that is part of an IRP.
 */
class IoStackLocation : public KernelObject {
public:
    IoStackLocation(void* emu);
};

/**
 * I/O request packet used when performing device input/output
 */
class Irp : public KernelObject {
private:
    std::vector<IoStackLocation> stack_locations_;

public:
    Irp(void* emu);
    IoStackLocation get_curr_stack_loc();
};

class Process;  // Forward declaration for circular dependency with Thread
class TEB;
class PEB;
class PebLdrData;
class LdrDataTableEntry;

/**
 * Public KernelObject subclasses for ported NT structures
 */
class PEB : public KernelObject {
public:
    PEB(void* emu, uint64_t address = 0);
    PEB() : KernelObject(nullptr) {}
};

class TEB : public KernelObject {
public:
    TEB(void* emu, uint64_t address = 0);
    TEB() : KernelObject(nullptr) {}
};

class PebLdrData : public KernelObject {
public:
    PebLdrData(void* emu);
    PebLdrData() : KernelObject(nullptr) {}
};

class LdrDataTableEntry : public KernelObject {
public:
    LdrDataTableEntry(void* emu, const std::string& dllname, const std::string& tag = "");
    LdrDataTableEntry() : KernelObject(nullptr) {}
};

class RTL_USER_PROCESS_PARAMETERS : public KernelObject {
public:
    RTL_USER_PROCESS_PARAMETERS(void* emu, Process* proc);
    RTL_USER_PROCESS_PARAMETERS() : KernelObject(nullptr) {}
};

class IDT : public KernelObject {
public:
    IDT(void* emu);
    IDT() : KernelObject(nullptr) {}
    void init_descriptors();
};

class Event : public KernelObject {
public:
    Event(void* emu);
    Event() : KernelObject(nullptr) {}
};

class Mutant : public KernelObject {
public:
    Mutant(void* emu);
    Mutant() : KernelObject(nullptr) {}
};

/**
 * Represents a Windows ETHREAD object that describes an OS level thread
 */
class Thread : public KernelObject {
private:
    void* ctx_;
    bool modified_pc_;
    std::shared_ptr<TEB> teb_;
    SEH seh_;
    std::vector<void*> tls_;
    std::vector<void*> message_queue_;
    std::vector<void*> fls_;
    int suspend_count_;
    void* token_;
    int last_error_;
    int stack_base_;
    int stack_commit_;
    std::shared_ptr<Process> process_;

public:
    Thread(void* emu, int stack_base = 0, int stack_commit = 0);
    Thread() : KernelObject(nullptr) {}

    void queue_message(void* msg);
    SEH& get_seh();
    void* get_context();
    void set_context(void* ctx);
    std::shared_ptr<Process> get_process() { return process_; }
    void set_process(std::shared_ptr<Process> proc) { process_ = proc; } 
    void init_teb(int teb_addr, int peb_addr);
    std::shared_ptr<TEB> get_teb() { return teb_; }
    void set_last_error(int code);
    int get_last_error();
    std::vector<void*> get_tls();
    void set_tls(const std::vector<void*>& tls);
    std::vector<void*> get_fls();
    void set_fls(const std::vector<void*>& fls);
    void* get_token();
    void init_tls(int tls_dir, const std::string& modname);
};

/**
 * Represents a TOKEN object
 */
class Token : public KernelObject {
public:
    Token(void* emu);
    Token() : KernelObject(nullptr) {}
};

/**
 * An EPROCESS object used by the Windows kernel to represent a process
 */
class Process : public KernelObject {
public:
    static std::vector<void*> ldr_entries;

    std::vector<std::shared_ptr<speakeasy::RuntimeModule>> modules;
    std::vector<std::shared_ptr<Thread>> threads;
    Console console;
    std::shared_ptr<Thread> curr_thread;
    std::string cmdline;
    int session;
    Token token;
    std::shared_ptr<speakeasy::RuntimeModule> pe;
    void* pe_data;
    int stdin_handle;
    int stdout_handle;
    int stderr_handle;
    std::shared_ptr<PEB> peb;
    std::shared_ptr<PebLdrData> peb_ldr_data;
    std::vector<std::shared_ptr<LdrDataTableEntry>> ldr_entries_list;
    bool is_peb_active;
    std::string path;
    std::string image;
    std::string title;
    uint64_t base;

public:
    Process(void* emu, 
        std::shared_ptr<speakeasy::RuntimeModule> pe = nullptr,
        const std::vector<std::shared_ptr<speakeasy::RuntimeModule>> user_modules = {},
            const std::string& name = "", const std::string& path = "",
            const std::string& cmdline = "", uint64_t base = 0, int session = 0);

    std::shared_ptr<PEB> get_peb();
    void set_peb_ldr_address(int addr);
    void set_process_parameters(void* emu);
    std::shared_ptr<PebLdrData> get_peb_ldr();
    void alloc_console();
    std::string get_desktop_name();
    void* get_token();
    int get_std_handle(int dev);
    std::string get_title_name();
    std::shared_ptr<speakeasy::RuntimeModule> get_module();
    void* get_ep();
    Console get_console();
    int get_session_id();
    int get_pid();
    std::string get_process_path();
    std::string get_command_line();
    void set_user_modules(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& mods);
    void new_thread();
    void add_module_to_peb(std::shared_ptr<speakeasy::RuntimeModule> module);
    void init_peb(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& modules);
};

/**
 * Class that manages kernel objects during emulation
 */
class ObjectManager {
private:
    void* emu_;
    std::map<uint64_t, std::shared_ptr<KernelObject>> objects_;
    std::vector<std::pair<std::string, std::string>> symlinks_;

public:
    ObjectManager(void* emu);

    void add_symlink(const std::string& link, const std::string& dev);
    template<typename T>
    std::shared_ptr<T> new_object();
    std::shared_ptr<KernelObject> add_object(std::shared_ptr<KernelObject> obj);
    void remove_object(std::shared_ptr<KernelObject> obj);
    int dec_ref(std::shared_ptr<KernelObject> obj);
    uint64_t get_handle(std::shared_ptr<KernelObject> obj);
    uint64_t new_id();
    std::shared_ptr<KernelObject> get_object_from_addr(uint64_t addr);
    std::shared_ptr<KernelObject> get_object_from_id(uint64_t id);
    std::shared_ptr<KernelObject> get_object_from_name(const std::string& name, bool check_symlinks = true);
    std::shared_ptr<KernelObject> get_object_from_handle(uint64_t handle);
};

#endif // OBJMAN_H
