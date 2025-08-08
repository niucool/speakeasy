// objman.h
#ifndef OBJMAN_H
#define OBJMAN_H

#include <string>
#include <vector>
#include <map>
#include <memory>
// TODO: Replace Python imports with C++ equivalents
// #include <ntoskrnl.h>  // TODO: Need C++ equivalent
// #include <arch.h>      // TODO: Need C++ equivalent
// #include <ddk.h>       // TODO: Need C++ equivalent
// #include <windows.h>   // TODO: Need C++ equivalent
#include <nlohmann/json.hpp>

/**
 * Represents a console window object
 */
class Console {
private:
    static int curr_handle;
    int handle;
    int window;

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
        // TODO: Define record type
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
        // TODO: Define entry type
        void* entry;
        // TODO: Define scope_table type
        void* scope_table;
        std::vector<ScopeRecord> scope_records;
        bool searched;

        Frame(void* entry, void* scope_table, std::vector<void*> records);
    };

private:
    // TODO: Define context type
    void* context;
    int context_address;
    // TODO: Define record type
    void* record;
    std::vector<Frame> frames;
    // TODO: Define func type
    void* last_func;
    int last_exception_code;
    int exception_ptrs;
    // TODO: Define handler_ret_val type
    void* handler_ret_val;

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
};

/**
 * Base class for Kernel objects managed by the object manager
 */
class KernelObject {
protected:
    static int curr_handle;
    static int curr_id;

    // TODO: Define emu type
    void* emu;
    int address;
    std::string name;
    int object;
    int ref_cnt;
    std::vector<int> handles;
    int arch;
    int id;

    // TODO: Define nt_types and win_types
    // void* nt_types;
    // void* win_types;

public:
    KernelObject(void* emu);
    virtual ~KernelObject() = default;
    
    int sizeof_obj(void* obj = nullptr);
    // TODO: Define get_bytes return type
    void* get_bytes(void* obj = nullptr);
    KernelObject read_back();
    void write_back();
    int get_id();
    void set_id(int oid);
    std::string get_class_name();
    std::string get_mem_tag();
    int get_handle();
};

/**
 * Class that represents DRIVER_OBJECTs created by the Windows kernel
 */
class Driver : public KernelObject {
private:
    // TODO: Define pe type
    void* pe;
    std::vector<void*> devices;
    // TODO: Define mj_funcs type
    std::vector<void*> mj_funcs;
    // TODO: Define on_unload type
    void* on_unload;
    bool unload_called;
    int reg_path_ptr;
    std::string reg_path;
    std::string basename;
    
    // TODO: Define ldr_entries type
    static std::vector<void*> ldr_entries;

public:
    Driver(void* emu);
    
    void create_reg_path(const std::string& name);
    std::string get_basename();
    std::string get_reg_path();
    void* init_driver_section();
    void init_driver_object(const std::string& name = "", void* pe = nullptr, bool is_decoy = true);
    KernelObject read_back() override;
};

/**
 * Represents a DEVICE_OBJECT created by the windows kernel
 */
class Device : public KernelObject {
private:
    // TODO: Define file_object type
    void* file_object;
    // TODO: Define driver type
    void* driver;

public:
    Device(void* emu);
    void* get_parent_driver();
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
    std::vector<IoStackLocation> stack_locations;

public:
    Irp(void* emu);
    IoStackLocation get_curr_stack_loc();
};

/**
 * Represents a Windows ETHREAD object that describes an OS level thread
 */
class Thread : public KernelObject {
private:
    // TODO: Define ctx type
    void* ctx;
    bool modified_pc;
    // TODO: Define teb type
    void* teb;
    SEH seh;
    std::vector<void*> tls;
    std::vector<void*> message_queue;
    std::vector<void*> fls;
    int suspend_count;
    // TODO: Define token type
    void* token;
    int last_error;
    int stack_base;
    int stack_commit;

public:
    Thread(void* emu, int stack_base = 0, int stack_commit = 0);
    
    void queue_message(void* msg);
    SEH get_seh();
    void* get_context();
    void set_context(void* ctx);
    void init_teb(int teb_addr, int peb_addr);
    void* get_teb();
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
};

/**
 * An EPROCESS object used by the Windows kernel to represent a process
 */
class Process : public KernelObject {
private:
    // TODO: Define ldr_entries type
    static std::vector<void*> ldr_entries;
    
    // TODO: Define modules type
    std::vector<void*> modules;
    std::vector<Thread> threads;
    Console console;
    Thread curr_thread;
    std::string cmdline;
    int session;
    // TODO: Define token type
    Token token;
    // TODO: Define pe type
    void* pe;
    void* pe_data;
    int stdin_handle;
    int stdout_handle;
    int stderr_handle;
    // TODO: Define peb type
    void* peb;
    // TODO: Define peb_ldr_data type
    void* peb_ldr_data;
    bool is_peb_active;
    std::string path;
    std::string image;
    std::string title;

public:
    Process(void* emu, void* pe = nullptr, const std::vector<void*>& user_modules = {},
            const std::string& name = "", const std::string& path = "",
            const std::string& cmdline = "", int base = 0, int session = 0);
    
    void* get_peb();
    void set_peb_ldr_address(int addr);
    void set_process_parameters(void* emu);
    void* get_peb_ldr();
    void alloc_console();
    std::string get_desktop_name();
    void* get_token();
    int get_std_handle(int dev);
    std::string get_title_name();
    void* get_module();
    // TODO: Define get_ep return type
    void* get_ep();
    Console get_console();
    int get_session_id();
    int get_pid();
    std::string get_process_path();
    std::string get_command_line();
    void set_user_modules(const std::vector<void*>& mods);
    void new_thread();
    void add_module_to_peb(void* module);
    void init_peb(const std::vector<void*>& modules);
};

// TODO: Define other classes (RTL_USER_PROCESS_PARAMETERS, PEB, TEB, 
// PebLdrData, LdrDataTableEntry, IDT, Event, Mutant)

/**
 * Class that manages kernel objects during emulation
 */
class ObjectManager {
private:
    // TODO: Define emu type
    void* emu;
    std::map<int, KernelObject> objects;
    std::vector<std::pair<std::string, std::string>> symlinks;

public:
    ObjectManager(void* emu);
    
    void add_symlink(const std::string& link, const std::string& dev);
    template<typename T>
    T new_object();
    KernelObject add_object(KernelObject obj);
    void remove_object(KernelObject obj);
    int dec_ref(KernelObject obj);
    int get_handle(KernelObject obj);
    int new_id();
    KernelObject get_object_from_addr(int addr);
    KernelObject get_object_from_id(int id);
    KernelObject get_object_from_name(const std::string& name, bool check_symlinks = true);
    KernelObject get_object_from_handle(int handle);
};

#endif // OBJMAN_H