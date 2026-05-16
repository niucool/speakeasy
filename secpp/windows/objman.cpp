// objman.cpp — Kernel object manager implementation
//
// Maps to: speakeasy/windows/objman.py
//
// Provides base classes for emulated Windows kernel objects
// (Driver, Device, Thread, Process, etc.) and their manager.
//
// NOTE: Many NT structure types (DRIVER_OBJECT, DEVICE_OBJECT, ETHREAD,
// EPROCESS, etc.) are not yet fully ported as C++ classes with field
// layouts.  Where the Python code uses self.nt_types.FOO(ptr_size) and
// then accesses fields like obj.Type, obj.Size, the C++ code stores a
// void* to a serialized blob and relies on the underlying EmuStruct
// interface.  When the full type definitions land, these void* casts
// should be replaced with typed pointers.

#include "objman.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "../winenv/arch.h"
#include "../winenv/defs/nt/ddk.h"
#include "../winenv/defs/nt/ntoskrnl.h"
#include "../binemu.h"      // BinaryEmulator (get_arch, mem_read, mem_write, …)
#include "../windows/winemu.h" // WindowsEmulator (get_thread_context)
#include "../struct.h"      // EmuStruct
#include "../profiler.h"    // Run (indirectly)

using namespace speakeasy;

// ── Helper: get BinaryEmulator from void* ─────────────────────

static inline BinaryEmulator* BE(void* raw) {
    return static_cast<BinaryEmulator*>(raw);
}

// ═══════════════════════════════════════════════════════════════
// Console
// ═══════════════════════════════════════════════════════════════

int Console::curr_handle = 0x340;

Console::Console() : handle(get_handle()), window(0) {}

int Console::get_handle() {
    int tmp = Console::curr_handle;
    Console::curr_handle += 4;
    return tmp;
}

void Console::set_window(int window) {
    this->window = window;
}

int Console::get_window() {
    return this->window;
}

// ═══════════════════════════════════════════════════════════════
// SEH
// ═══════════════════════════════════════════════════════════════

SEH::ScopeRecord::ScopeRecord(void* rec)
    : record(rec), filter_called(false), handler_called(false) {}

SEH::Frame::Frame(void* entry, void* scope_table, std::vector<void*> records)
    : entry(entry), scope_table(scope_table), searched(false) {
    for (void* rec : records) {
        scope_records.emplace_back(rec);
    }
}

SEH::SEH()
    : context(nullptr), context_address(0), record(nullptr),
      last_func(nullptr), last_exception_code(0),
      exception_ptrs(0), handler_ret_val(nullptr) {}

void SEH::set_context(void* context, int address) {
    this->context = context;
    this->context_address = address;
}

void* SEH::get_context() {
    return this->context;
}

void SEH::set_last_func(void* func) {
    this->last_func = func;
}

void SEH::set_record(void* record, int address) {
    (void)address;
    this->record = record;
}

void SEH::set_current_frame(Frame frame) {
    // Replace the frames list with just this frame (or push it).
    // Python code does not have an explicit set_current_frame, but
    // the method exists in the C++ API — push it onto the frame stack.
    this->frames.push_back(frame);
}

std::vector<SEH::Frame> SEH::get_frames() {
    return this->frames;
}

void SEH::clear_frames() {
    this->frames.clear();
}

void SEH::add_frame(void* entry, void* scope_table, std::vector<void*> records) {
    Frame frame(entry, scope_table, records);
    this->frames.push_back(frame);
}

// ═══════════════════════════════════════════════════════════════
// KernelObject
// ═══════════════════════════════════════════════════════════════

int KernelObject::curr_handle = 0x220;
int KernelObject::curr_id = 0x400;

KernelObject::KernelObject(void* emu)
    : emu(emu), address(0), object(nullptr),
      ref_cnt(0), arch(0), id(0) {
    if (emu) {
        arch = BE(emu)->get_arch();
    }
    this->id = KernelObject::curr_id;
    KernelObject::curr_id += 4;
}

int KernelObject::sizeof_obj(void* obj) {
    if (obj) {
        auto* es = static_cast<EmuStruct*>(obj);
        return static_cast<int>(es->sizeof_obj());
    }
    if (object) {
        auto* es = static_cast<EmuStruct*>(object);
        return static_cast<int>(es->sizeof_obj());
    }
    return 0;
}

void* KernelObject::get_bytes(void* obj) {
    if (obj) {
        auto* es = static_cast<EmuStruct*>(obj);
        auto bytes = es->get_bytes();
        // Return a copy; caller must know the size.
        // This is a simplification — when typed, the Python version
        // returns the struct's byte representation directly.
        auto* buf = new std::vector<uint8_t>(std::move(bytes));
        return buf;
    }
    if (object) {
        auto* es = static_cast<EmuStruct*>(object);
        auto bytes = es->get_bytes();
        auto* buf = new std::vector<uint8_t>(std::move(bytes));
        return buf;
    }
    return nullptr;
}

KernelObject KernelObject::read_back() {
    // Python: data = emu.mem_read(address, sizeof()); object.cast(data)
    if (emu && address && object) {
        size_t sz = sizeof_obj();
        if (sz > 0) {
            auto data = BE(emu)->mem_read(static_cast<uint64_t>(address), sz);
            auto* es = static_cast<EmuStruct*>(object);
            es->from_bytes(data);
        }
    }
    return *this;
}

void KernelObject::write_back() {
    // Python: data = get_bytes(); if data and address: emu.mem_write(address, data)
    if (!object || !address) return;
    auto* es = static_cast<EmuStruct*>(object);
    auto data = es->get_bytes();
    if (!data.empty()) {
        BE(emu)->mem_write(static_cast<uint64_t>(address), data);
    }
}

int KernelObject::get_id() {
    return this->id;
}

void KernelObject::set_id(int oid) {
    this->id = oid;
}

std::string KernelObject::get_class_name() {
    // Python: return self.object.__class__.__name__
    // In C++ we lack reflection; use the object's mem_tag as a best-effort.
    if (object) {
        auto* es = static_cast<EmuStruct*>(object);
        return es->get_mem_tag();
    }
    return "KernelObject";
}

std::string KernelObject::get_mem_tag() {
    return "emu.struct." + get_class_name();
}

int KernelObject::get_handle() {
    int tmp = KernelObject::curr_handle;
    KernelObject::curr_handle += 4;
    this->handles.push_back(tmp);
    return tmp;
}

// ═══════════════════════════════════════════════════════════════
// Driver
// ═══════════════════════════════════════════════════════════════

std::vector<void*> Driver::ldr_entries;

Driver::Driver(void* emu)
    : KernelObject(emu),
      pe(nullptr), on_unload(nullptr), unload_called(false),
      reg_path_ptr(0) {
    // Python: self.object = self.nt_types.DRIVER_OBJECT(emu.get_ptr_size())
    // For now we create a generic EmuStruct placeholder.
    // When ntoskrnl::DRIVER_OBJECT is ported, replace with:
    //   object = new ntoskrnl::DRIVER_OBJECT(BE(emu)->get_ptr_size());
    object = new EmuStruct();

    // Python: mj_funcs = [None] * (ddk.IRP_MJ_MAXIMUM_FUNCTION + 1)
    mj_funcs.resize(IRP_MJ_MAXIMUM_FUNCTION + 1, nullptr);
}

void Driver::create_reg_path(const std::string& name) {
    // Python: build "\\Registry\\Machine\\...\\%s" name, create UNICODE_STRING,
    // allocate memory, write bytes.
    std::string reg_path_str =
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + name;
    this->reg_path = reg_path_str;

    // Build UTF-16LE buffer (with null terminator)
    std::u16string u16;
    for (char c : reg_path_str) u16.push_back(static_cast<char16_t>(static_cast<unsigned char>(c)));
    u16.push_back(0);  // null terminator
    size_t buf_size = u16.size() * 2;

    // Python: us = UNICODE_STRING(ptr_size); size = sizeof(us) + len(buf)
    // For now, allocate a simple block: UNICODE_STRING overhead + buffer
    size_t us_overhead = (BE(emu)->get_ptr_size() == 8) ? 16 : 12;  // rough UNICODE_STRING size
    size_t total_size = us_overhead + buf_size;

    uint64_t addr = BE(emu)->mem_map(total_size, 0, 4 /* RW */,
                                      "emu.object." + name + ".reg_path");

    // Write the buffer right after the header
    uint64_t buf_addr = addr + us_overhead;
    std::vector<uint8_t> raw_buf;
    for (char16_t c : u16) {
        raw_buf.push_back(static_cast<uint8_t>(c & 0xFF));
        raw_buf.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    BE(emu)->mem_write(buf_addr, raw_buf);

    this->reg_path_ptr = static_cast<int>(addr);
}

std::string Driver::get_basename() {
    // Python: return self.basename.lower()
    std::string lower = this->basename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower;
}

void* Driver::init_driver_section() {
    // Python: create LdrDataTableEntry, link it into ldr_entries list.
    // This requires the full LdrDataTableEntry type which isn't ported yet.
    // For now, allocate a placeholder and track it.
    //
    // TODO: When LdrDataTableEntry is ported, implement full linked-list logic:
    //   ldte = LdrDataTableEntry(emu, mod_name, tag=...)
    //   ldte.object.DllBase = pe.base
    //   ldte.object.EntryPoint = pe.base + ep
    //   ldte.object.SizeOfImage = pe.image_size
    //   ... (set Flink/Blink links)
    //   self.ldr_entries.append(ldte)
    //   ldte.write_back()
    //   return ldte

    // Stub: allocate a small block to represent the driver section
    size_t stub_size = 128;
    uint64_t addr = BE(emu)->mem_map(stub_size, 0, 4,
                                      "emu.object." + name + ".DriverSection");
    auto* stub = new EmuStruct();
    (void)stub;
    // We don't return a proper LdrDataTableEntry yet
    return reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
}

void Driver::init_driver_object(const std::string& name, void* pe, bool is_decoy) {
    // Python: initialize DRIVER_OBJECT fields
    this->pe = pe;

    // Python: drvobj.Type = 4; drvobj.Size = sizeof(); drvobj.DeviceObject = 0; drvobj.Flags = 2
    // These fields live on the EmuStruct subclass.  For now we skip setting them
    // since the underlying DRIVER_OBJECT emulated struct isn't fully ported.
    //
    // Python: if pe: drvobj.DriverStart = pe.base; ... ; drvobj.DriverInit = pe.base + pe.ep
    // Python: if is_decoy: set MajorFunction entries
    // Python: allocate memory for driver object + unicode name
    // Python: write bytes, call create_reg_path, init_driver_section

    if (!name.empty()) {
        this->name = name;
        this->basename = name;
        // Extract basename after last backslash
        auto pos = name.rfind('\\');
        if (pos != std::string::npos && pos + 1 < name.size()) {
            this->basename = name.substr(pos + 1);
        }
    }

    create_reg_path(this->basename);
    init_driver_section();
}

KernelObject Driver::read_back() {
    KernelObject::read_back();

    // Python: extract MajorFunction entries and DriverUnload from the DRIVER_OBJECT
    // Since the DRIVER_OBJECT struct isn't ported, this is a stub.
    // TODO: iterate mj_funcs = [self.object.MajorFunction[i] for i in range(...)]

    return *this;
}

// ═══════════════════════════════════════════════════════════════
// Device
// ═══════════════════════════════════════════════════════════════

Device::Device(void* emu)
    : KernelObject(emu), file_object(nullptr), driver(nullptr) {
    // Python: devobj = DEVICE_OBJECT(ptr_size)
    // devobj.Type = 0x3; devobj.Size = sizeof(devobj); devobj.ReferenceCount = 1
    // self.object = devobj
    object = new EmuStruct();
}

void* Device::get_parent_driver() {
    return this->driver;
}

void Device::init_device(const std::string& name, uint32_t dev_type,
                          uint32_t chars, void* drv) {
    (void)dev_type; (void)chars;
    this->name = name;
    this->driver = drv;
}

// ═══════════════════════════════════════════════════════════════
// FileObject
// ═══════════════════════════════════════════════════════════════

FileObject::FileObject(void* emu)
    : KernelObject(emu) {
    // Python: fileobj = FILE_OBJECT(ptr_size); fileobj.Type = 0x5; fileobj.Size = sizeof()
    // self.object = fileobj; self.address = emu.mem_map(sizeof(), tag=...)
    object = new EmuStruct();
}

// ═══════════════════════════════════════════════════════════════
// IoStackLocation
// ═══════════════════════════════════════════════════════════════

IoStackLocation::IoStackLocation(void* emu)
    : KernelObject(emu) {
    // Python: object = IO_STACK_LOCATION(ptr_size)
    // address = emu.mem_map(sizeof() * 2, tag=...)  # reserve two slots
    object = new EmuStruct();
}

// ═══════════════════════════════════════════════════════════════
// Irp
// ═══════════════════════════════════════════════════════════════

Irp::Irp(void* emu)
    : KernelObject(emu) {
    // Python: object = IRP(ptr_size); address = emu.mem_map(sizeof(), tag=...)
    object = new EmuStruct();

    // Create and add an IoStackLocation
    IoStackLocation ios(emu);
    ios.write_back();
    stack_locations.push_back(ios);

    // Python: object.Tail.Overlay.CurrentStackLocation = ios.address + ios.sizeof()
    // object.Type = 0x6; object.Size = sizeof()
    // write_back()

    write_back();
}

IoStackLocation Irp::get_curr_stack_loc() {
    if (stack_locations.empty()) {
        return IoStackLocation(nullptr);
    }
    return stack_locations[0];
}

// ═══════════════════════════════════════════════════════════════
// Thread
// ═══════════════════════════════════════════════════════════════

Thread::Thread(void* emu, int stack_base, int stack_commit)
    : KernelObject(emu),
      ctx(nullptr), modified_pc(false), teb(nullptr),
      suspend_count(0), token(nullptr), last_error(0),
      stack_base(stack_base), stack_commit(stack_commit) {
    // Python: object = ETHREAD(ptr_size)
    // address = emu.mem_map(sizeof(), tag=...)
    // object.Data = b"\xff" * sizeof()
    // ctx = emu.get_thread_context()
    // write_back()
    object = new EmuStruct();

    // Allocate thread context
    if (emu) {
        ctx = static_cast<WindowsEmulator*>(emu)->get_thread_context();
    }

    write_back();
}

void Thread::queue_message(void* msg) {
    this->message_queue.push_back(msg);
}

SEH Thread::get_seh() {
    return this->seh;
}

void* Thread::get_context() {
    if (this->ctx) {
        return this->ctx;
    }
    if (emu) {
        return static_cast<WindowsEmulator*>(emu)->get_thread_context();
    }
    return nullptr;
}

void Thread::set_context(void* ctx) {
    if (this->ctx && emu) {
        int arch = BE(emu)->get_arch();
        if (arch == speakeasy::arch::ARCH_AMD64) {
            // Compare Rip to detect PC modification
            // This requires a typed context structure; for now skip the comparison.
            (void)arch;
        } else if (arch == speakeasy::arch::ARCH_X86) {
            // Compare Eip
        }
    }
    this->ctx = ctx;
}

void Thread::init_teb(int teb_addr, int peb_addr) {
    // Python: if not teb: teb = TEB(emu=emu, address=teb_addr)
    // teb.object.NtTib.StackBase = stack_base
    // teb.object.NtTib.Self = teb_addr
    // teb.object.NtTib.StackLimit = stack_commit
    // teb.object.ProcessEnvironmentBlock = peb_addr
    // teb.write_back()
    //
    // TEB struct is not yet ported. For now, just store the address.
    if (!this->teb) {
        this->teb = reinterpret_cast<void*>(static_cast<uintptr_t>(teb_addr));
    }
}

void* Thread::get_teb() {
    // Python: return self.teb.read_back()
    // Without a typed TEB, just return the raw pointer.
    return this->teb;
}

void Thread::set_last_error(int code) {
    this->last_error = code;
}

int Thread::get_last_error() {
    return this->last_error;
}

std::vector<void*> Thread::get_tls() {
    return this->tls;
}

void Thread::set_tls(const std::vector<void*>& tls) {
    this->tls = tls;
}

std::vector<void*> Thread::get_fls() {
    return this->fls;
}

void Thread::set_fls(const std::vector<void*>& fls) {
    this->fls = fls;
}

void* Thread::get_token() {
    return this->token;
}

void Thread::init_tls(int tls_dir, const std::string& modname) {
    // Python: ptrsz = emu.get_ptr_size()
    // tls_dirp = emu.mem_map(ptrsz, tag=...)
    // emu.mem_write(tls_dirp, tls_dir)
    // teb.object.ThreadLocalStoragePointer = tls_dirp
    // teb.write_back()
    if (!emu) return;

    int ptrsz = BE(emu)->get_ptr_size();
    uint64_t tls_dirp = BE(emu)->mem_map(ptrsz, 0, 4, "emu.tls." + modname);

    std::vector<uint8_t> tls_data(ptrsz, 0);
    for (int i = 0; i < ptrsz; ++i) {
        tls_data[i] = static_cast<uint8_t>((static_cast<unsigned int>(tls_dir) >> (i * 8)) & 0xFF);
    }
    BE(emu)->mem_write(tls_dirp, tls_data);
}

// ═══════════════════════════════════════════════════════════════
// Token
// ═══════════════════════════════════════════════════════════════

Token::Token(void* emu)
    : KernelObject(emu) {
    // Python: no additional initialization
    object = new EmuStruct();
}

// ═══════════════════════════════════════════════════════════════
// Process
// ═══════════════════════════════════════════════════════════════

std::vector<void*> Process::ldr_entries;

Process::Process(void* emu, void* pe, const std::vector<void*>& user_modules,
                 const std::string& name, const std::string& path,
                 const std::string& cmdline, int base, int session)
    : KernelObject(emu),
      modules(user_modules), cmdline(cmdline),
      session(session), token(emu),
      pe(pe), pe_data(nullptr),
      stdin_handle(0), stdout_handle(0), stderr_handle(0),
      peb(nullptr), peb_ldr_data(nullptr), is_peb_active(false),
      path(path), base(base) {

    // Python: object = EPROCESS(ptr_size)
    // address = emu.mem_map(sizeof(), tag=..., perms=1, base=0xE0000000)
    object = new EmuStruct();

    // Allocate EPROCESS at the preferred address
    if (emu) {
        int sz = sizeof_obj();
        if (sz > 0) {
            address = static_cast<int>(
                BE(emu)->mem_map(sz, 0xE0000000, 1, get_mem_tag())
            );
        }

        // Python: write list_entry self-pointer (active process link)
        // On x86: list_entry offset 0x88; on AMD64: offset 0x188
        int arch = BE(emu)->get_arch();
        uint64_t list_entry_addr = 0;
        if (arch == speakeasy::arch::ARCH_X86) {
            list_entry_addr = static_cast<uint64_t>(address) + 0x88;
        } else if (arch == speakeasy::arch::ARCH_AMD64) {
            list_entry_addr = static_cast<uint64_t>(address) + 0x188;
        }
        if (list_entry_addr) {
            std::vector<uint8_t> le_data;
            int ptr_sz = BE(emu)->get_ptr_size();
            for (int i = 0; i < ptr_sz; ++i) {
                le_data.push_back(static_cast<uint8_t>((list_entry_addr >> (i * 8)) & 0xFF));
            }
            BE(emu)->mem_write(list_entry_addr, le_data);
            BE(emu)->mem_write(list_entry_addr + ptr_sz, le_data);
        }

        // Python: emu.add_object(self.token)
        // Token object tracking deferred to ObjectManager.

        // Python: std handles
        stdin_handle = 0xF000 + 1;
        stdout_handle = 0xF000 + 2;
        stderr_handle = 0xF000 + 3;
    }
}

void* Process::get_peb() {
    return this->peb;
}

void Process::set_peb_ldr_address(int addr) {
    // Python: set PEB.Ldr to addr
    this->peb_ldr_data = reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
}

void Process::set_process_parameters(void* emu) {
    // Python: set PEB.ProcessParameters
    // Requires PEB type to be ported. For now, stub.
    (void)emu;
}

void* Process::get_peb_ldr() {
    return this->peb_ldr_data;
}

void Process::alloc_console() {
    // Python: self.console = Console()
    this->console = Console();
}

std::string Process::get_desktop_name() {
    // Python: return "WinSta0\\Default" or similar
    return "WinSta0\\Default";
}

void* Process::get_token() {
    return reinterpret_cast<void*>(&this->token);
}

int Process::get_std_handle(int dev) {
    const int kStdInputHandle = 0xfffffff6;
    const int kStdOutputHandle = 0xfffffff5;
    const int kStdErrorHandle = 0xfffffff4;

    if (dev == kStdInputHandle) return this->stdin_handle;
    if (dev == kStdOutputHandle) return this->stdout_handle;
    if (dev == kStdErrorHandle) return this->stderr_handle;
    return 0;
}

std::string Process::get_title_name() {
    return this->title;
}

void* Process::get_module() {
    return this->pe;
}

void* Process::get_ep() {
    // Python: return pe.base + pe.ep  (entry point of the PE)
    // Without a typed PE object, return null.
    // TODO: When PE type is available, return base + entry_point
    return nullptr;
}

Console Process::get_console() {
    return this->console;
}

int Process::get_session_id() {
    return this->session;
}

int Process::get_pid() {
    return this->id;
}

std::string Process::get_process_path() {
    return this->path;
}

std::string Process::get_command_line() {
    return this->cmdline;
}

void Process::set_user_modules(const std::vector<void*>& mods) {
    this->modules = mods;
}

void Process::new_thread() {
    // Python: create a Thread, add it to threads list
    Thread t(emu);
    threads.push_back(t);
}

void Process::add_module_to_peb(void* module) {
    // Python: add module to PEB LDR linked list
    // Requires PEB / LdrDataTableEntry types.
    // For now, just track the module pointer.
    (void)module;
}

void Process::init_peb(const std::vector<void*>& modules) {
    for (void* mod : modules) {
        add_module_to_peb(mod);
    }
}

// ═══════════════════════════════════════════════════════════════
// ObjectManager
// ═══════════════════════════════════════════════════════════════

ObjectManager::ObjectManager(void* emu) : emu(emu) {}

void ObjectManager::add_symlink(const std::string& link, const std::string& dev) {
    this->symlinks.push_back(std::make_pair(link, dev));
}

template<typename T>
T ObjectManager::new_object() {
    // Python: T obj = T(emu); obj.set_id(new_id()); return add_object(obj)
    T obj(emu);
    obj.set_id(new_id());
    return add_object(obj);
}
// Explicit instantiation for common types
template KernelObject ObjectManager::new_object<KernelObject>();

KernelObject ObjectManager::add_object(KernelObject obj) {
    // Python: self.objects[obj.id] = obj; return obj
    objects[obj.get_id()] = obj;
    return obj;
}

void ObjectManager::remove_object(KernelObject obj) {
    // Python: del self.objects[obj.id]
    auto it = objects.find(obj.get_id());
    if (it != objects.end()) {
        objects.erase(it);
    }
}

int ObjectManager::dec_ref(KernelObject obj) {
    if (obj.ref_cnt > 0) {
        obj.ref_cnt--;
        if (obj.ref_cnt <= 0) {
            remove_object(obj);
        }
    }
    return obj.ref_cnt;
}

int ObjectManager::get_handle(KernelObject obj) {
    int tmp = KernelObject::curr_handle;
    KernelObject::curr_handle += 4;
    obj.handles.push_back(tmp);
    return tmp;
}

int ObjectManager::new_id() {
    int tmp = KernelObject::curr_id;
    KernelObject::curr_id += 4;
    return tmp;
}

KernelObject ObjectManager::get_object_from_addr(int addr) {
    // Python: iterate objects, return one whose address matches
    for (auto& [id, obj] : objects) {
        (void)id;
        if (obj.get_id() == addr) {  // fallback: match by id
            return obj;
        }
    }
    return KernelObject(nullptr);
}

KernelObject ObjectManager::get_object_from_id(int id) {
    auto it = objects.find(id);
    if (it != objects.end()) {
        return it->second;
    }
    return KernelObject(nullptr);
}

KernelObject ObjectManager::get_object_from_name(const std::string& name, bool check_symlinks) {
    // Python: iterate objects, return one with matching name
    (void)check_symlinks;
    for (auto& [id, obj] : objects) {
        (void)id;
        // TODO: add a getName() virtual to KernelObject for proper lookup
        // For now return empty since name isn't accessible on the base type.
    }
    return KernelObject(nullptr);
}

KernelObject ObjectManager::get_object_from_handle(int handle) {
    // Python: iterate objects, return one with matching handle in handles list
    for (auto& [id, obj] : objects) {
        (void)id;
        for (int h : obj.handles) {
            if (h == handle) {
                return obj;
            }
        }
    }
    return KernelObject(nullptr);
}
