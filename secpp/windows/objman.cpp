// objman.cpp  Kernel object manager implementation
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
#include "../helper.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "../winenv/arch.h"
#include "../winenv/deffs/nt/ddk.h"
#include "../winenv/deffs/nt/ntoskrnl.h"
#include "../binemu.h"      // BinaryEmulator (get_arch, mem_read, mem_write, )
#include "../windows/winemu.h" // WindowsEmulator (get_thread_context)
#include "../struct.h"      // EmuStruct
#include "../windows/loaders.h"  // speakeasy::LoadedImage
#include "../profiler.h"    // Run (indirectly)

using namespace speakeasy;
using speakeasy::deffs::nt::IRP_MJ_MAXIMUM_FUNCTION;

constexpr int kPtrSize = sizeof(void*);

//  Helper: get BinaryEmulator / WindowsEmulator from void* 

static inline BinaryEmulator* BE(void* raw) {
    return static_cast<BinaryEmulator*>(raw);
}

static inline WindowsEmulator* WE(void* raw) {
    return static_cast<WindowsEmulator*>(raw);
}

// 
// Console
// 

int Console::curr_handle_ = 0x340;

Console::Console() : handle_(get_handle()), window_(0) {}

int Console::get_handle() {
    int tmp = Console::curr_handle_;
    Console::curr_handle_ += 4;
    return tmp;
}

void Console::set_window(int window) {
    this->window_ = window;
}

int Console::get_window() {
    return this->window_;
}

// 
// SEH
// 

SEH::ScopeRecord::ScopeRecord(void* rec)
    : record(rec), filter_called(false), handler_called(false) {}

SEH::Frame::Frame(void* entry, void* scope_table, std::vector<void*> records)
    : entry(entry), scope_table(scope_table), searched(false) {
    for (void* rec : records) {
        scope_records.emplace_back(rec);
    }
}

SEH::SEH()
    : context_(nullptr), context_address_(0), record_(nullptr),
      last_func_(nullptr), last_exception_code_(0),
      exception_ptrs_(0), handler_ret_val_(nullptr) {}

void SEH::set_context(void* context, int address) {
    this->context_ = context;
    this->context_address_ = address;
}

void* SEH::get_context() {
    return this->context_;
}

void SEH::set_last_func(void* func) {
    this->last_func_ = func;
}

void SEH::set_record(void* record, int address) {
    (void)address;
    this->record_ = record;
}

void SEH::set_current_frame(Frame frame) {
    // Replace the frames list with just this frame (or push it).
    // Python code does not have an explicit set_current_frame, but
    // the method exists in the C++ API  push it onto the frame stack.
    this->frames_.push_back(frame);
}

std::vector<SEH::Frame> SEH::get_frames() {
    return this->frames_;
}

void SEH::clear_frames() {
    this->frames_.clear();
}

void SEH::add_frame(void* entry, void* scope_table, std::vector<void*> records) {
    Frame frame(entry, scope_table, records);
    this->frames_.push_back(frame);
}

// 
// KernelObject
// 

int KernelObject::curr_handle = 0x220;
int KernelObject::curr_id = 0x400;

KernelObject::KernelObject(void* emu)
    : emu_(emu), address_(0), object_(nullptr),
      ref_cnt(0), arch_(0), id(0) {
    if (emu) {
        arch_ = BE(emu)->get_arch();
    }
    this->id = KernelObject::curr_id;
    KernelObject::curr_id += 4;
}

int KernelObject::sizeof_obj(void* obj) {
    if (obj) {
        auto* es = static_cast<EmuStruct*>(obj);
        return static_cast<int>(es->sizeof_obj());
    }
    if (object_) {
        auto* es = static_cast<EmuStruct*>(object_);
        return static_cast<int>(es->sizeof_obj());
    }
    return 0;
}

void* KernelObject::get_bytes(void* obj) {
    if (obj) {
        auto* es = static_cast<EmuStruct*>(obj);
        auto bytes = es->get_bytes();
        // Return a copy; caller must know the size.
        // This is a simplification  when typed, the Python version
        // returns the struct's byte representation directly.
        auto* buf = new std::vector<uint8_t>(std::move(bytes));
        return buf;
    }
    if (object_) {
        auto* es = static_cast<EmuStruct*>(object_);
        auto bytes = es->get_bytes();
        auto* buf = new std::vector<uint8_t>(std::move(bytes));
        return buf;
    }
    return nullptr;
}

KernelObject KernelObject::read_back() {
    // Python: data = emu.mem_read(address, sizeof()); object.cast(data)
    if (emu_ && address_ && object_) {
        size_t sz = sizeof_obj();
        if (sz > 0) {
            auto data = BE(emu_)->mem_read(static_cast<uint64_t>(address_), sz);
            auto* es = static_cast<EmuStruct*>(object_);
            es->from_bytes(data);
        }
    }
    return *this;
}

void KernelObject::write_back() {
    // Python: data = get_bytes(); if data and address: emu.mem_write(address, data)
    if (!object_ || !address_) return;
    auto* es = static_cast<EmuStruct*>(object_);
    auto data = es->get_bytes();
    if (!data.empty()) {
        BE(emu_)->mem_write(static_cast<uint64_t>(address_), data);
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
    if (object_) {
        auto* es = static_cast<EmuStruct*>(object_);
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

// 
// Driver
// 

std::vector<void*> Driver::ldr_entries;

Driver::Driver(void* emu)
    : KernelObject(emu),
      pe_(nullptr), on_unload_(nullptr), unload_called_(false),
      reg_path_ptr(0) {
    // Python: self.object = self.nt_types.DRIVER_OBJECT(emu.get_ptr_size())
    // For now we create a generic EmuStruct placeholder.
    // When ntoskrnl::DRIVER_OBJECT is ported, replace with:
    //   object = new ntoskrnl::DRIVER_OBJECT(BE(emu)->get_ptr_size());
    object_ = new EmuStruct();

    // Python: mj_funcs = [None] * (ddk.IRP_MJ_MAXIMUM_FUNCTION + 1)
    mj_funcs_.resize(IRP_MJ_MAXIMUM_FUNCTION + 1, nullptr);
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
    size_t us_overhead = (BE(emu_)->get_ptr_size() == 8) ? 16 : 12;  // rough UNICODE_STRING size
    size_t total_size = us_overhead + buf_size;

    uint64_t addr = BE(emu_)->mem_map(total_size, 0, 4 /* RW */,
                                      "emu.object." + name + ".reg_path");

    // Write the buffer right after the header
    uint64_t buf_addr = addr + us_overhead;
    std::vector<uint8_t> raw_buf;
    for (char16_t c : u16) {
        raw_buf.push_back(static_cast<uint8_t>(c & 0xFF));
        raw_buf.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    BE(emu_)->mem_write(buf_addr, raw_buf);

    this->reg_path_ptr = static_cast<int>(addr);
}

std::string Driver::get_basename() {
    // Python: return self.basename.lower()
    return speakeasy::to_lower(this->basename);
}

void* Driver::init_driver_section() {
    // Python: create LdrDataTableEntry, link it into ldr_entries list.
    // Simulate LDR_DATA_TABLE_ENTRY by allocating memory and writing basic fields.
    int ptr_sz = (arch_ == speakeasy::arch::ARCH_AMD64) ? 8 : 4;

    // LDR_DATA_TABLE_ENTRY field offsets (EmuStruct sequential layout, no padding):
    //   InLoadOrderLinks (LIST_ENTRY = 2*ptr_sz) ........ offset 0
    //   InMemoryOrderLinks (LIST_ENTRY = 2*ptr_sz) ..... offset 2*ptr_sz
    //   InInitializationOrderLinks (LIST_ENTRY = 2*ptr_sz)  offset 4*ptr_sz
    //   DllBase (ptr_sz) ............................... offset 6*ptr_sz
    //   EntryPoint (ptr_sz) ........................... offset 7*ptr_sz
    //   SizeOfImage (uint32, 4) ....................... offset 8*ptr_sz
    //   FullDllName (UNICODE_STRING = 2+2+ptr_sz) ..... offset 8*ptr_sz + 4
    //   BaseDllName (UNICODE_STRING = 2+2+ptr_sz) ..... after FullDllName
    //   Flags (uint32, 4) + LoadCount (uint16, 2) ..... after BaseDllName
    size_t ldte_struct_size = 8 * ptr_sz + 4;   // up to SizeOfImage
    ldte_struct_size += (2 + 2 + ptr_sz);        // FullDllName
    ldte_struct_size += (2 + 2 + ptr_sz);        // BaseDllName
    ldte_struct_size += 4 + 2;                   // Flags + LoadCount

    // Build tag
    std::string mem_tag = "emu.object." + name_ + ".DriverSection";
    uint64_t addr = BE(emu_)->mem_map(ldte_struct_size, 0, 4, mem_tag);

    // Get PE info if available
    uint64_t dll_base = 0;
    uint64_t entry_point = 0;
    uint32_t image_size = 0;

    if (pe_) {
        auto img = pe_;
        dll_base = img->base;
        entry_point = img->base + img->ep;
        image_size = static_cast<uint32_t>(img->image_size);
    }

    // Build byte buffer for LDR_DATA_TABLE_ENTRY
    std::vector<uint8_t> buf(ldte_struct_size, 0);

    // Write DllBase at offset 6*ptr_sz
    size_t dllbase_off = 6 * ptr_sz;
    for (int i = 0; i < ptr_sz; ++i)
        buf[dllbase_off + i] = static_cast<uint8_t>((dll_base >> (i * 8)) & 0xFF);

    // Write EntryPoint at offset 7*ptr_sz
    size_t ep_off = 7 * ptr_sz;
    for (int i = 0; i < ptr_sz; ++i)
        buf[ep_off + i] = static_cast<uint8_t>((entry_point >> (i * 8)) & 0xFF);

    // Write SizeOfImage at offset 8*ptr_sz
    size_t si_off = 8 * ptr_sz;
    for (int i = 0; i < 4; ++i)
        buf[si_off + i] = static_cast<uint8_t>((image_size >> (i * 8)) & 0xFF);

    // Write the buffer to emulated memory
    BE(emu_)->mem_write(addr, buf);

    // Track in static ldr_entries list
    ldr_entries.push_back(reinterpret_cast<void*>(static_cast<uintptr_t>(addr)));

    return reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
}

void Driver::init_driver_object(const std::string& name, std::shared_ptr<speakeasy::RuntimeModule> pe, bool is_decoy) {
    // Python: initialize DRIVER_OBJECT fields
    this->pe_ = pe;

    // Python: drvobj.Type = 4; drvobj.Size = sizeof(); drvobj.DeviceObject = 0; drvobj.Flags = 2
    // These fields live on the EmuStruct subclass.  For now we skip setting them
    // since the underlying DRIVER_OBJECT emulated struct isn't fully ported.
    //
    // Python: if pe: drvobj.DriverStart = pe.base; ... ; drvobj.DriverInit = pe.base + pe.ep
    // Python: if is_decoy: set MajorFunction entries
    // Python: allocate memory for driver object + unicode name
    // Python: write bytes, call create_reg_path, init_driver_section

    if (!name.empty()) {
        this->name_ = name;
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

    // Python: read MajorFunction entries from DRIVER_OBJECT
    // DRIVER_OBJECT layout (EmuStruct sequential):
    //   Type(2) + Size(2) + DeviceObject(Ptr) + Flags(4) + DriverStart(Ptr) +
    //   DriverSize(4) + DriverSection(Ptr) + DriverExtension(Ptr) +
    //   DriverName(2+2+Ptr) + HardwareDatabase(Ptr) + FastIoDispatch(Ptr) +
    //   DriverInit(Ptr) + DriverStartIo(Ptr) + DriverUnload(Ptr)
    // MajorFunction offset = 16 + 10*ptr_sz
    int ptr_sz = (arch_ == speakeasy::arch::ARCH_AMD64) ? 8 : 4;
    uint64_t mf_offset = 16 + 10 * static_cast<uint64_t>(ptr_sz);

    if (emu_ && address_) {
        size_t mf_count = static_cast<size_t>(IRP_MJ_MAXIMUM_FUNCTION) + 1;
        size_t mf_size = mf_count * static_cast<size_t>(ptr_sz);
        auto data = BE(emu_)->mem_read(static_cast<uint64_t>(address_) + mf_offset, mf_size);

        mj_funcs_.resize(mf_count, nullptr);
        for (size_t i = 0; i < mf_count && i < mj_funcs_.size(); ++i) {
            uint64_t func_addr = 0;
            for (int j = 0; j < ptr_sz; ++j) {
                size_t idx = i * static_cast<size_t>(ptr_sz) + static_cast<size_t>(j);
                if (idx < data.size()) {
                    func_addr |= static_cast<uint64_t>(data[idx]) << (j * 8);
                }
            }
            mj_funcs_[i] = reinterpret_cast<void*>(static_cast<uintptr_t>(func_addr));
        }

        // Read DriverUnload (right before MajorFunction)
        uint64_t unload_offset = 16 + 9 * static_cast<uint64_t>(ptr_sz);
        auto unload_data = BE(emu_)->mem_read(
            static_cast<uint64_t>(address_) + unload_offset,
            static_cast<size_t>(ptr_sz));
        uint64_t unload_addr = 0;
        for (int j = 0; j < ptr_sz && static_cast<size_t>(j) < unload_data.size(); ++j) {
            unload_addr |= static_cast<uint64_t>(unload_data[j]) << (j * 8);
        }
        on_unload_ = reinterpret_cast<void*>(static_cast<uintptr_t>(unload_addr));
    }

    return *this;
}

// 
// Device
// 

Device::Device(void* emu)
    : KernelObject(emu), file_object_(nullptr), driver_(nullptr) {
    // Python: devobj = DEVICE_OBJECT(ptr_size)
    // devobj.Type = 0x3; devobj.Size = sizeof(devobj); devobj.ReferenceCount = 1
    // self.object = devobj
    object_ = new EmuStruct();
}

void* Device::get_parent_driver() {
    return this->driver_;
}

void Device::init_device(const std::string& name, uint32_t dev_type,
                          uint32_t chars, void* drv) {
    (void)dev_type; (void)chars;
    this->name_ = name;
    this->driver_ = drv;
}

// 
// FileObject
// 

FileObject::FileObject(void* emu)
    : KernelObject(emu) {
    // Python: fileobj = FILE_OBJECT(ptr_size); fileobj.Type = 0x5; fileobj.Size = sizeof()
    // self.object = fileobj; self.address = emu.mem_map(sizeof(), tag=...)
    object_ = new EmuStruct();
}

// 
// IoStackLocation
// 

IoStackLocation::IoStackLocation(void* emu)
    : KernelObject(emu) {
    // Python: object = IO_STACK_LOCATION(ptr_size)
    // address = emu.mem_map(sizeof() * 2, tag=...)  # reserve two slots
    object_ = new EmuStruct();
}

// 
// Irp
// 

Irp::Irp(void* emu)
    : KernelObject(emu) {
    // Python: object = IRP(ptr_size); address = emu.mem_map(sizeof(), tag=...)
    object_ = new EmuStruct();

    // Create and add an IoStackLocation
    IoStackLocation ios(emu);
    ios.write_back();
    stack_locations_.push_back(ios);

    // Python: object.Tail.Overlay.CurrentStackLocation = ios.address + ios.sizeof()
    // object.Type = 0x6; object.Size = sizeof()
    // write_back()

    write_back();
}

IoStackLocation Irp::get_curr_stack_loc() {
    if (stack_locations_.empty()) {
        return IoStackLocation(nullptr);
    }
    return stack_locations_[0];
}

// 
// Thread
// 

Thread::Thread(void* emu, uint64_t stack_base, uint64_t stack_commit)
    : KernelObject(emu),
      ctx_(nullptr), modified_pc_(false), teb_(nullptr),
      suspend_count_(0), token_(emu), last_error_(0),
      stack_base_(stack_base), stack_commit_(stack_commit) {
    // Python: object = ETHREAD(ptr_size)
    // address = emu.mem_map(sizeof(), tag=...)
    // object.Data = b"\xff" * sizeof()
    // ctx = emu.get_thread_context()
    // write_back()
    object_ = new speakeasy::deffs::nt::ETHREAD();
    address_ = static_cast<WindowsEmulator*>(emu_)->mem_map(sizeof_obj());

    // Allocate thread context
    if (emu_) {
        ctx_ = static_cast<WindowsEmulator*>(emu_)->get_thread_context();
    }

    write_back();
}

void Thread::queue_message(void* msg) {
    this->message_queue_.push_back(msg);
}

SEH& Thread::get_seh() {
    return this->seh_;
}

void* Thread::get_context() {
    if (this->ctx_) {
        return this->ctx_;
    }
    if (emu_) {
        return static_cast<WindowsEmulator*>(emu_)->get_thread_context();
    }
    return nullptr;
}

void Thread::set_context(void* ctx) {
    if (this->ctx_ && emu_ && ctx) {
        int arch = BE(emu_)->get_arch();
        uint64_t old_ctx_addr = reinterpret_cast<uint64_t>(this->ctx_);
        uint64_t new_ctx_addr = reinterpret_cast<uint64_t>(ctx);
        if (arch == speakeasy::arch::ARCH_AMD64) {
            // CONTEXT is 1232 bytes
            // RIP is at offset 0x140 (8 bytes)
            auto old_buf = BE(emu_)->mem_read(old_ctx_addr + 0x140, 8);
            auto new_buf = BE(emu_)->mem_read(new_ctx_addr + 0x140, 8);
            if (old_buf.size() == 8 && new_buf.size() == 8) {
                uint64_t old_rip = speakeasy::read_le(old_buf, 0, 8);
                uint64_t new_rip = speakeasy::read_le(new_buf, 0, 8);
                if (old_rip != new_rip) {
                    this->modified_pc_ = true;
                }
            }
        } else if (arch == speakeasy::arch::ARCH_X86) {
            // CONTEXT is 716 bytes
            // EIP is at offset 0x98 (4 bytes)
            auto old_buf = BE(emu_)->mem_read(old_ctx_addr + 0x98, 4);
            auto new_buf = BE(emu_)->mem_read(new_ctx_addr + 0x98, 4);
            if (old_buf.size() == 4 && new_buf.size() == 4) {
                uint32_t old_eip = static_cast<uint32_t>(speakeasy::read_le(old_buf, 0, 4));
                uint32_t new_eip = static_cast<uint32_t>(speakeasy::read_le(new_buf, 0, 4));
                if (old_eip != new_eip) {
                    this->modified_pc_ = true;
                }
            }
        }
    }
    this->ctx_ = ctx;
}

void Thread::init_teb(uint64_t teb_addr, uint64_t peb_addr) {
    if (!this->teb_) {
        this->teb_ = std::make_shared<TEB>(emu_, teb_addr);
    }

    auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<kPtrSize>* >(this->teb_->get_object());
    teb_struct->NtTib.StackBase = this->stack_base_;
    teb_struct->NtTib.Self = teb_addr;
    teb_struct->NtTib.StackLimit = this->stack_commit_;
    teb_struct->ProcessEnvironmentBlock = peb_addr;
    this->teb_->write_back();
}

std::shared_ptr<TEB> Thread::get_teb() {
    if (this->teb_) {
        this->teb_->read_back();
    }
    return this->teb_;
}

void Thread::set_last_error(int code) {
    this->last_error_ = code;
}

int Thread::get_last_error() {
    return this->last_error_;
}

std::vector<void*> Thread::get_tls() {
    return this->tls_;
}

void Thread::set_tls(const std::vector<void*>& tls) {
    this->tls_ = tls;
}

std::vector<void*> Thread::get_fls() {
    return this->fls_;
}

void Thread::set_fls(const std::vector<void*>& fls) {
    this->fls_ = fls;
}

Token* Thread::get_token() {
    return &this->token_;
}

void Thread::init_tls(int tls_dir, const std::string& modname) {
    if (!emu_ || !this->teb_) return;

    int ptrsz = BE(emu_)->get_ptr_size();
    uint64_t tls_dirp = BE(emu_)->mem_map(ptrsz, 0, 4, "emu.tls." + modname);

    std::vector<uint8_t> tls_data(ptrsz, 0);
    for (int i = 0; i < ptrsz; ++i) {
        tls_data[i] = static_cast<uint8_t>((static_cast<unsigned int>(tls_dir) >> (i * 8)) & 0xFF);
    }
    BE(emu_)->mem_write(tls_dirp, tls_data);

    auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<kPtrSize>* >(this->teb_->get_object());
    teb_struct->ThreadLocalStoragePointer = tls_dirp;
    this->teb_->write_back();
}

// 
// Token
// 

Token::Token(void* emu)
    : KernelObject(emu) {
    object_ = new EmuStruct();
}

// 
// PEB
// 
PEB::PEB(void* emu, uint64_t addr)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::PEB<kPtrSize>();
    if (!addr) {
        address_ = static_cast<int>(
            BE(emu)->mem_map(sizeof_obj(), 0, 4, get_mem_tag())
        );
    } else {
        address_ = static_cast<int>(addr);
    }
}

// 
// TEB
// 
TEB::TEB(void* emu, uint64_t addr)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::TEB<kPtrSize>();
    if (addr) {
        address_ = static_cast<int>(addr);
    } else {
        address_ = static_cast<int>(
            BE(emu)->mem_map(sizeof_obj(), 0, 4, get_mem_tag())
        );
    }
}

// 
// PebLdrData
// 
PebLdrData::PebLdrData(void* emu)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::PEB_LDR_DATA<kPtrSize>();
    address_ = 0;
}

// 
// LdrDataTableEntry
// 
LdrDataTableEntry::LdrDataTableEntry(void* emu, const std::string& dllname, const std::string& tag)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<kPtrSize>();

    int size = static_cast<int>(sizeof_obj());
    size += static_cast<int>((dllname.length() + 1) * 2);

    std::string tag_str = tag.empty() ? get_mem_tag() : tag;
    address_ = static_cast<int>(
        BE(emu)->mem_map(size, 0, 4, tag_str)
    );
}

// 
// RTL_USER_PROCESS_PARAMETERS
// 
RTL_USER_PROCESS_PARAMETERS::RTL_USER_PROCESS_PARAMETERS(void* emu, Process* proc)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::RTL_USER_PROCESS_PARAMETERS<kPtrSize>();

    std::string proc_path = proc->path + '\0';
    std::string proc_cmdline = proc->cmdline + '\0';

    std::string cur_dir = "";
    size_t idx = proc->path.rfind('\\');
    if (idx != std::string::npos) {
        cur_dir = proc->path.substr(0, idx + 1);
    }
    if (cur_dir.empty() || cur_dir.back() != '\\') {
        cur_dir += '\\';
    }
    cur_dir += '\0';

    std::string desktop_name = "WinSta0\\Default";
    desktop_name += '\0';

    std::vector<uint8_t> path_utf16((proc_path.length()) * 2, 0);
    speakeasy::write_string(path_utf16, 0, proc_path.substr(0, proc_path.length() - 1), true);

    std::vector<uint8_t> cmd_utf16((proc_cmdline.length()) * 2, 0);
    speakeasy::write_string(cmd_utf16, 0, proc_cmdline.substr(0, proc_cmdline.length() - 1), true);

    std::vector<uint8_t> dir_utf16((cur_dir.length()) * 2, 0);
    speakeasy::write_string(dir_utf16, 0, cur_dir.substr(0, cur_dir.length() - 1), true);

    std::vector<uint8_t> desk_utf16((desktop_name.length()) * 2, 0);
    speakeasy::write_string(desk_utf16, 0, desktop_name.substr(0, desktop_name.length() - 1), true);

    int string_data_size = static_cast<int>(path_utf16.size() + cmd_utf16.size() + dir_utf16.size() + desk_utf16.size());
    int size = static_cast<int>(sizeof_obj()) + string_data_size;

    address_ = static_cast<int>(
        BE(emu)->mem_map(size, 0, 4, proc->get_mem_tag() + ".ProcessParameters")
    );

    uint64_t offset = static_cast<uint64_t>(address_) + sizeof_obj();
    BE(emu)->mem_write(offset, path_utf16);
    uint64_t path_addr = offset;
    offset += path_utf16.size();

    BE(emu)->mem_write(offset, cmd_utf16);
    uint64_t cmdline_addr = offset;
    offset += cmd_utf16.size();

    BE(emu)->mem_write(offset, dir_utf16);
    uint64_t cur_dir_addr = offset;
    offset += dir_utf16.size();

    BE(emu)->mem_write(offset, desk_utf16);
    uint64_t desktop_addr = offset;

    auto* param = static_cast<speakeasy::deffs::nt::RTL_USER_PROCESS_PARAMETERS<kPtrSize>* >(object_);
    param->MaximumLength = size;
    param->Length = size;
    param->Flags = 1;

    param->StandardInput = proc->stdin_handle;
    param->StandardOutput = proc->stdout_handle;
    param->StandardError = proc->stderr_handle;

    param->CurrentDirectory.DosPath.Length = static_cast<uint16_t>(dir_utf16.size() - 2);
    param->CurrentDirectory.DosPath.MaximumLength = static_cast<uint16_t>(dir_utf16.size());
    param->CurrentDirectory.DosPath.Buffer = cur_dir_addr;

    param->ImagePathName.Length = static_cast<uint16_t>(path_utf16.size() - 2);
    param->ImagePathName.MaximumLength = static_cast<uint16_t>(path_utf16.size());
    param->ImagePathName.Buffer = path_addr;

    param->CommandLine.Length = static_cast<uint16_t>(cmd_utf16.size() - 2);
    param->CommandLine.MaximumLength = static_cast<uint16_t>(cmd_utf16.size());
    param->CommandLine.Buffer = cmdline_addr;

    param->DesktopInfo.Length = static_cast<uint16_t>(desk_utf16.size() - 2);
    param->DesktopInfo.MaximumLength = static_cast<uint16_t>(desk_utf16.size());
    param->DesktopInfo.Buffer = desktop_addr;

    write_back();
}

// 
// IDT
// 
IDT::IDT(void* emu)
    : KernelObject(emu) {
    int ptr_sz = emu ? BE(emu)->get_ptr_size() : 4;
    object_ = new speakeasy::deffs::nt::IDT<kPtrSize>();
    address_ = static_cast<int>(
        BE(emu)->mem_map(sizeof_obj(), 0, 4, get_mem_tag())
    );
}

void IDT::init_descriptors() {
    int ptr_sz = BE(emu_)->get_ptr_size();
    auto km = WE(emu_)->get_mod_by_name("ntoskrnl");
    uint64_t kbase = km ? km->base : 0x80000000;

    uint64_t descs;
    if (ptr_sz == 4) {
        speakeasy::deffs::nt::DESCRIPTOR_TABLE<4> tbl;
        descs = BE(emu_)->mem_map(tbl.sizeof_obj(), 0, 4, get_mem_tag() + ".idt_entries");
        auto* idt_obj = static_cast<speakeasy::deffs::nt::IDT<4>*>(object_);
        idt_obj->Limit = 0xFFF;
        idt_obj->Descriptors = descs;
        for (int i = 0; i < 256; ++i) {
            tbl.Table[i].OffsetLow = 0 + (4 * i);
            tbl.Table[i].Base = static_cast<uint32_t>(kbase);
        }
        BE(emu_)->mem_write(descs, tbl.get_bytes());
    } else {
        speakeasy::deffs::nt::DESCRIPTOR_TABLE<8> tbl;
        descs = BE(emu_)->mem_map(tbl.sizeof_obj(), 0, 4, get_mem_tag() + ".idt_entries");
        auto* idt_obj = static_cast<speakeasy::deffs::nt::IDT<8>*>(object_);
        idt_obj->Limit = 0xFFF;
        idt_obj->Descriptors = descs;
        for (int i = 0; i < 256; ++i) {
            tbl.Table[i].OffsetLow = kbase & 0xFFFF;
            tbl.Table[i].OffsetMiddle = (kbase & 0xFFFF0000) >> 16;
            tbl.Table[i].OffsetHigh = (kbase & 0xFFFFFFFF00000000) >> 32;
        }
        BE(emu_)->mem_write(descs, tbl.get_bytes());
    }
    write_back();
}

// 
// Event
// 
Event::Event(void* emu)
    : KernelObject(emu) {
    object_ = new speakeasy::deffs::nt::KEVENT();
    address_ = static_cast<int>(
        BE(emu)->mem_map(sizeof_obj(), 0, 4, get_mem_tag())
    );
}

// 
// Mutant
// 
Mutant::Mutant(void* emu)
    : KernelObject(emu) {
    object_ = new speakeasy::deffs::nt::MUTANT();
    address_ = static_cast<int>(
        BE(emu)->mem_map(sizeof_obj(), 0, 4, get_mem_tag())
    );
}

// 
// Process
// 

std::vector<void*> Process::ldr_entries;

Process::Process(void* emu, std::shared_ptr<speakeasy::RuntimeModule> pe,
    const std::vector<std::shared_ptr<speakeasy::RuntimeModule>> user_modules,
                 const std::string& name, const std::string& path,
                 const std::string& cmdline, uint64_t basel, int session)
    : KernelObject(emu),
      modules(user_modules), cmdline(cmdline),
      session(session), token(emu),
      pe(pe), pe_data(nullptr),
      stdin_handle(0), stdout_handle(0), stderr_handle(0),
      peb(nullptr), peb_ldr_data(nullptr), is_peb_active(false),
      path(path), base(basel) {

    object_ = new EmuStruct();

    if (emu_) {
        int sz = sizeof_obj();
        if (sz > 0) {
            address_ = static_cast<int>(
                BE(emu_)->mem_map(sz, 0xE0000000, 1, get_mem_tag())
            );
        }

        int arch = BE(emu_)->get_arch();
        uint64_t list_entry_addr = 0;
        if (arch == speakeasy::arch::ARCH_X86) {
            list_entry_addr = static_cast<uint64_t>(address_) + 0x88;
        } else if (arch == speakeasy::arch::ARCH_AMD64) {
            list_entry_addr = static_cast<uint64_t>(address_) + 0x188;
        }
        if (list_entry_addr) {
            std::vector<uint8_t> le_data;
            int ptr_sz = BE(emu_)->get_ptr_size();
            for (int i = 0; i < ptr_sz; ++i) {
                le_data.push_back(static_cast<uint8_t>((list_entry_addr >> (i * 8)) & 0xFF));
            }
            BE(emu_)->mem_write(list_entry_addr, le_data);
            BE(emu_)->mem_write(list_entry_addr + ptr_sz, le_data);
        }

        stdin_handle = 0xF000 + 1;
        stdout_handle = 0xF000 + 2;
        stderr_handle = 0xF000 + 3;

        peb = std::make_shared<PEB>(emu_);
        peb_ldr_data = std::make_shared<PebLdrData>(emu_);
        set_process_parameters(emu_);
    }
}

std::shared_ptr<PEB> Process::get_peb() {
    return this->peb;
}

void Process::set_peb_ldr_address(uint64_t addr) {
    if (!peb || !peb_ldr_data) return;
    auto* peb_struct = static_cast<speakeasy::deffs::nt::PEB<kPtrSize>* >(peb->get_object());
    peb_struct->Ldr = addr;
    peb->write_back();

    peb_ldr_data->set_address(addr);
}

void Process::set_process_parameters(void* emu) {
    if (!emu || !this->peb) return;
    auto params = std::make_shared<RTL_USER_PROCESS_PARAMETERS>(emu, this);
    auto* peb_struct = static_cast<speakeasy::deffs::nt::PEB<kPtrSize>* >(peb->get_object());
    peb_struct->ProcessParameters = params->get_address();
    peb->write_back();
}

std::shared_ptr<PebLdrData> Process::get_peb_ldr() {
    return this->peb_ldr_data;
}

void Process::alloc_console() {
    this->console = Console();
}

std::string Process::get_desktop_name() {
    return "WinSta0\\Default";
}

Token* Process::get_token() {
    return &this->token;
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

std::shared_ptr<speakeasy::RuntimeModule> Process::get_module() {
    return this->pe;
}

void* Process::get_ep() {
    if (pe) {
        auto img = pe;
        return reinterpret_cast<void*>(static_cast<uintptr_t>(img->base + img->ep));
    }
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

void Process::set_user_modules(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& mods) {
    this->modules = mods;
}

void Process::new_thread() {
    auto t = std::make_shared<Thread>(emu_);
    threads.push_back(t);
}

void Process::add_module_to_peb(std::shared_ptr<speakeasy::RuntimeModule> module) {
    if (!emu_ || !peb_ldr_data || !peb) return;

    auto* be = BE(emu_);
    int ptr_sz = be->get_ptr_size();

    speakeasy::deffs::nt::LIST_ENTRY<kPtrSize> list_type;
    size_t list_sz = list_type.sizeof_obj();

    auto ldte = std::make_shared<LdrDataTableEntry>(emu_, module->emu_path);
    auto* ldte_struct = static_cast<speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<kPtrSize>* >(ldte->get_object());

    std::shared_ptr<LdrDataTableEntry> prev;
    if (ldr_entries_list.empty()) {
        prev = ldte;
    } else {
        prev = ldr_entries_list.back();
    }

    ldr_entries_list.push_back(ldte);
    auto first = ldr_entries_list.front();
    auto* first_struct = static_cast<speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<kPtrSize>* >(first->get_object());

    ldte_struct->InLoadOrderLinks.Flink = first->get_address();
    ldte_struct->InMemoryOrderLinks.Flink = first->get_address() + list_sz;
    ldte_struct->InInitializationOrderLinks.Flink = first->get_address() + list_sz * 2;

    ldte_struct->DllBase = module->base;
    ldte_struct->EntryPoint = module->base + module->ep;
    ldte_struct->SizeOfImage = module->image_size;

    std::vector<uint8_t> dllname_bytes;
    std::string emu_path_with_null = module->emu_path + '\0';
    for (size_t i = 0; i < emu_path_with_null.size(); ++i) {
        dllname_bytes.push_back(static_cast<uint8_t>(emu_path_with_null[i] & 0xFF));
        dllname_bytes.push_back(static_cast<uint8_t>((emu_path_with_null[i] >> 8) & 0xFF));
    }

    uint64_t name_addr = ldte->get_address() + ldte->sizeof_obj();
    be->mem_write(name_addr, dllname_bytes);

    ldte_struct->FullDllName.Length = static_cast<uint16_t>(dllname_bytes.size() - 2);
    ldte_struct->FullDllName.MaximumLength = static_cast<uint16_t>(dllname_bytes.size());
    ldte_struct->FullDllName.Buffer = name_addr;

    std::string base_name = module->emu_path;
    size_t last_slash = base_name.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        base_name = base_name.substr(last_slash + 1);
    }
    std::vector<uint8_t> basename_bytes;
    std::string basename_with_null = base_name + '\0';
    for (size_t i = 0; i < basename_with_null.size(); ++i) {
        basename_bytes.push_back(static_cast<uint8_t>(basename_with_null[i] & 0xFF));
        basename_bytes.push_back(static_cast<uint8_t>((basename_with_null[i] >> 8) & 0xFF));
    }

    ldte_struct->BaseDllName.Length = static_cast<uint16_t>(basename_bytes.size() - 2);
    ldte_struct->BaseDllName.MaximumLength = static_cast<uint16_t>(basename_bytes.size());
    ldte_struct->BaseDllName.Buffer = name_addr + (ldte_struct->FullDllName.MaximumLength - basename_bytes.size());

    ldte->write_back();

    auto* prev_struct = static_cast<speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<kPtrSize>* >(prev->get_object());
    prev_struct->InLoadOrderLinks.Flink = ldte->get_address();
    prev_struct->InMemoryOrderLinks.Flink = ldte->get_address() + list_sz;

    if (first == ldte) {
        prev_struct->InInitializationOrderLinks.Flink = 0;
    } else {
        uint64_t imol = prev_struct->InMemoryOrderLinks.Flink;
        prev_struct->InInitializationOrderLinks.Flink = imol + list_sz;
    }

    ldte_struct->InLoadOrderLinks.Blink = prev->get_address();
    ldte_struct->InMemoryOrderLinks.Blink = prev->get_address() + list_sz;

    if (first == ldte) {
        ldte_struct->InInitializationOrderLinks.Blink = 0;
    } else {
        uint64_t imol = ldte_struct->InMemoryOrderLinks.Blink;
        ldte_struct->InInitializationOrderLinks.Blink = imol + list_sz;
    }

    prev->write_back();
    ldte->write_back();

    first_struct->InLoadOrderLinks.Blink = ldte->get_address();
    first_struct->InMemoryOrderLinks.Blink = ldte->get_address() + list_sz;
    if (first != ldte) {
        first_struct->InInitializationOrderLinks.Blink = ldte->get_address() + list_sz * 2;
    }
    first->write_back();

    auto* pld_struct = static_cast<speakeasy::deffs::nt::PEB_LDR_DATA<kPtrSize>* >(peb_ldr_data->get_object());
    pld_struct->InLoadOrderModuleList.Flink = first->get_address();
    pld_struct->InMemoryOrderModuleList.Flink = pld_struct->InLoadOrderModuleList.Flink + list_sz;

    uint64_t head = pld_struct->InMemoryOrderModuleList.Flink;
    std::vector<uint8_t> le_data = be->mem_read(head, list_sz);
    speakeasy::deffs::nt::LIST_ENTRY<kPtrSize> le;
    le.from_bytes(le_data);

    pld_struct->InInitializationOrderModuleList.Flink = le.Flink + list_sz;
    pld_struct->InLoadOrderModuleList.Blink = ldte->get_address();
    pld_struct->InMemoryOrderModuleList.Blink = ldte->get_address() + list_sz;
    pld_struct->InInitializationOrderModuleList.Blink = ldte->get_address() + list_sz * 2;

    peb_ldr_data->write_back();

    auto* peb_struct = static_cast<speakeasy::deffs::nt::PEB<kPtrSize>* >(peb->get_object());
    peb_struct->Ldr = peb_ldr_data->get_address();
    peb->write_back();
}

void Process::init_peb(std::vector<std::shared_ptr<speakeasy::RuntimeModule>>& modules) {
    for (auto& mod : modules) {
        add_module_to_peb(mod);
    }
}

// 
// ObjectManager
// 

ObjectManager::ObjectManager(void* emu) : emu_(emu) {}

void ObjectManager::add_symlink(const std::string& link, const std::string& dev) {
    this->symlinks_.push_back(std::make_pair(link, dev));
}

template<typename T>
std::shared_ptr<T> ObjectManager::new_object() {
    // Python: T obj = T(emu); obj.set_id(new_id()); return add_object(obj)
    std::shared_ptr<T> obj = std::make_shared<T>(emu_);
    obj->set_id(new_id());
    add_object(obj);
    return obj;
}
// Explicit instantiation for common types
template std::shared_ptr<KernelObject> ObjectManager::new_object<KernelObject>();
template std::shared_ptr<Event> ObjectManager::new_object<Event>();
template std::shared_ptr<Mutant> ObjectManager::new_object<Mutant>();

std::shared_ptr<KernelObject> ObjectManager::add_object(std::shared_ptr<KernelObject> obj) {
    // Python: self.objects[obj.id] = obj; return obj
    objects_[obj->get_id()] = obj;
    return obj;
}

void ObjectManager::remove_object(std::shared_ptr<KernelObject> obj) {
    // Python: del self.objects[obj.id]
    auto it = objects_.find(obj->get_id());
    if (it != objects_.end()) {
        objects_.erase(it);
    }
}

int ObjectManager::dec_ref(std::shared_ptr<KernelObject> obj) {
    if (obj->ref_cnt > 0) {
        obj->ref_cnt--;
        if (obj->ref_cnt <= 0) {
            remove_object(obj);
        }
    }
    return obj->ref_cnt;
}

uint64_t ObjectManager::get_handle(std::shared_ptr<KernelObject> obj) {
    uint64_t tmp = KernelObject::curr_handle;
    KernelObject::curr_handle += 4;
    obj->handles.push_back(tmp);
    return tmp;
}

uint64_t ObjectManager::new_id() {
    uint64_t tmp = KernelObject::curr_id;
    KernelObject::curr_id += 4;
    return tmp;
}

std::shared_ptr<KernelObject> ObjectManager::get_object_from_addr(uint64_t addr) {
    // Python: iterate objects, return one whose address matches
    for (auto& [id, obj] : objects_) {
        (void)id;
        if (obj->get_id() == addr) {  // fallback: match by id
            return obj;
        }
    }
    return nullptr;
}

std::shared_ptr<KernelObject> ObjectManager::get_object_from_id(uint64_t id) {
    auto it = objects_.find(id);
    if (it != objects_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<KernelObject> ObjectManager::get_object_from_name(const std::string& name, bool check_symlinks) {
    // Python: iterate objects, return one with matching name
    for (auto& [id, obj] : objects_) {
        (void)id;
        std::string obj_name = obj->get_obj_name();
        if (!obj_name.empty()) {
            // Case-insensitive comparison
            std::string lname = speakeasy::to_lower(name);
            std::string lobj_name = speakeasy::to_lower(obj_name);
            if (lobj_name == lname) {
                return obj;
            }
        }
    }
    if (check_symlinks) {
        for (auto& sl : symlinks_) {
            std::string lsl = speakeasy::to_lower(sl.first);
            std::string lname = speakeasy::to_lower(name);
            if (lsl == lname) {
                return get_object_from_name(sl.second, false);
            }
        }
    }
    return nullptr;
}

std::shared_ptr<KernelObject> ObjectManager::get_object_from_handle(uint64_t handle) {
    // Python: iterate objects, return one with matching handle in handles list
    for (auto& [id, obj] : objects_) {
        (void)id;
        for (int h : obj->handles) {
            if (h == handle) {
                return obj;
            }
        }
    }
    return nullptr;
}
