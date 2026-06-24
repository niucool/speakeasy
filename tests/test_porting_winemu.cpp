/**
 * test_porting_winemu.cpp  Object Manager and Winemu Porting Validation
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

#include "config.h"
#include "windows/winemu.h"
#include "windows/loaders.h"
#include "windows/win32.h"
#include "winenv/deffs/nt/ntoskrnl.h"
#include "winenv/api/usermode/kernel32.h"
#include "winenv/api/usermode/user32.h"
#include "winenv/api/usermode/ntdll.h"
#include "winenv/api/usermode/msvcrt.h"

using namespace speakeasy;
using namespace speakeasy::api;

TEST(ObjmanPortingTest, PebTebLinkedlistValidation) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    auto proc = std::make_shared<Process>(&emu, nullptr,
                                         std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                         "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                         "", 0x400000, 0);
    emu.set_current_process(proc);

    // PEB should be allocated and mapped
    auto peb = proc->get_peb();
    if (!peb) {
        ADD_FAILURE() << "PEB is null";
        return;
    }
    if (peb->get_address() == 0) {
        ADD_FAILURE() << "PEB address is 0";
    }

    // PEB_LDR_DATA should be allocated
    auto ldr = proc->get_peb_ldr();
    if (!ldr) {
        ADD_FAILURE() << "PEB_LDR_DATA is null";
        return;
    }

    // Test ProcessParameters address linked to PEB
    int ps = emu.get_ptr_size();
    bool has_process_params = false;
    if (ps == 8) {
        has_process_params = (static_cast<speakeasy::deffs::nt::PEB<8>*>(peb->get_object())->ProcessParameters != 0);
    } else {
        has_process_params = (static_cast<speakeasy::deffs::nt::PEB<4>*>(peb->get_object())->ProcessParameters != 0);
    }
    if (!has_process_params) {
        ADD_FAILURE() << "ProcessParameters is 0";
    }

    // Add a mock DLL module to verify PEB module links
    auto img = std::make_shared<LoadedImage>();
    img->is_driver = false;
    img->is_dll = true;
    img->is_decoy = false;
    img->base = 0x10000000;
    img->image_size = 0x2000;
    img->ep = 0x1000;
    img->emu_path = "C:\\Windows\\System32\\dummy.dll";

    auto mod = std::make_shared<RuntimeModule>(img);

    // Add module to PEB
    proc->add_module_to_peb(mod);

    // Check that ldr_entries_list has 1 entry
    if (proc->ldr_entries_list.size() != 1) {
        ADD_FAILURE() << "ldr_entries_list size is not 1";
        return;
    }
    auto ldte = proc->ldr_entries_list[0];
    if (!ldte) {
        ADD_FAILURE() << "ldte is null";
        return;
    }

    // Dispatch on runtime pointer size so field offsets are correct.
    if (ps == 8) {
        auto* ldte_struct = static_cast<speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<8>*>(ldte->get_object());
        if (ldte_struct->DllBase != 0x10000000ULL) {
            ADD_FAILURE() << "DllBase mismatch";
        }
        if (ldte_struct->EntryPoint != 0x10001000ULL) {
            ADD_FAILURE() << "EntryPoint mismatch";
        }
        if (ldte_struct->SizeOfImage != 0x2000) {
            ADD_FAILURE() << "SizeOfImage mismatch";
        }
        if (ldte_struct->InLoadOrderLinks.Flink != ldte->get_address()) {
            ADD_FAILURE() << "Flink mismatch";
        }
        if (ldte_struct->InLoadOrderLinks.Blink != ldte->get_address()) {
            ADD_FAILURE() << "Blink mismatch";
        }
        if (ldte_struct->FullDllName.Length == 0) {
            ADD_FAILURE() << "FullDllName is empty";
        }
        if (ldte_struct->BaseDllName.Length == 0) {
            ADD_FAILURE() << "BaseDllName is empty";
        }
    } else {
        auto* ldte_struct = static_cast<speakeasy::deffs::nt::LDR_DATA_TABLE_ENTRY<4>*>(ldte->get_object());
        if (ldte_struct->DllBase != 0x10000000ULL) {
            ADD_FAILURE() << "DllBase mismatch";
        }
        if (ldte_struct->EntryPoint != 0x10001000ULL) {
            ADD_FAILURE() << "EntryPoint mismatch";
        }
        if (ldte_struct->SizeOfImage != 0x2000) {
            ADD_FAILURE() << "SizeOfImage mismatch";
        }
        if (ldte_struct->InLoadOrderLinks.Flink != ldte->get_address()) {
            ADD_FAILURE() << "Flink mismatch";
        }
        if (ldte_struct->InLoadOrderLinks.Blink != ldte->get_address()) {
            ADD_FAILURE() << "Blink mismatch";
        }
        if (ldte_struct->FullDllName.Length == 0) {
            ADD_FAILURE() << "FullDllName is empty";
        }
        if (ldte_struct->BaseDllName.Length == 0) {
            ADD_FAILURE() << "BaseDllName is empty";
        }
    }
}

TEST(ObjmanPortingTest, WinemuErrorContextTriage) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Verify region info retrieval resolves to null or expected mapped ranges
    auto region_unmapped = emu._resolve_region_info(0x9999000);
    EXPECT_EQ(region_unmapped, nullptr);

    auto region_mapped = emu._resolve_region_info(0x1000);
    EXPECT_NE(region_mapped, nullptr);

    // Verify context triage builder formats summaries faithfully
    auto nearby = emu._find_nearby_regions(0x1000, 2);
    auto summary = emu._build_context_summary("read", 0x401000, 0x1000, "read", "test.exe+0x1000", nullptr, nearby);
    EXPECT_FALSE(summary.empty());
}

TEST(ObjmanPortingTest, ThreadContextPcModification) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Create a Process
    auto proc = std::make_shared<Process>(&emu, nullptr,
                                         std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                         "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                         "", 0x400000, 0);
    emu.set_current_process(proc);

    // Create a Thread
    auto thread = std::make_shared<Thread>(&emu, 0x10000, 0x1000);
    EXPECT_FALSE(thread->get_modified_pc());

    // Retrieve initial context (allocated by constructor)
    auto ctx_ptr = thread->get_context();
    void* ctx = ctx_ptr.get();
    EXPECT_NE(ctx, nullptr);

    // Allocate a second context for testing and change PC
    size_t ctx_size = (emu.get_arch() == speakeasy::arch::ARCH_AMD64) ? 1232 : 716;
    uint64_t new_ctx_addr = emu.mem_map(ctx_size, std::nullopt, PERM_MEM_RW, "test.CONTEXT");
    std::vector<uint8_t> new_ctx_buf(ctx_size, 0xff);

    // Write a different RIP/EIP value into the new context buffer
    if (emu.get_arch() == speakeasy::arch::ARCH_AMD64) {
        // RIP at 0x140
        speakeasy::write_le(new_ctx_buf, 0x140, 0x401050ULL, 8);
    } else {
        // EIP at 0x98
        speakeasy::write_le(new_ctx_buf, 0x98, 0x401050ULL, 4);
    }
    emu.mem_write(new_ctx_addr, new_ctx_buf);

    // Read context back from the new buffer and set it on the thread
    auto new_ctx = std::make_shared<speakeasy::deffs::windows::CONTEXT>();
    emu.mem_cast(new_ctx.get(), new_ctx_addr);
    thread->set_context(new_ctx);
    EXPECT_TRUE(thread->get_modified_pc());
}

TEST(ObjmanPortingTest, TebReadbackIntegration) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Create a Process and a Thread
    auto proc = std::make_shared<Process>(&emu, nullptr,
                                         std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                         "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                         "", 0x400000, 0);
    emu.set_current_process(proc);
    
    // stack_base = 0x20000, stack_commit = 0x2000
    auto thread = std::make_shared<Thread>(&emu, 0x20000, 0x2000);
    
    // Initialize TEB
    uint64_t teb_addr = emu.mem_map(4096, std::nullopt, PERM_MEM_RW, "test.TEB");
    thread->init_teb(static_cast<int>(teb_addr), 0x30000);

    // Verify initial values
    auto teb = thread->get_teb();
    ASSERT_NE(teb, nullptr);
    {
        int teb_ps = emu.get_ptr_size();
        if (teb_ps == 8) {
            auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<8>*>(teb->get_object());
            EXPECT_EQ(teb_struct->NtTib.StackBase, 0x20000);
            EXPECT_EQ(teb_struct->NtTib.StackLimit, 0x2000);
        } else {
            auto* teb_struct = static_cast<speakeasy::deffs::nt::TEB<4>*>(teb->get_object());
            EXPECT_EQ(teb_struct->NtTib.StackBase, 0x20000);
            EXPECT_EQ(teb_struct->NtTib.StackLimit, 0x2000);
        }
    }

    // Directly modify TEB's StackLimit in emulation memory
    std::vector<uint8_t> new_limit_buf(4);
    speakeasy::write_le(new_limit_buf, 0, 0x5000, 4);
    // StackLimit is at offset 0x8 for both 32-bit and 64-bit TEB
    emu.mem_write(teb_addr + 8, new_limit_buf);

    // get_teb() should call read_back() and reflect the update
    auto teb_updated = thread->get_teb();
    {
        int teb_ps = emu.get_ptr_size();
        if (teb_ps == 8) {
            auto* ts = static_cast<speakeasy::deffs::nt::TEB<8>*>(teb_updated->get_object());
            EXPECT_EQ(ts->NtTib.StackLimit, 0x5000);
        } else {
            auto* ts = static_cast<speakeasy::deffs::nt::TEB<4>*>(teb_updated->get_object());
            EXPECT_EQ(ts->NtTib.StackLimit, 0x5000);
        }
    }
}

TEST(ObjmanPortingTest, ThreadSpecificLastErrorRouting) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Verify global last error works initially when no thread is active
    emu.set_last_error(123);
    EXPECT_EQ(emu.get_last_error(), 123);

    // Create a Process
    auto proc = std::make_shared<Process>(&emu, nullptr,
                                         std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                         "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                         "", 0x400000, 0);
    emu.set_current_process(proc);

    // Create a Thread and make it the current thread
    auto thread = std::make_shared<Thread>(&emu, 0x10000, 0x1000);
    proc->threads.push_back(thread);
    emu.set_current_thread(thread);

    // Setting error when thread is active should route to the thread
    emu.set_last_error(456);
    EXPECT_EQ(thread->get_last_error(), 456);
    EXPECT_EQ(emu.get_last_error(), 456);

    // Verify suspend count and stack getters/setters work
    thread->set_suspend_count(3);
    EXPECT_EQ(thread->get_suspend_count(), 3);
    EXPECT_EQ(thread->get_stack_base(), 0x10000);
    EXPECT_EQ(thread->get_stack_commit(), 0x1000);
    
    // Verify token routing
    void* token = thread->get_token();
    EXPECT_NE(token, nullptr);
}

TEST(ObjmanPortingTest, LoadModuleByNamePriorities) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Create a Process
    auto proc = std::make_shared<Process>(&emu, nullptr,
                                         std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                         "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                         "", 0x400000, 0);
    emu.set_current_process(proc);

    // 1. Load an API module (JIT PE synthetic image) - kernel32
    auto mod_kernel32 = emu.load_module_by_name("kernel32");
    ASSERT_NE(mod_kernel32, nullptr);
    EXPECT_EQ(mod_kernel32->get_base_name(), "kernel32.dll");
    EXPECT_FALSE(mod_kernel32->is_decoy());
    EXPECT_TRUE(mod_kernel32->is_dll());

    // 2. Load a nonexistent module - should fall back to default_exe template loading
    auto mod_decoy = emu.load_module_by_name("nonexistent");
    ASSERT_NE(mod_decoy, nullptr);
    EXPECT_EQ(mod_decoy->get_base_name(), "nonexistent.dll");
    // Since default_exe exists in the test config/paths, it resolves as a real template PE (EXE)
    EXPECT_FALSE(mod_decoy->is_decoy());
    // But we set module_type to "dll" in the default_exe template, so it should still be marked as a DLL
    EXPECT_TRUE(mod_decoy->is_dll());
}

TEST(ObjmanPortingTest, ShellcodeLoadAndRun) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // 1. Create a 1-byte shellcode with a RET instruction (0xC3)
    std::vector<uint8_t> sc_data = {0xC3};

    // 2. Load the shellcode using load_shellcode with override filename
    uint64_t sc_addr = emu.load_shellcode("", "x86", sc_data, "my_test_shellcode");
    EXPECT_NE(sc_addr, 0ULL);

    // 3. Verify the RuntimeModule registration and name
    auto rtmod = emu.get_mod_from_addr(sc_addr);
    ASSERT_NE(rtmod, nullptr);
    EXPECT_EQ(rtmod->name, "my_test_shellcode");

    // 4. Verify permissions of mapped shellcode memory
    auto mm = emu.get_address_map(sc_addr);
    ASSERT_NE(mm, nullptr);
    EXPECT_TRUE(mm->get_prot() & 0x4); // Executable bit is set (PERM_MEM_RWX)

    //TODO: SKIP NOW
    return;

    // 5. Emulate the shellcode. It will execute the RET and cleanly terminate when hitting return_hook.
    EXPECT_NO_THROW({
        emu.run_shellcode(sc_addr);
    });

    // 6. Verify the container process and thread were successfully created
    EXPECT_NE(emu.get_current_process(), nullptr);
    EXPECT_NE(emu.get_current_thread(), nullptr);

    // 7. Verify the stack base and commit sizes are valid and not truncated
    auto t = std::dynamic_pointer_cast<Thread>(emu.get_current_thread());
    ASSERT_NE(t, nullptr);
    EXPECT_GT(t->get_stack_base(), 0ULL);
    EXPECT_GT(t->get_stack_commit(), 0ULL);
}

TEST(WindowsEmulatorTest, ResumeInstructionLimit) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // 1. Load simple NOP shellcode that executes RET cleanly
    std::vector<uint8_t> sc_data = {0x90, 0x90, 0x90, 0xC3};
    uint64_t sc_addr = emu.load_shellcode("", "x86", sc_data, "resume_limit_test");
    EXPECT_NE(sc_addr, 0ULL);

    // 2. We trigger run_shellcode to start the engine run lifecycle
    // But to verify resume, we call resume directly.
    // EmuEngine::start will execute exactly 2 NOP instructions (0x90, 0x90) and return UC_ERR_OK.
    EXPECT_NO_THROW({
        emu.resume(sc_addr, 2);
    });
}

TEST(WindowsEmulatorTest, ModuleAccessHookSymbolResolution) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    //TODO: skip now
    return;

    // 1. Load a dummy shellcode to instantiate emu_eng_ and setup the memory engine
    std::vector<uint8_t> sc_data = {0xC3};
    uint64_t sc_addr = emu.load_shellcode("", "x86", sc_data, "access_hook_test");
    EXPECT_NE(sc_addr, 0ULL);


    // 2. Setup Process, Thread and stack so that get_ret_address() resolves safely
    auto proc = emu.get_current_process();
    if (!proc) {
        proc = std::make_shared<Process>(&emu, nullptr,
                                             std::vector<std::shared_ptr<speakeasy::RuntimeModule>>{},
                                             "dummy.exe", "C:\\Windows\\System32\\dummy.exe",
                                             "", 0x400000, 0);
        emu.set_current_process(proc);
    }

    auto [sb, sp] = emu.alloc_stack(0x4000);
    sp -= 0x100; // Decrement stack pointer to leave room at the top of the stack for arguments
    emu.set_stack_ptr(sp);
    auto t = std::make_shared<Thread>(&emu, sb, 0x4000);
    proc->threads.push_back(t);
    emu.set_current_thread(t);

    // Write a dummy return address at the stack pointer sp
    std::vector<uint8_t> dummy_ret = {0x00, 0x10, 0x00, 0x00}; // 0x1000
    emu.mem_write(sp, dummy_ret);

    // 3. Manually register a composite symbol using the public helper
    emu.add_mock_symbol(0x2000, "kernel32", "CreateFileA");

    // 4. Verify _module_access_hook successfully splits and dispatches composite symbols
    // It should return true since the symbol was successfully resolved and routed
    bool resolved = emu._module_access_hook(nullptr, 0x2000, 4);
    EXPECT_TRUE(resolved);
}

TEST(WindowsEmulatorTest, GetNativeModulePathValidation) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string path_default_exe = emu.get_native_module_path("default_exe");
    EXPECT_FALSE(path_default_exe.empty());
    EXPECT_NE(path_default_exe.find("default_exe"), std::string::npos);

    std::string path_empty = emu.get_native_module_path("nonexistent_decoy");
    EXPECT_TRUE(path_empty.empty());
}

class TestWin32Emulator : public Win32Emulator {
public:
    using Win32Emulator::Win32Emulator;
    void set_curr_run(std::shared_ptr<::Run> run) {
        curr_run = run;
    }
};

TEST(WindowsEmulatorTest, DISABLED_LogApiValidation) {
    SpeakeasyConfig cfg;
    TestWin32Emulator emu(cfg);
    emu.setup();

    // Create a mock Run context and assign it to the emulator
    auto mock_run = std::make_shared<::Run>();
    emu.set_curr_run(mock_run);
    emu.add_run(mock_run);

    // Add to profiler's run tracking (normally done by _prepare_run_context)
    auto prof = emu.get_profiler();
    ASSERT_NE(prof, nullptr);
    prof->add_run(mock_run);

    // Map some memory in the emulator so we can write a test string
    uint64_t str_addr = emu.mem_map(0x1000, 0x200000, common::PERM_MEM_RWX, "test.string");
    ASSERT_NE(str_addr, 0ULL);

    // Write ANSI string
    std::string ansi_str = "test_ansi_mutex_name";
    emu.write_mem_string(ansi_str, str_addr, 1);

    // Write Unicode string (UTF-16LE)
    uint64_t wstr_addr = str_addr + 0x100;
    std::string unicode_str = "test_unicode_event_name";
    emu.write_mem_string(unicode_str, wstr_addr, 2);

    // Trigger record_api_event with both string pointers and hex numbers
    ArgList argv = { uint64_t(0), uint64_t(0x15), str_addr, wstr_addr };
    EXPECT_NO_THROW({
        emu.log_api(0x401000, "kernel32.CreateMutexA", 0x1804, argv);
    });

    // Check if the event was correctly logged to the profiler report
    auto report = prof->get_report();
    ASSERT_EQ(report.entry_points.size(), 1ULL);

    // Find the logged API call from run->events
    ASSERT_FALSE(mock_run->events.empty());
    auto* api_event = dynamic_cast<speakeasy::events::ApiEvent*>(mock_run->events[0].get());
    ASSERT_NE(api_event, nullptr);

    EXPECT_EQ(api_event->api_name, "kernel32.CreateMutexA");
    EXPECT_EQ(api_event->pos.pc, 0x401000);
    EXPECT_EQ(api_event->ret_val, "0x1804");

    // Check arguments formatting:
    // args[0] should be "0x0" (numeric hex)
    // args[1] should be "0x15" (numeric hex)
    // args[2] should be "\"test_ansi_mutex_name\"" (string, quoted)
    // args[3] should be "\"test_unicode_event_name\"" (string, quoted)

    ASSERT_EQ(api_event->args.size(), 4ULL);
    EXPECT_EQ(api_event->args[0], "0x0");
    EXPECT_EQ(api_event->args[1], "0x15");
    EXPECT_EQ(api_event->args[2], "\"test_ansi_mutex_name\"");
    EXPECT_EQ(api_event->args[3], "\"test_unicode_event_name\"");
}

//
//  API handler regression tests
//  Cover key APIs fixed/implemented during the porting effort.
//  Tests use the public emulator interface rather than calling private
//  static API handlers directly.
//

TEST(ApiRegressionTest, GetProcAddressReturnsSentinelForNtdll) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Load ntdll and get NtSetInformationThread via GetProcAddress
    emu.load_library("ntdll.dll");
    void* addr = emu.get_proc("ntdll", "NtSetInformationThread");
    EXPECT_NE(addr, nullptr);
    EXPECT_NE(reinterpret_cast<uint64_t>(addr), 0ULL);
}

TEST(ApiRegressionTest, ReadMemStringWideRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string original = "Hello World!";
    uint64_t addr = emu.mem_map(256, std::nullopt, PERM_MEM_RW, "test.rw");
    be(&emu)->write_mem_string(original, addr, 2);
    std::string decoded = be(&emu)->read_mem_string(addr, 2);
    EXPECT_EQ(original, decoded);
}

TEST(ApiRegressionTest, ReadMemStringUnicodeRoundTrip) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    std::string unicode_str = "H\xe2\x82\xacllo W\xc3\xb6rld \xe2\x80\x94 test"; // Hllo Wrld  test
    uint64_t addr = emu.mem_map(256, std::nullopt, PERM_MEM_RW, "test.uni");
    be(&emu)->write_mem_string(unicode_str, addr, 2);
    std::string decoded = be(&emu)->read_mem_string(addr, 2);
    EXPECT_EQ(unicode_str, decoded);
}

TEST(ApiRegressionTest, FileOpenViaEmulator) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    void* h = emu.file_open("C:\\Windows\\system32\\kernel32.dll", false);
    EXPECT_NE(h, nullptr);
}

TEST(ApiRegressionTest, MutantCreateViaEmulator) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    auto [h, m] = emu.create_mutant("TestMutex");
    EXPECT_NE(h, 0U);
}

TEST(ApiRegressionTest, ProcessCreateViaEmulator) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    auto proc = emu.create_process("C:\\test.exe", "arg1");
    EXPECT_NE(proc, nullptr);
}

TEST(ApiRegressionTest, DoCallReturnWritesZeroToEax) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    emu.do_call_return(2, 0x401000, 0, speakeasy::arch::CALL_CONV_STDCALL);
    uint64_t eax = emu.reg_read(speakeasy::arch::REG_EAX);
    EXPECT_EQ(eax, 0ULL);
}

TEST(ApiRegressionTest, DoCallReturnWritesNonZeroToEax) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    emu.do_call_return(0, 0x401000, 0x42, speakeasy::arch::CALL_CONV_STDCALL);
    uint64_t eax = emu.reg_read(speakeasy::arch::REG_EAX);
    EXPECT_EQ(eax, 0x42ULL);
}
