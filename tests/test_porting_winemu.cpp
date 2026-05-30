/**
 * test_porting_winemu.cpp  Object Manager and Winemu Porting Validation
 */

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#include "config.h"
#include "windows/winemu.h"
#include "windows/loaders.h"
#include "windows/win32.h"
#include "winenv/defs/nt/ntoskrnl.h"

using namespace speakeasy;

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
    auto* peb_struct = static_cast<speakeasy::defs::nt::PEB*>(peb->get_object());
    if (peb_struct->ProcessParameters == 0) {
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

    auto* ldte_struct = static_cast<speakeasy::defs::nt::LDR_DATA_TABLE_ENTRY*>(ldte->get_object());
    if (ldte_struct->DllBase != 0x10000000ULL) {
        ADD_FAILURE() << "DllBase mismatch";
    }
    if (ldte_struct->EntryPoint != 0x10001000ULL) {
        ADD_FAILURE() << "EntryPoint mismatch";
    }
    if (ldte_struct->SizeOfImage != 0x2000) {
        ADD_FAILURE() << "SizeOfImage mismatch";
    }

    // Circular links should point to itself since it is the only element
    if (ldte_struct->InLoadOrderLinks.Flink != ldte->get_address()) {
        ADD_FAILURE() << "Flink mismatch";
    }
    if (ldte_struct->InLoadOrderLinks.Blink != ldte->get_address()) {
        ADD_FAILURE() << "Blink mismatch";
    }

    // Verify Unicode strings
    if (ldte_struct->FullDllName.Length == 0) {
        ADD_FAILURE() << "FullDllName is empty";
    }
    if (ldte_struct->BaseDllName.Length == 0) {
        ADD_FAILURE() << "BaseDllName is empty";
    }
}

TEST(ObjmanPortingTest, WinemuErrorContextTriage) {
    SpeakeasyConfig cfg;
    Win32Emulator emu(cfg);
    emu.setup();

    // Verify region info retrieval resolves to null or expected mapped ranges
    auto region = emu._resolve_region_info(0x1000);
    EXPECT_EQ(region, nullptr);

    // Verify context triage builder formats summaries faithfully
    auto nearby = emu._find_nearby_regions(0x1000, 2);
    auto summary = emu._build_context_summary("read", 0x401000, 0x1000, "read", "test.exe+0x1000", nullptr, nearby);
    EXPECT_FALSE(summary.empty());
}
