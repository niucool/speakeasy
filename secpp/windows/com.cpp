// com.cpp
#include "com.h"
#include "winemu.h"
#include <stdexcept>
#include <cstring>

//  COM interface field definitions 

namespace comdefs {

// IUnknown: 3 method pointers
const std::vector<ComField> IUnknown_fields = {
    {"QueryInterface", false},
    {"AddRef",         false},
    {"Release",        false},
};

// IMalloc: IUnknown (inherited) + 6 methods
const std::vector<ComField> IMalloc_fields = {
    {"IUnknown",    true},   // inherited interface
    {"Alloc",       false},
    {"Realloc",     false},
    {"Free",        false},
    {"GetSize",     false},
    {"DidAlloc",    false},
    {"HeapMinimize", false},
};

// IWbemLocator: IUnknown + 1 method
const std::vector<ComField> IWbemLocator_fields = {
    {"IUnknown",      true},
    {"ConnectServer", false},
};

// IWbemServices: IUnknown + 23 methods
const std::vector<ComField> IWbemServices_fields = {
    {"IUnknown",             true},
    {"OpenNamespace",        false},
    {"CancelAsyncCall",      false},
    {"QueryObjectSink",      false},
    {"GetObject",            false},
    {"GetObjectAsync",       false},
    {"PutClass",             false},
    {"PutClassAsync",        false},
    {"DeleteClass",          false},
    {"DeleteClassAsync",     false},
    {"CreateClassEnum",      false},
    {"CreateClassEnumAsync", false},
    {"PutInstance",          false},
    {"PutInstanceAsync",     false},
    {"DeleteInstance",       false},
    {"DeleteInstanceAsync",  false},
    {"CreateInstanceEnum",   false},
    {"CreateInstanceEnumAsync", false},
    {"ExecQuery",            false},
    {"ExecQueryAsync",       false},
    {"ExecNotificationQuery",      false},
    {"ExecNotificationQueryAsync", false},
    {"ExecMethod",           false},
    {"ExecMethodAsync",      false},
};

// IWbemContext: IUnknown + 9 methods
const std::vector<ComField> IWbemContext_fields = {
    {"IUnknown",        true},
    {"Clone",           false},
    {"GetNames",        false},
    {"BeginEnumeration", false},
    {"Next",            false},
    {"EndEnumeration",  false},
    {"SetValue",        false},
    {"GetValue",        false},
    {"DeleteValue",     false},
    {"DeleteAll",       false},
};

// IFACE_TYPES map: name -> fields
const std::map<std::string, std::vector<ComField>> IFACE_TYPES = {
    {"IUnknown",      IUnknown_fields},
    {"IMalloc",       IMalloc_fields},
    {"IWbemLocator",  IWbemLocator_fields},
    {"IWbemServices", IWbemServices_fields},
    {"IWbemContext",  IWbemContext_fields},
};

} // namespace comdefs

//  COM implementation 

COM::COM(const speakeasy::SpeakeasyConfig& cfg)
    : config(cfg) {
}

std::shared_ptr<ComInterface> COM::get_interface(void* emu, size_t ptr_size, const std::string& name) {
    // Check cache
    auto it = interfaces.find(name);
    if (it != interfaces.end()) {
        return it->second;
    }

    // Look up the interface type
    auto iface_it = comdefs::IFACE_TYPES.find(name);
    if (iface_it == comdefs::IFACE_TYPES.end()) {
        throw Win32EmuError("Invalid COM interface: " + name);
    }

    const auto& fields = iface_it->second;
    auto ci = std::make_shared<ComInterface>(fields, name, ptr_size);
    auto* winemu = static_cast<WindowsEmulator*>(emu);

    // Allocate vtable memory
    uint64_t com_ptr = winemu->mem_map(ci->iface_size, std::nullopt, 0x7, "emu.COM." + name);
    ci->address = com_ptr;

    // Build the vtable
    size_t field_offset = 0;
    for (const auto& field : fields) {
        if (field.is_interface) {
            // Inherited interface (e.g. IUnknown inside IMalloc)
            // Look up the nested interface's fields
            auto nested_it = comdefs::IFACE_TYPES.find(field.name);
            if (nested_it == comdefs::IFACE_TYPES.end()) {
                throw Win32EmuError("COM interface " + name +
                                    " inherits unsupported interface " + field.name);
            }

            const auto& nested_fields = nested_it->second;
            for (const auto& subfield : nested_fields) {
                // Nested interface fields should be method pointers
                if (!subfield.is_interface) {
                    std::string method_name = field.name + "_" + subfield.name;
                    uint64_t addr = winemu->add_callback("com_api", method_name);
                    std::vector<uint8_t> addr_bytes(ptr_size, 0);
                    for (size_t i = 0; i < ptr_size; i++) {
                        addr_bytes[i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);
                    }
                    winemu->mem_write(com_ptr + field_offset, addr_bytes);
                }
                field_offset += ptr_size;
            }
        } else {
            // Direct method pointer
            std::string method_name = name + "_" + field.name;
            uint64_t addr = winemu->add_callback("com_api", method_name);
            std::vector<uint8_t> addr_bytes(ptr_size, 0);
            for (size_t i = 0; i < ptr_size; i++) {
                addr_bytes[i] = static_cast<uint8_t>((addr >> (i * 8)) & 0xFF);
            }
            winemu->mem_write(com_ptr + field_offset, addr_bytes);
            field_offset += ptr_size;
        }
    }

    // Cache and return
    interfaces[name] = ci;
    return ci;
}
