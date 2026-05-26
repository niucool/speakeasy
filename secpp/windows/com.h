// com.h
#ifndef COM_H
#define COM_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <nlohmann/json.hpp>

#include "../errors.h"
#include "../config.h"

//  Forward declarations 
class WindowsEmulator;
class COM;

//  COM Interface field descriptor 
// Describes one field (slot) in a COM interface vtable.
// If is_interface is true, this field is an embedded inherited
// interface (e.g. IUnknown inside IMalloc); the inner interface's
// own fields are laid out sequentially starting at this offset.
// Otherwise the field is a method pointer.
struct ComField {
    std::string name;
    bool is_interface;
};

//  ComInterface wrapper 
// Holds the emulated vtable address, size, and field layout for
// one COM interface instance.
class ComInterface {
public:
    uint64_t address;
    std::string name;
    size_t iface_size;               // total vtable byte size
    std::vector<ComField> fields;    // field layout

    ComInterface(const std::vector<ComField>& f, const std::string& n, size_t ptr_size)
        : address(0), name(n), fields(f) {
        iface_size = fields.size() * ptr_size;
    }
};

//  COM definitions 
namespace comdefs {

#ifndef S_OK
const int S_OK = 0;
#endif

// Interface field descriptors
extern const std::vector<ComField> IUnknown_fields;
extern const std::vector<ComField> IMalloc_fields;
extern const std::vector<ComField> IWbemLocator_fields;
extern const std::vector<ComField> IWbemServices_fields;
extern const std::vector<ComField> IWbemContext_fields;

// Map interface name -> field descriptor list
extern const std::map<std::string, std::vector<ComField>> IFACE_TYPES;

} // namespace comdefs

//  COM manager 
// The Component Object Model (COM) manager for the emulator.
// Manages COM interface vtables in the emulated address space.
class COM {
private:
    std::map<std::string, std::shared_ptr<ComInterface>> interfaces;
    const speakeasy::SpeakeasyConfig& config;

public:
    explicit COM(const speakeasy::SpeakeasyConfig& cfg);

    // Get (or create) a COM interface instance by name.
    std::shared_ptr<ComInterface> get_interface(void* emu, size_t ptr_size, const std::string& name);
};

#endif // COM_H
