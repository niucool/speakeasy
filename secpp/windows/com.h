// com.h
#ifndef COM_H
#define COM_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// TODO: Need C++ equivalents for these Python imports
// #include <speakeasy/winenv/defs/windows/com.h>
// #include <speakeasy/winenv/api/usermode/com_api.h>
// #include <speakeasy/errors.h>

// Forward declarations
class COM;
class ComInterface;

// The Component Object Model (COM) manager for the emulator. This will manage COM interfaces.
class COM {
private:
    std::map<std::string, std::shared_ptr<ComInterface>> interfaces;
    // TODO: Replace with nlohmann::json or appropriate JSON type
    // nlohmann::json config;
    std::map<std::string, std::string> config;

public:
    // Constructor
    // TODO: Replace with nlohmann::json parameter
    // COM(const nlohmann::json& config);
    COM(const std::map<std::string, std::string>& config);
    
    // Methods
    std::shared_ptr<ComInterface> get_interface(void* emu, size_t ptr_size, const std::string& name);
};

#endif // COM_H