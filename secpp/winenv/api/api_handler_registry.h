// api_handler_registry.h
#ifndef API_HANDLER_REGISTRY_H
#define API_HANDLER_REGISTRY_H

#include <string>
#include <map>
#include <functional>
#include <memory>

// Forward declarations
class ApiHandler;
class Emulator;

/**
 * API Handler Registry - C++ replacement for Python's dynamic module inspection
 * This registry allows static registration of API handlers at compile time
 */
class ApiHandlerRegistry {
public:
    using HandlerFactory = std::function<ApiHandler*(Emulator*)>;
    
private:
    static std::map<std::string, HandlerFactory>& get_registry() {
        static std::map<std::string, HandlerFactory> registry;
        return registry;
    }
    
public:
    /**
     * Register an API handler factory
     */
    static void register_handler(const std::string& name, HandlerFactory factory) {
        get_registry()[name] = factory;
    }
    
    /**
     * Create an API handler instance by name
     */
    static ApiHandler* create_handler(const std::string& name, Emulator* emu) {
        auto& registry = get_registry();
        auto it = registry.find(name);
        if (it != registry.end()) {
            return it->second(emu);
        }
        return nullptr;
    }
    
    /**
     * Get all registered handlers
     */
    static std::map<std::string, HandlerFactory> get_all_handlers() {
        return get_registry();
    }
};

/**
 * Macro for registering API handlers
 */
#define REGISTER_API_HANDLER(name, type) \
    namespace { \
        ApiHandler* create_##type(Emulator* emu) { \
            return new type(emu); \
        } \
        struct type##_Registrar { \
            type##_Registrar() { \
                ApiHandlerRegistry::register_handler(name, create_##type); \
            } \
        }; \
        static type##_Registrar type##_registrar; \
    }

#endif // API_HANDLER_REGISTRY_H