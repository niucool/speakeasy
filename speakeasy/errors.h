// errors.h
#ifndef SPEAKEASY_ERRORS_H
#define SPEAKEASY_ERRORS_H

#include <exception>
#include <string>

/**
 * Base class for Speakeasy errors
 */
class SpeakeasyError : public std::exception {
protected:
    std::string message;

public:
    explicit SpeakeasyError(const std::string& msg = "Speakeasy error occurred") 
        : message(msg) {}

    virtual const char* what() const noexcept override {
        return message.c_str();
    }
};

/**
 * Sample is not currently supported
 */
class NotSupportedError : public SpeakeasyError {
public:
    explicit NotSupportedError(const std::string& msg = "Sample is not currently supported")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for API errors
 */
class ApiEmuError : public SpeakeasyError {
public:
    explicit ApiEmuError(const std::string& msg = "API emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for emulation errors
 */
class EmuException : public SpeakeasyError {
public:
    explicit EmuException(const std::string& msg = "Emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Emulation engine error
 */
class EmuEngineError : public SpeakeasyError {
public:
    explicit EmuEngineError(const std::string& msg = "Emulation engine error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for Windows emulation errors
 */
class WindowsEmuError : public SpeakeasyError {
public:
    explicit WindowsEmuError(const std::string& msg = "Windows emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for Windows kernel mode emulation errors
 */
class KernelEmuError : public SpeakeasyError {
public:
    explicit KernelEmuError(const std::string& msg = "Windows kernel mode emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for Windows user mode emulation errors
 */
class Win32EmuError : public SpeakeasyError {
public:
    explicit Win32EmuError(const std::string& msg = "Windows user mode emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Base class for file system emulation errors
 */
class FileSystemEmuError : public SpeakeasyError {
public:
    explicit FileSystemEmuError(const std::string& msg = "File system emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Raised during network emulation errors
 */
class NetworkEmuError : public SpeakeasyError {
public:
    explicit NetworkEmuError(const std::string& msg = "Network emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Raised during registry emulation errors
 */
class RegistryEmuError : public SpeakeasyError {
public:
    explicit RegistryEmuError(const std::string& msg = "Registry emulation error occurred")
        : SpeakeasyError(msg) {}
};

/**
 * Raised during validating configuration
 */
class ConfigError : public SpeakeasyError {
public:
    explicit ConfigError(const std::string& msg = "Configuration error occurred")
        : SpeakeasyError(msg) {}
};

#endif // SPEAKEASY_ERRORS_H