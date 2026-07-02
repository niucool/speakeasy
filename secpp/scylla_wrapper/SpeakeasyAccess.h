/*
 * SpeakeasyAccess.h — Emulator-backed replacement for Windows process access.
 *
 * Replaces all native Windows APIs (OpenProcess, ReadProcessMemory,
 * VirtualQueryEx, EnumProcessModules, etc.) with Speakeasy emulator
 * equivalents.  All methods are static — call setEmulator() once
 * before any other operation.
 */
#pragma once

// (types provided via stdafx.h)  // was: #include <windows.h>
#include <cstdint>
#include <vector>

// Forward declarations
class Speakeasy;

// From ProcessAccessHelp.h (kept for compatibility)
class ModuleInfo;

class SpeakeasyAccess
{
public:
    /// Set the emulator instance (must be called before any other method).
    static void setEmulator(Speakeasy* se);
    static Speakeasy* emulator();

    // ---- Memory access (replaces ReadProcessMemory / WriteProcessMemory) ----

    static bool readMemory(DWORD_PTR address, SIZE_T size, void* dataBuffer);
    static bool writeMemory(DWORD_PTR address, SIZE_T size, const void* dataBuffer);

    // Partially-read: reads what's available, zero-fills the rest.
    static bool readMemoryPartly(DWORD_PTR address, SIZE_T size, void* dataBuffer);

    // ---- Module enumeration (replaces EnumProcessModules + GetModuleFileNameExW) ----

    static bool getModules(std::vector<ModuleInfo>& moduleList);

    // ---- Memory region query (replaces VirtualQueryEx) ----

    /// Get the base address and size of the memory region containing |address|.
    static bool getMemoryRegion(DWORD_PTR address, DWORD_PTR* regionBase, SIZE_T* regionSize);

    /// Walk memory regions starting at |moduleBase| and sum sizes until
    /// the mapped-file tag changes (mimics getSizeOfImageProcess).
    static SIZE_T getSizeOfImage(DWORD_PTR moduleBase);

    // ---- Host file I/O (kept for dump output — writes to real filesystem) ----

    static bool readFile(const WCHAR* filePath, LONG offset, DWORD size, void* buffer);
    static bool writeFile(const WCHAR* filePath, DWORD size, const void* buffer);

private:
    static Speakeasy* se_;
};
