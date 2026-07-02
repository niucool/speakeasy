/*
 * SpeakeasyAccess.cpp — Emulator-backed implementation.
 */
#include "stdafx.h"
#include "SpeakeasyAccess.h"
#include "ProcessAccessHelp.h"
#include "speakeasy.h"

#include <cstring>
#include <plog/Log.h>

Speakeasy* SpeakeasyAccess::se_ = nullptr;

void SpeakeasyAccess::setEmulator(Speakeasy* se) { se_ = se; }
Speakeasy* SpeakeasyAccess::emulator() { return se_; }

// ---- Memory access ---------------------------------------------------------

bool SpeakeasyAccess::readMemory(DWORD_PTR address, SIZE_T size, void* dataBuffer)
{
    if (!se_) return false;
    try {
        auto data = se_->mem_read(static_cast<uint64_t>(address), static_cast<size_t>(size));
        size_t copySize = (std::min)(data.size(), static_cast<size_t>(size));
        std::memcpy(dataBuffer, data.data(), copySize);
        if (copySize < static_cast<size_t>(size))
            std::memset(static_cast<uint8_t*>(dataBuffer) + copySize, 0,
                        static_cast<size_t>(size) - copySize);
        return true;
    } catch (const std::exception& e) {
        PLOG_DEBUG << "SpeakeasyAccess::readMemory failed at 0x"
                   << std::hex << address << ": " << e.what();
        return false;
    }
}

bool SpeakeasyAccess::writeMemory(DWORD_PTR address, SIZE_T size, const void* dataBuffer)
{
    if (!se_) return false;
    try {
        const auto* bytes = static_cast<const uint8_t*>(dataBuffer);
        std::vector<uint8_t> data(bytes, bytes + size);
        se_->mem_write(static_cast<uint64_t>(address), data);
        return true;
    } catch (const std::exception& e) {
        PLOG_DEBUG << "SpeakeasyAccess::writeMemory failed at 0x"
                   << std::hex << address << ": " << e.what();
        return false;
    }
}

bool SpeakeasyAccess::readMemoryPartly(DWORD_PTR address, SIZE_T size, void* dataBuffer)
{
    if (!se_) return false;

    // Try a straight read first.
    if (readMemory(address, size, dataBuffer))
        return true;

    // Fall back: read region by region, zero-filling gaps.
    auto regions = se_->get_mem_regions();
    DWORD_PTR addr = address;
    SIZE_T remaining = size;
    uint8_t* dst = static_cast<uint8_t*>(dataBuffer);

    while (remaining > 0) {
        bool found = false;
        for (const auto& r : regions) {
            uint64_t rBase = std::get<0>(r);
            uint64_t rSize = std::get<1>(r);
            if (static_cast<uint64_t>(addr) >= rBase &&
                static_cast<uint64_t>(addr) < rBase + rSize) {
                SIZE_T toRead = static_cast<SIZE_T>(
                    (std::min)(static_cast<uint64_t>(remaining), rBase + rSize - addr));
                if (!readMemory(addr, toRead, dst)) return false;
                dst += toRead; addr += toRead; remaining -= toRead;
                found = true;
                break;
            }
        }
        if (!found) {
            uint64_t nextBase = UINT64_MAX;
            for (const auto& r : regions) {
                if (std::get<0>(r) > static_cast<uint64_t>(addr))
                    nextBase = (std::min)(nextBase, std::get<0>(r));
            }
            SIZE_T gap = static_cast<SIZE_T>(
                (std::min)(static_cast<uint64_t>(remaining),
                           nextBase == UINT64_MAX ? remaining : nextBase - addr));
            ZeroMemory(dst, gap);
            dst += gap; addr += gap; remaining -= gap;
        }
    }
    return true;
}

// ---- Module enumeration ----------------------------------------------------

bool SpeakeasyAccess::getModules(std::vector<ModuleInfo>& moduleList)
{
    if (!se_) return false;

    auto mods = se_->get_user_modules();
    moduleList.clear();
    moduleList.reserve(mods.size());

    for (const auto& mod : mods) {
        if (!mod) continue;
        ModuleInfo info;
        info.modBaseAddr = mod->base;
        info.modBaseSize = static_cast<DWORD>(mod->image_size);
        info.isAlreadyParsed = false;
        info.parsing = false;
        info.priority = 1;
        std::string name = mod->name.empty() ? mod->emu_path : mod->name;
        MultiByteToWideChar(CP_UTF8, 0, name.c_str(), -1, info.fullPath, MAX_PATH);
        moduleList.push_back(info);
    }
    return true;
}

// ---- Memory region query ---------------------------------------------------

bool SpeakeasyAccess::getMemoryRegion(DWORD_PTR address, DWORD_PTR* regionBase, SIZE_T* regionSize)
{
    if (!se_) return false;
    auto map = se_->get_address_map(static_cast<uint64_t>(address));
    if (!map) return false;
    *regionBase = static_cast<DWORD_PTR>(map->get_base());
    *regionSize = static_cast<SIZE_T>(map->get_size());
    return true;
}

SIZE_T SpeakeasyAccess::getSizeOfImage(DWORD_PTR moduleBase)
{
    if (!se_) return 0;
    auto mods = se_->get_user_modules();
    for (const auto& mod : mods) {
        if (mod && mod->base == static_cast<uint64_t>(moduleBase))
            return static_cast<SIZE_T>(mod->image_size);
    }
    return 0;
}

// ---- Host file I/O ---------------------------------------------------------

bool SpeakeasyAccess::readFile(const WCHAR* filePath, LONG offset, DWORD size, void* buffer)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    SetFilePointer(hFile, offset, nullptr, FILE_BEGIN);
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, buffer, size, &bytesRead, nullptr);
    CloseHandle(hFile);
    return ok && bytesRead == size;
}

bool SpeakeasyAccess::writeFile(const WCHAR* filePath, DWORD size, const void* buffer)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(hFile, buffer, size, &bytesWritten, nullptr);
    CloseHandle(hFile);
    return ok && bytesWritten == size;
}
