// wsk.h  Winsock Kernel (WSK) type definitions
//
// Maps to: speakeasy/winenv/defs/wsk.py
//
// WSK provider and client NPI dispatch structures used by
// kernel-mode Winsock emulation.

#ifndef SPEAKEASY_DEFS_WSK_H
#define SPEAKEASY_DEFS_WSK_H

#include <cstdint>
#include <vector>
#include "../../struct.h"

namespace speakeasy { namespace defs {

//  WSK_PROVIDER_BASIC_DISPATCH (16 bytes) 
struct WSK_PROVIDER_BASIC_DISPATCH : speakeasy::EmuStruct {
    uint64_t WskControlSocket = 0;  // Ptr
    uint64_t WskCloseSocket   = 0;  // Ptr

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, WskControlSocket, 8);
        speakeasy::write_le(b, 8, WskCloseSocket, 8);
        return b;
    }
};

//  WSK_PROVIDER_DATAGRAM_DISPATCH (48 bytes) 
struct WSK_PROVIDER_DATAGRAM_DISPATCH : speakeasy::EmuStruct {
    WSK_PROVIDER_BASIC_DISPATCH Basic;
    uint64_t WskBind            = 0;
    uint64_t WskSendTo          = 0;
    uint64_t WskReceiveFrom     = 0;
    uint64_t WskRelease         = 0;
    uint64_t WskGetLocalAddress = 0;
    uint64_t WskSendMessages    = 0;

    size_t sizeof_obj() const override {
        return Basic.sizeof_obj() + 6 * 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        size_t sz = sizeof_obj();
        std::vector<uint8_t> b(sz, 0);
        auto bb = Basic.get_bytes();
        std::copy(bb.begin(), bb.end(), b.begin());
        size_t off = bb.size();
        speakeasy::write_le(b, off, WskBind, 8); off += 8;
        speakeasy::write_le(b, off, WskSendTo, 8); off += 8;
        speakeasy::write_le(b, off, WskReceiveFrom, 8); off += 8;
        speakeasy::write_le(b, off, WskRelease, 8); off += 8;
        speakeasy::write_le(b, off, WskGetLocalAddress, 8); off += 8;
        speakeasy::write_le(b, off, WskSendMessages, 8); off += 8;
        return b;
    }
};

//  WSK_CLIENT_DISPATCH (16 bytes) 
struct WSK_CLIENT_DISPATCH : speakeasy::EmuStruct {
    uint16_t Version   = 0;
    uint16_t Reserved  = 0;
    uint32_t __pad0    = 0;
    uint64_t WskClientEvent = 0;  // Ptr

    size_t sizeof_obj() const override { return 2 + 2 + 4 + 8; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, Version, 2);
        speakeasy::write_le(b, 2, Reserved, 2);
        // __pad0
        speakeasy::write_le(b, 8, WskClientEvent, 8);
        return b;
    }
};

//  WSK_CLIENT_NPI (16 bytes) 
struct WSK_CLIENT_NPI : speakeasy::EmuStruct {
    uint64_t ClientContext = 0;  // Ptr
    uint64_t Dispatch      = 0;  // Ptr (PWSK_CLIENT_DISPATCH)

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, ClientContext, 8);
        speakeasy::write_le(b, 8, Dispatch, 8);
        return b;
    }
};

//  WSK_PROVIDER_DISPATCH (56 bytes) 
struct WSK_PROVIDER_DISPATCH : speakeasy::EmuStruct {
    uint16_t Version           = 0;
    uint16_t Reserved          = 0;
    uint32_t __pad0            = 0;
    uint64_t WskSocket         = 0;
    uint64_t WskSocketConnect  = 0;
    uint64_t WskControlClient  = 0;
    uint64_t WskGetAddressInfo = 0;
    uint64_t WskFreeAddressInfo = 0;
    uint64_t WskGetNameInfo    = 0;

    size_t sizeof_obj() const override {
        return 2 + 2 + 4 + 6 * 8;
    }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(56);
        speakeasy::write_le(b, 0, Version, 2);
        speakeasy::write_le(b, 2, Reserved, 2);
        // __pad0
        speakeasy::write_le(b, 8, WskSocket, 8);
        speakeasy::write_le(b, 16, WskSocketConnect, 8);
        speakeasy::write_le(b, 24, WskControlClient, 8);
        speakeasy::write_le(b, 32, WskGetAddressInfo, 8);
        speakeasy::write_le(b, 40, WskFreeAddressInfo, 8);
        speakeasy::write_le(b, 48, WskGetNameInfo, 8);
        return b;
    }
};

//  WSK_PROVIDER_NPI (16 bytes) 
struct WSK_PROVIDER_NPI : speakeasy::EmuStruct {
    uint64_t Client   = 0;  // Ptr
    uint64_t Dispatch = 0;  // Ptr

    size_t sizeof_obj() const override { return 16; }
    std::vector<uint8_t> get_bytes() const override {
        std::vector<uint8_t> b(16);
        speakeasy::write_le(b, 0, Client, 8);
        speakeasy::write_le(b, 8, Dispatch, 8);
        return b;
    }
};

}} // namespace speakeasy::defs

#endif // SPEAKEASY_DEFS_WSK_H
