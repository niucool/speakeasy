// loaders.cpp — PE file loader (stub — pe-parse uses callback API)
//
// NOTE: pe-parse provides callback-based iteration (IterSec, IterImpVAString,
// IterExpVA) rather than direct struct arrays.  Full implementation requires
// wiring up callbacks to populate the LoadedImage structures.
// This stub provides the API surface and basic PE header parsing.

#include "loaders.h"
#include <fstream>
#include <cstring>
#include <stdexcept>

#include <pe-parse/parse.h>

namespace speakeasy {

PeLoader::PeLoader(const std::string& path, const std::vector<uint8_t>& data)
    : path_(path), data_(data) {

    if (data_.empty() && !path_.empty()) {
        std::ifstream ifs(path_, std::ios::binary | std::ios::ate);
        if (!ifs.is_open()) {
            throw std::runtime_error("Cannot open PE file: " + path_);
        }
        size_t fsize = static_cast<size_t>(ifs.tellg());
        ifs.seekg(0);
        data_.resize(fsize);
        ifs.read(reinterpret_cast<char*>(data_.data()), fsize);
    }

    if (data_.empty()) {
        throw std::runtime_error("No PE data to parse");
    }

    parse_pe();
}

void PeLoader::parse_pe() {
    peparse::parsed_pe* pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(data_.data()),
        static_cast<uint32_t>(data_.size()));

    if (!pe) {
        throw std::runtime_error("Failed to parse PE file");
    }

    // Read from peHeader directly
    metadata_.machine = pe->peHeader.nt.FileHeader.Machine;
    metadata_.magic = pe->peHeader.nt.OptionalHeader.Magic;
    metadata_.subsystem = pe->peHeader.nt.OptionalHeader.Subsystem;
    metadata_.timestamp = pe->peHeader.nt.FileHeader.TimeDateStamp;

    // TODO: Iterate sections via IterSec callback
    // TODO: Iterate imports via IterImpVAString callback
    // TODO: Iterate exports via IterExpVA callback
    // TODO: Iterate resources via IterRsrc callback

    peparse::DestructParsedPE(pe);
}

LoadedImage PeLoader::make_image() {
    LoadedImage img;

    uint64_t image_base = 0;
    uint64_t image_size = 0;

    peparse::parsed_pe* pe = peparse::ParsePEFromPointer(
        const_cast<uint8_t*>(data_.data()),
        static_cast<uint32_t>(data_.size()));

    if (pe) {
        image_base = pe->peHeader.nt.OptionalHeader.ImageBase;
        image_size = pe->peHeader.nt.OptionalHeader.SizeOfImage;

        // Get entry point
        peparse::VA ep_va;
        if (peparse::GetEntryPoint(pe, ep_va)) {
            // ep_va contains the entry point address
        }

        // Copy header bytes
        size_t header_size = pe->peHeader.nt.OptionalHeader.SizeOfHeaders;
        if (header_size > 0 && header_size <= data_.size()) {
            img.mapped_image.assign(data_.begin(),
                                    data_.begin() + header_size);
        }

        // Pad to section alignment
        uint32_t section_align = pe->peHeader.nt.OptionalHeader.SectionAlignment;
        if (section_align > 0) {
            while (img.mapped_image.size() % section_align != 0) {
                img.mapped_image.push_back(0);
            }
        }

        // Pad to full image size
        while (img.mapped_image.size() < image_size) {
            img.mapped_image.push_back(0);
        }

        peparse::DestructParsedPE(pe);
    }

    // Derive module name from path
    img.name = path_.empty() ? "unknown" :
        path_.substr(path_.find_last_of("/\\") + 1);
    img.name = img.name.substr(0, img.name.find_last_of('.'));

    img.image_size = image_size;
    img.base = image_base;
    img.arch = (metadata_.machine == 0x8664) ? 64 : 32;
    img.is_driver = (metadata_.subsystem == 1);  // NATIVE
    img.metadata = metadata_;
    img.imports = imports_;
    img.exports = exports_;
    img.sections = sections_;

    return img;
}

uint32_t PeLoader::perms_from_section_chars(uint32_t chars) {
    return speakeasy::perms_from_section_chars(chars);
}

std::string PeLoader::get_prot_string(uint32_t perms) {
    std::string s;
    s += (perms & 0x02) ? 'r' : '-';
    s += (perms & 0x04) ? 'w' : '-';
    s += (perms & 0x10) ? 'x' : '-';
    return s;
}

} // namespace speakeasy
