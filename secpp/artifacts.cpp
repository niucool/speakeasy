// artifacts.cpp  Artifact store implementation
//
// Maps to: speakeasy/artifacts.py
//
// Provides deduplicated storage for binary data captured during
// emulation.  Data is compressed with miniz (zlib-compatible) and
// base64-encoded for JSON embedding.

#include "artifacts.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

// PicoSHA2: header-only SHA-256 (via vcpkg)
#include "picosha2.h"

// miniz: zlib-compatible compression (via vcpkg)
#include <miniz.h>

namespace speakeasy {

//  Base64 encoding/decoding (inline, no external dependency) 

namespace {

static const std::string kB64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t oct = (static_cast<uint32_t>(data[i]) << 16);
        if (i + 1 < data.size()) oct |= (static_cast<uint32_t>(data[i + 1]) << 8);
        if (i + 2 < data.size()) oct |= static_cast<uint32_t>(data[i + 2]);
        out += kB64Chars[(oct >> 18) & 0x3F];
        out += kB64Chars[(oct >> 12) & 0x3F];
        out += (i + 1 < data.size()) ? kB64Chars[(oct >> 6) & 0x3F] : '=';
        out += (i + 2 < data.size()) ? kB64Chars[oct & 0x3F] : '=';
    }
    return out;
}

static uint8_t b64_dc(char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<uint8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0;
}

std::vector<uint8_t> base64_decode(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve((s.size() / 4) * 3);
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
        uint32_t oct = (static_cast<uint32_t>(b64_dc(s[i])) << 18) |
                       (static_cast<uint32_t>(b64_dc(s[i + 1])) << 12) |
                       (static_cast<uint32_t>(b64_dc(s[i + 2])) << 6) |
                       (static_cast<uint32_t>(b64_dc(s[i + 3])));
        out.push_back(static_cast<uint8_t>((oct >> 16) & 0xFF));
        if (s[i + 2] != '=') out.push_back(static_cast<uint8_t>((oct >> 8) & 0xFF));
        if (s[i + 3] != '=') out.push_back(static_cast<uint8_t>(oct & 0xFF));
    }
    return out;
}

} // anonymous namespace

//  zlib-compatible compression (via miniz/vcpkg) 

static const std::string kArtifactCompression = "zlib";

std::vector<uint8_t> artifact_compress(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    size_t bound = mz_compressBound(static_cast<mz_ulong>(data.size()));
    std::vector<uint8_t> compressed(bound);
    mz_ulong dest_len = bound;

    int ret = mz_compress(compressed.data(), &dest_len,
                          data.data(), static_cast<mz_ulong>(data.size()));
    if (ret != MZ_OK) {
        throw std::runtime_error("miniz compression failed with code: " +
                                 std::to_string(ret));
    }
    compressed.resize(dest_len);
    return compressed;
}

std::vector<uint8_t> artifact_decompress(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};

    // Guess decompressed size; grow exponentially if needed
    size_t guess = data.size() * 4;
    if (guess < 128) guess = 128;

    for (int attempt = 0; attempt < 10; ++attempt) {
        std::vector<uint8_t> decompressed(guess);
        mz_ulong dest_len = static_cast<mz_ulong>(guess);

        int ret = mz_uncompress(decompressed.data(), &dest_len,
                                data.data(), static_cast<mz_ulong>(data.size()));
        if (ret == MZ_OK) {
            decompressed.resize(dest_len);
            return decompressed;
        }
        if (ret != MZ_BUF_ERROR) {
            throw std::runtime_error("miniz decompression failed with code: " +
                                     std::to_string(ret));
        }
        guess *= 2;
    }
    throw std::runtime_error("miniz decompression failed: buffer too small after 10 attempts");
}

//  ArtifactStore 

std::string ArtifactStore::put_bytes(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";

    // SHA-256 digest
    std::string sha = picosha2::hash256_hex_string(data.begin(), data.end());

    // Dedup
    if (artifacts_.count(sha)) return sha;

    // Compress + encode
    std::vector<uint8_t> compressed = artifact_compress(data);
    DataArtifact artifact;
    artifact.compression = kArtifactCompression;
    artifact.encoding = "base64";
    artifact.size = data.size();
    artifact.data = base64_encode(compressed);

    artifacts_[sha] = std::move(artifact);
    return sha;
}

std::vector<uint8_t> ArtifactStore::get_bytes(const std::string& ref) const {
    auto it = artifacts_.find(ref);
    if (it == artifacts_.end()) {
        throw std::runtime_error("Artifact not found: " + ref);
    }

    const auto& art = it->second;

    // Decode
    std::vector<uint8_t> decoded = base64_decode(art.data);

    // Decompress if not plain
    if (art.compression != "none") {
        decoded = artifact_decompress(decoded);
    }

    return decoded;
}

std::map<std::string, DataArtifact> ArtifactStore::to_report_data() const {
    return artifacts_;
}

} // namespace speakeasy
