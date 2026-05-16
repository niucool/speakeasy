// artifacts.cpp — Artifact store implementation

#include "artifacts.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>

// PicoSHA2: header-only SHA-256 (via vcpkg)
#include <picosha2.h>

namespace speakeasy {

// ── Base64 encoding/decoding (inline, no external dependency) ─

namespace {

const char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);

        out.push_back(BASE64_TABLE[(n >> 18) & 0x3F]);
        out.push_back(BASE64_TABLE[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < data.size()) ? BASE64_TABLE[(n >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < data.size()) ? BASE64_TABLE[n & 0x3F] : '=');
    }
    return out;
}

std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static int decode_table[256] = {};
    static bool table_built = false;
    if (!table_built) {
        for (int i = 0; i < 256; ++i) decode_table[i] = -1;
        for (int i = 0; i < 64; ++i) decode_table[static_cast<uint8_t>(BASE64_TABLE[i])] = i;
        table_built = true;
    }

    std::vector<uint8_t> out;
    out.reserve((encoded.size() / 4) * 3);

    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=' || decode_table[c] == -1) continue;
        val = (val << 6) + decode_table[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ── Minimal zlib-compatible deflate (stub) ─────────────────
// TODO: Replace with real zlib when available, or use miniz/zlib-ng.
// For now, artifacts are stored raw (no compression).

std::vector<uint8_t> artifact_compress(const std::vector<uint8_t>& data) {
    // Stub: return data unchanged.  Real implementation would use zlib.
    return data;
}

std::vector<uint8_t> artifact_decompress(const std::vector<uint8_t>& data) {
    // Stub: return data unchanged.
    return data;
}

// ── SHA-256 (PicoSHA2) ──────────────────────────────────

std::string sha256_hex(const std::vector<uint8_t>& data) {
    picosha2::hash256_one_by_one h;
    h.process(data.data(), data.data() + data.size());
    h.finish();
    picosha2::byte_t hash[32];
    h.get_hash_bytes(hash, hash + 32);
    static const char hex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i) { out[i*2] = hex[(hash[i]>>4)&0xf]; out[i*2+1] = hex[hash[i]&0xf]; }
    return out;
}

} // anonymous namespace

// ── Public methods ──────────────────────────────────────────

std::string ArtifactStore::put_bytes(const std::vector<uint8_t>& data) {
    std::string digest = sha256_hex(data);

    if (artifacts_.count(digest) == 0) {
        std::vector<uint8_t> compressed = artifact_compress(data);
        DataArtifact artifact;
        artifact.compression = "none";  // TODO: "zlib" when real zlib is available
        artifact.encoding = "base64";
        artifact.size = data.size();
        artifact.data = base64_encode(compressed);
        artifacts_[digest] = artifact;
    }

    return digest;
}

std::vector<uint8_t> ArtifactStore::get_bytes(const std::string& ref) const {
    auto it = artifacts_.find(ref);
    if (it == artifacts_.end()) {
        throw std::runtime_error("Artifact not found: " + ref);
    }

    const auto& artifact = it->second;
    if (artifact.compression != "none" && artifact.compression != "zlib") {
        throw std::runtime_error("Unsupported compression: " + artifact.compression);
    }
    if (artifact.encoding != "base64") {
        throw std::runtime_error("Unsupported encoding: " + artifact.encoding);
    }

    std::vector<uint8_t> compressed = base64_decode(artifact.data);
    return artifact_decompress(compressed);
}

std::map<std::string, DataArtifact> ArtifactStore::to_report_data() const {
    return artifacts_;
}

} // namespace speakeasy
