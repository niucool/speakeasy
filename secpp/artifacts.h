// artifacts.h  Artifact store for emulation data blobs
//
// Maps to: speakeasy/artifacts.py
//
// Provides deduplicated storage for binary data captured during
// emulation (memory dumps, network payloads, extracted files).
// Data is compressed with zlib and base64-encoded for JSON embedding.

#ifndef SPEAKEASY_ARTIFACTS_H
#define SPEAKEASY_ARTIFACTS_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "report.h"

namespace speakeasy {

/// Maximum size (bytes) for a single embedded artifact before external storage is used.
constexpr size_t MAX_EMBEDDED_FILE_SIZE = 10 * 1024 * 1024;  // 10 MB

/**
 * Thread-safe store for binary artifacts.
 *
 * Each artifact is keyed by its SHA-256 digest.  On insertion the raw
 * bytes are compressed (zlib) and base64-encoded for embedding in the
 * JSON report.  Duplicate insertions are silently ignored.
 */
class ArtifactStore {
public:
    ArtifactStore() = default;

    /**
     * Store raw bytes.  Returns the SHA-256 hex digest used as the key.
     * If the same data was already stored, returns the existing digest
     * without re-encoding.
     */
    std::string put_bytes(const std::vector<uint8_t>& data);

    /**
     * Retrieve raw (decompressed, decoded) bytes by artifact reference.
     * @throws std::runtime_error if the ref is unknown or has unsupported encoding.
     */
    std::vector<uint8_t> get_bytes(const std::string& ref) const;

    /**
     * Export all stored artifacts as report-ready DataArtifact entries,
     * keyed by their SHA-256 digest.
     */
    std::map<std::string, DataArtifact> to_report_data() const;

    /**
     * Number of artifacts currently stored.
     */
    size_t size() const { return artifacts_.size(); }

    /**
     * Clear all stored artifacts.
     */
    void clear() { artifacts_.clear(); }

private:
    std::map<std::string, DataArtifact> artifacts_;
};

} // namespace speakeasy

#endif // SPEAKEASY_ARTIFACTS_H
