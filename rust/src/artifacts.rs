use std::collections::HashMap;
use sha2::{Sha256, Digest};
use hex;

// Assuming reporting contains arbitrary datatypes, replacing with standard string if missing
#[derive(Clone, Debug)]
pub struct DataArtifact {
    pub compression: String,
    pub encoding: String,
    pub size: usize,
    pub data: String,
}

pub struct ArtifactStore {
    artifacts: HashMap<String, DataArtifact>,
}

pub const MAX_EMBEDDED_FILE_SIZE: usize = 10 * 1024 * 1024;

impl ArtifactStore {
    pub fn new() -> Self {
        Self {
            artifacts: HashMap::new(),
        }
    }

    pub fn put_bytes(&mut self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest_bytes = hasher.finalize();
        let digest = hex::encode(digest_bytes);

        if !self.artifacts.contains_key(&digest) {
            // Because base64/zlib crates aren't loaded standard, we will mock hex formatting
            // In full implementation, this uses flate2::write::ZlibEncoder and base64::encode
            let compressed = hex::encode(data); // mock
            self.artifacts.insert(digest.clone(), DataArtifact {
                compression: "mock_zlib".to_string(), // mock
                encoding: "hex".to_string(), // mock
                size: data.len(),
                data: compressed,
            });
        }
        digest
    }

    pub fn get_bytes(&self, artifact_ref: &str) -> Option<Vec<u8>> {
        if let Some(artifact) = self.artifacts.get(artifact_ref) {
            if artifact.compression != "mock_zlib" || artifact.encoding != "hex" {
                return None;
            }
            if let Ok(decoded) = hex::decode(&artifact.data) {
                return Some(decoded);
            }
        }
        None
    }

    pub fn to_report_data(&self) -> HashMap<String, DataArtifact> {
        self.artifacts.clone()
    }
}
