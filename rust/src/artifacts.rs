// Artifact store for Speakeasy

use std::collections::HashMap;
use crate::report::DataArtifact;
use sha2::{Sha256, Digest};
use hex;

pub const MAX_EMBEDDED_FILE_SIZE: usize = 10 * 1024 * 1024;

pub struct ArtifactStore {
    pub artifacts: HashMap<String, DataArtifact>,
}

impl ArtifactStore {
    pub fn new() -> Self {
        Self {
            artifacts: HashMap::new(),
        }
    }

    pub fn put_bytes(&mut self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hex::encode(hasher.finalize());

        if !self.artifacts.contains_key(&digest) {
            // Simplified: no compression for now as zlib is not in Cargo.toml
            self.artifacts.insert(digest.clone(), DataArtifact {
                compression: "none".to_string(),
                encoding: "hex".to_string(),
                size: data.len(),
                data: hex::encode(data),
            });
        }
        digest
    }

    pub fn get_bytes(&self, artifact_ref: &str) -> Option<Vec<u8>> {
        let artifact = self.artifacts.get(artifact_ref)?;
        if artifact.encoding == "hex" {
            hex::decode(&artifact.data).ok()
        } else {
            None
        }
    }

    pub fn to_report_data(&self) -> HashMap<String, DataArtifact> {
        self.artifacts.clone()
    }
}
