use crate::case::TetherCase;
use crate::spec::TetherSpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to read file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse lockfile JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("lockfile drift detected: {0}")]
    Drift(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetherLockfile {
    pub lock_version: String,
    pub suite_name: String,
    pub suite_version: String,
    pub spec_sha256: String,
    pub total_cases: usize,
    pub case_digests: BTreeMap<String, String>,
    pub overall_lock_digest: String,
}

pub fn hash_bytes_framed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sha256-framed-v1\n");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn hash_file_framed(path: impl AsRef<Path>) -> Result<String, LockfileError> {
    let p = path.as_ref();
    let bytes = fs::read(p).map_err(|e| LockfileError::Io {
        path: p.display().to_string(),
        source: e,
    })?;
    Ok(hash_bytes_framed(&bytes))
}

impl TetherLockfile {
    pub fn create(
        spec_path: impl AsRef<Path>,
        spec: &TetherSpec,
        cases: &[TetherCase],
    ) -> Result<Self, LockfileError> {
        let spec_sha = hash_file_framed(spec_path)?;

        let mut case_digests = BTreeMap::new();
        let mut overall_hasher = Sha256::new();
        overall_hasher.update(b"sha256-framed-v1-suite\n");
        overall_hasher.update(spec_sha.as_bytes());

        for case in cases {
            let json_bytes = serde_json::to_vec(case)?;
            let digest = hash_bytes_framed(&json_bytes);
            case_digests.insert(case.id.clone(), digest.clone());

            overall_hasher.update(case.id.as_bytes());
            overall_hasher.update(digest.as_bytes());
        }

        let overall_digest = format!("{:x}", overall_hasher.finalize());

        Ok(Self {
            lock_version: "sha256-framed-v1".to_string(),
            suite_name: spec.suite.name.clone(),
            suite_version: spec.suite.version.clone(),
            spec_sha256: spec_sha,
            total_cases: cases.len(),
            case_digests,
            overall_lock_digest: overall_digest,
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), LockfileError> {
        let p = path.as_ref();
        let json_str = serde_json::to_string_pretty(self)?;
        fs::write(p, json_str).map_err(|e| LockfileError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, LockfileError> {
        let p = path.as_ref();
        let content = fs::read_to_string(p).map_err(|e| LockfileError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        let lock: Self = serde_json::from_str(&content)?;
        Ok(lock)
    }

    pub fn verify(
        &self,
        spec_path: impl AsRef<Path>,
        cases: &[TetherCase],
    ) -> Result<(), LockfileError> {
        let current_spec_sha = hash_file_framed(spec_path)?;
        if current_spec_sha != self.spec_sha256 {
            return Err(LockfileError::Drift(format!(
                "Specification file has drifted: expected SHA-256 {}, got {}",
                self.spec_sha256, current_spec_sha
            )));
        }

        if cases.len() != self.total_cases {
            return Err(LockfileError::Drift(format!(
                "Case count mismatch: lockfile recorded {} cases, but loaded suite contains {}",
                self.total_cases,
                cases.len()
            )));
        }

        let mut overall_hasher = Sha256::new();
        overall_hasher.update(b"sha256-framed-v1-suite\n");
        overall_hasher.update(current_spec_sha.as_bytes());

        for case in cases {
            let expected_digest = self.case_digests.get(&case.id).ok_or_else(|| {
                LockfileError::Drift(format!("Unrecognized case '{}' not in lockfile", case.id))
            })?;
            let json_bytes = serde_json::to_vec(case)?;
            let current_digest = hash_bytes_framed(&json_bytes);
            if &current_digest != expected_digest {
                return Err(LockfileError::Drift(format!(
                    "Case '{}' content has drifted from sealed lockfile",
                    case.id
                )));
            }

            overall_hasher.update(case.id.as_bytes());
            overall_hasher.update(current_digest.as_bytes());
        }

        let computed_overall = format!("{:x}", overall_hasher.finalize());
        if computed_overall != self.overall_lock_digest {
            return Err(LockfileError::Drift(format!(
                "Suite lock digest mismatch: expected {}, got {}",
                self.overall_lock_digest, computed_overall
            )));
        }

        Ok(())
    }
}
