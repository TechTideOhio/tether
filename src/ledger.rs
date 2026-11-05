use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("failed to access ledger at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to serialize/deserialize ledger entry: {0}")]
    Json(#[from] serde_json::Error),
    #[error("ledger integrity breach at index {index}: expected prev_hash {expected}, found {found}")]
    IntegrityBreach {
        index: usize,
        expected: String,
        found: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopLedgerEntry {
    pub index: usize,
    pub event_kind: String,
    pub case_id: Option<String>,
    pub detail: String,
    pub timestamp: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TetherLedger {
    pub version: String,
    pub total_entries: usize,
    pub head_hash: String,
    pub entries: Vec<LoopLedgerEntry>,
}

pub fn hash_ledger_entry(
    index: usize,
    event_kind: &str,
    case_id: Option<&str>,
    detail: &str,
    timestamp: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tether-run-v1\n");
    hasher.update(index.to_le_bytes());
    hasher.update(event_kind.as_bytes());
    hasher.update(b":");
    if let Some(id) = case_id {
        hasher.update(id.as_bytes());
    }
    hasher.update(b":");
    hasher.update(detail.as_bytes());
    hasher.update(b":");
    hasher.update(timestamp.as_bytes());
    hasher.update(b":");
    hasher.update(prev_hash.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl TetherLedger {
    pub fn new() -> Self {
        Self {
            version: "tether-run-v1".to_string(),
            total_entries: 0,
            head_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            entries: Vec::new(),
        }
    }

    pub fn append(
        &mut self,
        event_kind: &str,
        case_id: Option<&str>,
        detail: &str,
        timestamp: &str,
    ) -> &LoopLedgerEntry {
        let index = self.entries.len();
        let prev_hash = if index == 0 {
            self.head_hash.clone()
        } else {
            self.entries[index - 1].entry_hash.clone()
        };

        let entry_hash = hash_ledger_entry(index, event_kind, case_id, detail, timestamp, &prev_hash);

        let entry = LoopLedgerEntry {
            index,
            event_kind: event_kind.to_string(),
            case_id: case_id.map(ToString::to_string),
            detail: detail.to_string(),
            timestamp: timestamp.to_string(),
            prev_hash,
            entry_hash: entry_hash.clone(),
        };

        self.head_hash = entry_hash;
        self.total_entries = self.entries.len() + 1;
        self.entries.push(entry);
        self.entries.last().expect("just pushed")
    }

    pub fn verify_chain(&self) -> Result<(), LedgerError> {
        let mut expected_prev = "0000000000000000000000000000000000000000000000000000000000000000";
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.index != i {
                return Err(LedgerError::IntegrityBreach {
                    index: i,
                    expected: format!("index {i}"),
                    found: format!("index {}", entry.index),
                });
            }
            if entry.prev_hash != expected_prev {
                return Err(LedgerError::IntegrityBreach {
                    index: i,
                    expected: expected_prev.to_string(),
                    found: entry.prev_hash.clone(),
                });
            }
            let computed = hash_ledger_entry(
                entry.index,
                &entry.event_kind,
                entry.case_id.as_deref(),
                &entry.detail,
                &entry.timestamp,
                &entry.prev_hash,
            );
            if computed != entry.entry_hash {
                return Err(LedgerError::IntegrityBreach {
                    index: i,
                    expected: computed,
                    found: entry.entry_hash.clone(),
                });
            }
            expected_prev = &entry.entry_hash;
        }
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(Self::new());
        }
        let file = File::open(p).map_err(|e| LedgerError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        let reader = BufReader::new(file);
        let mut ledger = Self::new();

        for line in reader.lines() {
            let l = line.map_err(|e| LedgerError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
            let trimmed = l.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry: LoopLedgerEntry = serde_json::from_str(trimmed)?;
            ledger.head_hash = entry.entry_hash.clone();
            ledger.entries.push(entry);
        }
        ledger.total_entries = ledger.entries.len();
        ledger.verify_chain()?;
        Ok(ledger)
    }

    pub fn append_to_file(&self, path: impl AsRef<Path>, entry: &LoopLedgerEntry) -> Result<(), LedgerError> {
        let p = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .map_err(|e| LedgerError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
        let json_str = serde_json::to_string(entry)?;
        writeln!(file, "{json_str}").map_err(|e| LedgerError::Io {
            path: p.display().to_string(),
            source: e,
        })?;
        Ok(())
    }
}
