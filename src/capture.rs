use crate::case::{CaseFingerprint, CaseSource, CaseState, ExpectAssertion, TetherCase};
use crate::dedupe::{compute_exact_hash, compute_simhash64, is_near_duplicate};
use crate::error::TetherError;
use crate::redact::scrub_text;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessResultJson {
    pub status: String,
    pub summary: String,
    #[serde(default)]
    pub next_actions: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureIngestPayload {
    pub source_kind: String,
    pub run_ref: String,
    pub timestamp: String,
    pub agent: Option<String>,
    pub task: String,
    pub summary: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub category_hint: Option<String>,
}

pub enum CaptureOutcome {
    NewCandidate(TetherCase),
    MergedDuplicate {
        case_id: String,
        new_frequency: u64,
        reason: String,
    },
}

pub fn ingest_harness_result(
    result_path: impl AsRef<Path>,
    task_prompt_path: Option<&Path>,
) -> Result<FailureIngestPayload, TetherError> {
    let path = result_path.as_ref();
    let content = fs::read_to_string(path)?;
    let parsed: HarnessResultJson = serde_json::from_str(&content)?;

    let run_ref = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown-run".to_string());

    let task = if let Some(prompt_path) = task_prompt_path {
        fs::read_to_string(prompt_path).unwrap_or_else(|_| parsed.summary.clone())
    } else {
        parsed.summary.clone()
    };

    Ok(FailureIngestPayload {
        source_kind: "harness-run".to_string(),
        run_ref,
        timestamp: "2026-11-04".to_string(),
        agent: parsed.agent,
        task,
        summary: parsed.summary,
        details: None,
        category_hint: None,
    })
}

pub fn process_failure_ingest(
    payload: FailureIngestPayload,
    existing_cases: &mut [TetherCase],
    held_out_ratio: f64,
    next_id: String,
) -> Result<CaptureOutcome, TetherError> {
    let scrubbed_task = scrub_text(&payload.task)?;
    let scrubbed_summary = scrub_text(&payload.summary)?;
    let combined_for_hash = format!("{scrubbed_task} {scrubbed_summary}");

    let exact = compute_exact_hash(&combined_for_hash);
    let shingle = compute_simhash64(&combined_for_hash);

    // 1. Check exact duplicate
    for case in existing_cases.iter_mut() {
        if case.fingerprint.exact == exact {
            case.frequency = case.frequency.saturating_add(1);
            case.updated_at = "2026-11-04".to_string();
            return Ok(CaptureOutcome::MergedDuplicate {
                case_id: case.id.clone(),
                new_frequency: case.frequency,
                reason: format!("Exact SHA-256 match on {}", case.id),
            });
        }
    }

    // 2. Check near-duplicate (SimHash Hamming distance <= 3)
    for case in existing_cases.iter_mut() {
        if is_near_duplicate(case.fingerprint.shingle, shingle, 3) {
            case.frequency = case.frequency.saturating_add(1);
            case.updated_at = "2026-11-04".to_string();
            return Ok(CaptureOutcome::MergedDuplicate {
                case_id: case.id.clone(),
                new_frequency: case.frequency,
                reason: format!(
                    "Near-duplicate SimHash match on {} (shingle distance <= 3)",
                    case.id
                ),
            });
        }
    }

    // 3. Create new Candidate case
    let seed: u64 = crate::dedupe::fnv1a_64(next_id.as_bytes());
    let bucket = (seed % 100) as f64 / 100.0;
    let split = if bucket < held_out_ratio {
        "held_out".to_string()
    } else {
        "dev".to_string()
    };

    let category = payload
        .category_hint
        .unwrap_or_else(|| infer_category(&scrubbed_summary));

    let new_case = TetherCase {
        id: next_id,
        schema: "tether-case-v1".to_string(),
        state: CaseState::Candidate,
        source: CaseSource::HarnessRun {
            run_id: payload.run_ref,
            timestamp: payload.timestamp,
            agent: payload.agent.unwrap_or_else(|| "agent".to_string()),
        },
        fingerprint: CaseFingerprint { exact, shingle },
        category,
        stratum: "regression".to_string(),
        task: scrubbed_task,
        input_context: payload.details,
        expect: vec![
            ExpectAssertion::StatusEquals {
                equals: "error".to_string(),
            },
            ExpectAssertion::RegexAbsent {
                pattern: r"(?i)api[_-]?key".to_string(),
            },
        ],
        weight: 1.0,
        frequency: 1,
        split,
        is_blocker: false,
        created_at: "2026-11-04".to_string(),
        updated_at: "2026-11-04".to_string(),
        notes: format!("Auto-captured from production failure: {scrubbed_summary}"),
    };

    Ok(CaptureOutcome::NewCandidate(new_case))
}

fn infer_category(summary: &str) -> String {
    let lower = summary.to_lowercase();
    if lower.contains("not installed") || lower.contains("command not found") || lower.contains("exit 127") {
        "tool_execution".to_string()
    } else if lower.contains("secret") || lower.contains("token") || lower.contains("credential") || lower.contains("key") {
        "security_firewall".to_string()
    } else if lower.contains("loop") || lower.contains("timeout") || lower.contains("circuit breaker") {
        "loop_containment".to_string()
    } else {
        "prompt_alignment".to_string()
    }
}
