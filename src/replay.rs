use crate::case::TetherCase;
use crate::error::TetherError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub case_id: String,
    pub model: String,
    pub status: String,
    pub output: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCaseResult {
    pub case_id: String,
    pub category: String,
    pub split: String,
    pub passed: bool,
    pub is_blocker: bool,
    pub duration_ms: u64,
    pub tokens: u64,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteReport {
    pub model: String,
    pub total_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub pass_rate: f64,
    pub dev_cases: usize,
    pub dev_passed: usize,
    pub dev_pass_rate: f64,
    pub held_out_cases: usize,
    pub held_out_passed: usize,
    pub held_out_pass_rate: f64,
    pub category_pass_rates: HashMap<String, f64>,
    pub category_counts: HashMap<String, usize>,
    pub category_passed: HashMap<String, usize>,
    pub blocker_failures: usize,
    pub results: Vec<ReplayCaseResult>,
}

pub fn load_offline_replay_records(
    path: impl AsRef<Path>,
) -> Result<Vec<ReplayRecord>, TetherError> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (line_no, line) in reader.lines().enumerate() {
        let line_content = line?;
        let trimmed = line_content.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let record: ReplayRecord = serde_json::from_str(trimmed).map_err(|e| {
            TetherError::General(format!(
                "Failed to parse replay JSONL at line {}: {e}",
                line_no + 1
            ))
        })?;
        records.push(record);
    }

    Ok(records)
}

pub fn execute_runner_command(
    cmd_str: &str,
    case: &TetherCase,
) -> Result<ReplayRecord, TetherError> {
    let mut child = if cfg!(windows) {
        Command::new("powershell")
            .args(["-NoProfile", "-Command", cmd_str])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    } else {
        Command::new("sh")
            .args(["-c", cmd_str])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }
    .map_err(|e| TetherError::RunnerFailed(format!("Failed to spawn runner: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        let case_json = serde_json::to_string(case)?;
        stdin.write_all(case_json.as_bytes())?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| TetherError::RunnerFailed(format!("Runner wait error: {e}")))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();

    #[derive(Deserialize)]
    struct RunnerOutput {
        status: Option<String>,
        output: Option<String>,
        duration_ms: Option<u64>,
        tokens: Option<u64>,
    }

    if let Ok(parsed) = serde_json::from_str::<RunnerOutput>(&stdout_str) {
        Ok(ReplayRecord {
            case_id: case.id.clone(),
            model: "runner-model".to_string(),
            status: parsed.status.unwrap_or_else(|| {
                if output.status.success() {
                    "success".to_string()
                } else {
                    "error".to_string()
                }
            }),
            output: parsed.output.unwrap_or_else(|| stdout_str.clone()),
            duration_ms: parsed.duration_ms.unwrap_or(100),
            tokens: parsed.tokens.unwrap_or(250),
        })
    } else {
        Ok(ReplayRecord {
            case_id: case.id.clone(),
            model: "runner-model".to_string(),
            status: if output.status.success() {
                "success".to_string()
            } else {
                "error".to_string()
            },
            output: stdout_str,
            duration_ms: 100,
            tokens: 250,
        })
    }
}

pub fn evaluate_replay_against_suite(
    cases: &[TetherCase],
    records: &[ReplayRecord],
    model_name: &str,
) -> Result<ReplaySuiteReport, TetherError> {
    let mut record_map: HashMap<&str, &ReplayRecord> = HashMap::new();
    for r in records {
        record_map.insert(r.case_id.as_str(), r);
    }

    let mut results = Vec::new();
    let mut passed_cases = 0;
    let mut dev_cases = 0;
    let mut dev_passed = 0;
    let mut held_out_cases = 0;
    let mut held_out_passed = 0;
    let mut blocker_failures = 0;

    let mut category_counts = HashMap::new();
    let mut category_passed = HashMap::new();

    for case in cases {
        *category_counts.entry(case.category.clone()).or_insert(0) += 1;

        if case.split == "held_out" {
            held_out_cases += 1;
        } else {
            dev_cases += 1;
        }

        let record = record_map.get(case.id.as_str());
        let (passed, duration_ms, tokens, failures) = match record {
            Some(rec) => {
                match case.evaluate_run(&rec.status, &rec.output, rec.duration_ms, rec.tokens) {
                    Ok(()) => (true, rec.duration_ms, rec.tokens, Vec::new()),
                    Err(errs) => (false, rec.duration_ms, rec.tokens, errs),
                }
            }
            None => (
                false,
                0,
                0,
                vec![format!("Missing replay execution for case '{}'", case.id)],
            ),
        };

        if passed {
            passed_cases += 1;
            *category_passed.entry(case.category.clone()).or_insert(0) += 1;
            if case.split == "held_out" {
                held_out_passed += 1;
            } else {
                dev_passed += 1;
            }
        } else if case.is_blocker {
            blocker_failures += 1;
        }

        results.push(ReplayCaseResult {
            case_id: case.id.clone(),
            category: case.category.clone(),
            split: case.split.clone(),
            passed,
            is_blocker: case.is_blocker,
            duration_ms,
            tokens,
            failures,
        });
    }

    let total = cases.len();
    let pass_rate = if total > 0 {
        passed_cases as f64 / total as f64
    } else {
        0.0
    };

    let dev_pass_rate = if dev_cases > 0 {
        dev_passed as f64 / dev_cases as f64
    } else {
        0.0
    };

    let held_out_pass_rate = if held_out_cases > 0 {
        held_out_passed as f64 / held_out_cases as f64
    } else {
        0.0
    };

    let mut category_pass_rates = HashMap::new();
    for (cat, count) in &category_counts {
        let passed = category_passed.get(cat).copied().unwrap_or(0);
        let rate = if *count > 0 {
            passed as f64 / *count as f64
        } else {
            0.0
        };
        category_pass_rates.insert(cat.clone(), rate);
    }

    Ok(ReplaySuiteReport {
        model: model_name.to_string(),
        total_cases: total,
        passed_cases,
        failed_cases: total.saturating_sub(passed_cases),
        pass_rate,
        dev_cases,
        dev_passed,
        dev_pass_rate,
        held_out_cases,
        held_out_passed,
        held_out_pass_rate,
        category_pass_rates,
        category_counts,
        category_passed,
        blocker_failures,
        results,
    })
}
