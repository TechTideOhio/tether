use crate::error::TetherError;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseState {
    Candidate,
    Labeled,
    Active,
    Retired,
}

impl CaseState {
    pub fn transition_to(
        &self,
        target: CaseState,
        reason: Option<&str>,
    ) -> Result<(), TetherError> {
        match (self, target) {
            (CaseState::Candidate, CaseState::Labeled) => Ok(()),
            (CaseState::Candidate, CaseState::Retired) => Ok(()),
            (CaseState::Labeled, CaseState::Active) => Ok(()),
            (CaseState::Labeled, CaseState::Retired) => Ok(()),
            (CaseState::Active, CaseState::Retired) => Ok(()),
            (CaseState::Retired, _) => Err(TetherError::InvalidTransition {
                from: format!("{self:?}"),
                to: format!("{target:?}"),
                reason: "Retired state is terminal; cases cannot be unretired".to_string(),
            }),
            (from, to) if from == &to => Ok(()),
            (from, to) => Err(TetherError::InvalidTransition {
                from: format!("{from:?}"),
                to: format!("{to:?}"),
                reason: reason
                    .unwrap_or("Illegal direct state jump in case lifecycle")
                    .to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpectAssertion {
    StatusEquals { equals: String },
    Contains { text: String },
    NotContains { text: String },
    RegexMatch { pattern: String },
    RegexAbsent { pattern: String },
    MaxDurationMs { max: u64 },
    MaxTokens { max: u64 },
}

impl ExpectAssertion {
    pub fn evaluate(
        &self,
        actual_status: &str,
        actual_output: &str,
        duration_ms: u64,
        tokens: u64,
    ) -> Result<(), String> {
        match self {
            ExpectAssertion::StatusEquals { equals } => {
                if actual_status == equals {
                    Ok(())
                } else {
                    Err(format!(
                        "Status mismatch: expected '{equals}', got '{actual_status}'"
                    ))
                }
            }
            ExpectAssertion::Contains { text } => {
                if actual_output.contains(text) {
                    Ok(())
                } else {
                    Err(format!("Expected output to contain substring '{text}'"))
                }
            }
            ExpectAssertion::NotContains { text } => {
                if !actual_output.contains(text) {
                    Ok(())
                } else {
                    Err(format!("Expected output to NOT contain substring '{text}'"))
                }
            }
            ExpectAssertion::RegexMatch { pattern } => {
                let re =
                    Regex::new(pattern).map_err(|e| format!("Invalid regex '{pattern}': {e}"))?;
                if re.is_match(actual_output) {
                    Ok(())
                } else {
                    Err(format!("Output failed to match regex pattern '{pattern}'"))
                }
            }
            ExpectAssertion::RegexAbsent { pattern } => {
                let re =
                    Regex::new(pattern).map_err(|e| format!("Invalid regex '{pattern}': {e}"))?;
                if !re.is_match(actual_output) {
                    Ok(())
                } else {
                    Err(format!(
                        "Output matched forbidden regex pattern '{pattern}'"
                    ))
                }
            }
            ExpectAssertion::MaxDurationMs { max } => {
                if duration_ms <= *max {
                    Ok(())
                } else {
                    Err(format!("Duration SLA exceeded: {duration_ms}ms > {max}ms"))
                }
            }
            ExpectAssertion::MaxTokens { max } => {
                if tokens <= *max {
                    Ok(())
                } else {
                    Err(format!("Token budget exceeded: {tokens} > {max}"))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CaseSource {
    HarnessRun {
        run_id: String,
        timestamp: String,
        agent: String,
    },
    OtelTrace {
        trace_id: String,
        span_id: String,
    },
    ProductionLog {
        log_id: String,
        service: String,
    },
    Manual {
        author: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseFingerprint {
    pub exact: String,
    pub shingle: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TetherCase {
    pub id: String,
    pub schema: String,
    pub state: CaseState,
    pub source: CaseSource,
    pub fingerprint: CaseFingerprint,
    pub category: String,
    pub stratum: String,
    pub task: String,
    #[serde(default)]
    pub input_context: Option<String>,
    pub expect: Vec<ExpectAssertion>,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default = "default_frequency")]
    pub frequency: u64,
    pub split: String,
    #[serde(default)]
    pub is_blocker: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub notes: String,
}

fn default_weight() -> f64 {
    1.0
}

fn default_frequency() -> u64 {
    1
}

impl TetherCase {
    pub fn transition(
        &mut self,
        target: CaseState,
        reason: Option<&str>,
    ) -> Result<(), TetherError> {
        self.state.transition_to(target, reason)?;
        self.state = target;
        Ok(())
    }

    pub fn evaluate_run(
        &self,
        actual_status: &str,
        actual_output: &str,
        duration_ms: u64,
        tokens: u64,
    ) -> Result<(), Vec<String>> {
        let mut failures = Vec::new();
        for assertion in &self.expect {
            if let Err(msg) = assertion.evaluate(actual_status, actual_output, duration_ms, tokens)
            {
                failures.push(msg);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}
