use crate::case::{CaseState, ExpectAssertion, TetherCase};
use crate::error::TetherError;
use crate::spec::TetherSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteStats {
    pub total_cases: usize,
    pub active_cases: usize,
    pub candidate_cases: usize,
    pub labeled_cases: usize,
    pub retired_cases: usize,
    pub dev_cases: usize,
    pub held_out_cases: usize,
    pub blocker_cases: usize,
    pub category_counts: HashMap<String, usize>,
    pub total_incident_frequency: u64,
}

pub struct SuiteManager {
    pub root: PathBuf,
    pub cases_dir: PathBuf,
    pub cases: Vec<TetherCase>,
}

impl SuiteManager {
    pub fn init(suite_root: impl AsRef<Path>, spec: &TetherSpec) -> Result<Self, TetherError> {
        let root = suite_root.as_ref().to_path_buf();
        let cases_dir = root.join("cases");
        fs::create_dir_all(&cases_dir)?;

        let spec_path = root.join("tether.toml");
        if !spec_path.exists() {
            let toml_str = toml::to_string_pretty(spec)
                .map_err(|e| TetherError::General(format!("Failed to serialize spec: {e}")))?;
            fs::write(spec_path, toml_str)?;
        }

        Ok(Self {
            root,
            cases_dir,
            cases: Vec::new(),
        })
    }

    pub fn load_or_create(suite_root: impl AsRef<Path>) -> Result<Self, TetherError> {
        let root = suite_root.as_ref().to_path_buf();
        let cases_dir = root.join("cases");
        fs::create_dir_all(&cases_dir)?;

        let mut cases = Vec::new();
        if let Ok(entries) = fs::read_dir(&cases_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let content = fs::read_to_string(&path)?;
                    if let Ok(case) = serde_json::from_str::<TetherCase>(&content) {
                        cases.push(case);
                    }
                }
            }
        }

        Ok(Self {
            root,
            cases_dir,
            cases,
        })
    }

    pub fn save_case(&self, case: &TetherCase) -> Result<(), TetherError> {
        let filename = format!("{}.json", case.id);
        let path = self.cases_dir.join(filename);
        let content = serde_json::to_string_pretty(case)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn save_all(&self) -> Result<(), TetherError> {
        for case in &self.cases {
            self.save_case(case)?;
        }
        Ok(())
    }

    pub fn find_case(&self, id: &str) -> Option<&TetherCase> {
        self.cases.iter().find(|c| c.id == id)
    }

    pub fn find_case_mut(&mut self, id: &str) -> Option<&mut TetherCase> {
        self.cases.iter_mut().find(|c| c.id == id)
    }

    pub fn label_case(
        &mut self,
        id: &str,
        category: &str,
        expect: Vec<ExpectAssertion>,
        is_blocker: bool,
    ) -> Result<&TetherCase, TetherError> {
        let case = self
            .find_case_mut(id)
            .ok_or_else(|| TetherError::CaseNotFound(id.to_string()))?;

        if case.state == CaseState::Candidate {
            case.transition(CaseState::Labeled, None)?;
        }
        case.category = category.to_string();
        case.expect = expect;
        case.is_blocker = is_blocker;
        case.transition(CaseState::Active, None)?;
        case.updated_at = "2026-11-04".to_string();

        let case_clone = case.clone();
        self.save_case(&case_clone)?;
        Ok(self.find_case(id).expect("case exists"))
    }

    pub fn retire_case(&mut self, id: &str, reason: &str) -> Result<(), TetherError> {
        let case = self
            .find_case_mut(id)
            .ok_or_else(|| TetherError::CaseNotFound(id.to_string()))?;

        case.transition(CaseState::Retired, Some(reason))?;
        case.notes = format!("Retired: {reason}");
        case.updated_at = "2026-11-04".to_string();
        let case_clone = case.clone();
        self.save_case(&case_clone)?;
        Ok(())
    }

    pub fn close_failure(
        &self,
        failure_ref: &str,
        baseline_failed: bool,
        candidate_passed: bool,
    ) -> Result<(), TetherError> {
        // Enforce the hard closing loop invariant:
        // 1. There must be an active regression test case tracking this failure.
        let matching_case = self.cases.iter().find(|c| {
            if c.state != CaseState::Active {
                return false;
            }
            if c.id == failure_ref {
                return true;
            }
            match &c.source {
                crate::case::CaseSource::HarnessRun { run_id, .. } => run_id == failure_ref,
                crate::case::CaseSource::ProductionLog { log_id, .. } => log_id == failure_ref,
                _ => false,
            }
        });

        let case = match matching_case {
            Some(c) => c,
            None => {
                return Err(TetherError::InvariantViolation(format!(
                    "Refusing to close failure '{failure_ref}': no active regression test case found in the suite. You must capture and activate a test case before marking a production incident resolved."
                )));
            }
        };

        // 2. The reproduction test case must reproduce the bug on baseline (baseline must fail).
        if !baseline_failed {
            return Err(TetherError::InvariantViolation(format!(
                "Refusing to close failure '{failure_ref}': the regression test case '{}' did NOT fail on the baseline run. A valid reproduction case must fail on the buggy implementation.",
                case.id
            )));
        }

        // 3. The candidate fix must pass the reproduction test case.
        if !candidate_passed {
            return Err(TetherError::InvariantViolation(format!(
                "Refusing to close failure '{failure_ref}': the candidate fix failed regression test case '{}'. The bug remains unresolved.",
                case.id
            )));
        }

        Ok(())
    }

    pub fn stats(&self) -> SuiteStats {
        let total_cases = self.cases.len();
        let mut active_cases = 0;
        let mut candidate_cases = 0;
        let mut labeled_cases = 0;
        let mut retired_cases = 0;
        let mut dev_cases = 0;
        let mut held_out_cases = 0;
        let mut blocker_cases = 0;
        let mut total_incident_frequency: u64 = 0;
        let mut category_counts = HashMap::new();

        for case in &self.cases {
            match case.state {
                CaseState::Active => active_cases += 1,
                CaseState::Candidate => candidate_cases += 1,
                CaseState::Labeled => labeled_cases += 1,
                CaseState::Retired => retired_cases += 1,
            }

            if case.split == "held_out" {
                held_out_cases += 1;
            } else {
                dev_cases += 1;
            }

            if case.is_blocker {
                blocker_cases += 1;
            }

            total_incident_frequency = total_incident_frequency.saturating_add(case.frequency);
            *category_counts.entry(case.category.clone()).or_insert(0) += 1;
        }

        SuiteStats {
            total_cases,
            active_cases,
            candidate_cases,
            labeled_cases,
            retired_cases,
            dev_cases,
            held_out_cases,
            blocker_cases,
            category_counts,
            total_incident_frequency,
        }
    }
}
