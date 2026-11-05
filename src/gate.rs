use crate::replay::ReplaySuiteReport;
use crate::spec::TetherSpec;
use crate::stats::{exact_mcnemar_p_value, paired_bootstrap_ci, wilson_score_interval};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TetherVerdict {
    SwitchApproved,
    HoldNoSignificantDifference,
    BlockedCategoryRegression,
    BlockedHeldOutRegression,
    BlockedSuiteStale,
    BlockedBlockerFailure,
}

impl TetherVerdict {
    pub fn is_approved(&self) -> bool {
        matches!(self, TetherVerdict::SwitchApproved)
    }

    pub fn display_badge(&self) -> &'static str {
        match self {
            TetherVerdict::SwitchApproved => "[APPROVED] SwitchApproved",
            TetherVerdict::HoldNoSignificantDifference => "[HOLD] HoldNoSignificantDifference",
            TetherVerdict::BlockedCategoryRegression => "[BLOCKED] CategoryRegression",
            TetherVerdict::BlockedHeldOutRegression => "[BLOCKED] HeldOutOverfitRegression",
            TetherVerdict::BlockedSuiteStale => "[BLOCKED] SuiteStaleStagnant",
            TetherVerdict::BlockedBlockerFailure => "[BLOCKED] BlockerFailure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryComparison {
    pub category: String,
    pub baseline_rate: f64,
    pub candidate_rate: f64,
    pub delta: f64,
    pub floor: f64,
    pub max_allowed_drop: f64,
    pub passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseGateReport {
    pub verdict: TetherVerdict,
    pub passed: bool,
    pub summary: String,
    pub baseline_model: String,
    pub candidate_model: String,
    pub total_cases: usize,
    pub baseline_pass_rate: f64,
    pub baseline_wilson_ci: (f64, f64),
    pub candidate_pass_rate: f64,
    pub candidate_wilson_ci: (f64, f64),
    pub delta_pass_rate: f64,
    pub bootstrap_delta_ci: (f64, f64, f64),
    pub mcnemar_p_value: f64,
    pub discordant_b: usize,
    pub discordant_c: usize,
    pub dev_baseline_rate: f64,
    pub dev_candidate_rate: f64,
    pub held_out_baseline_rate: f64,
    pub held_out_candidate_rate: f64,
    pub category_evaluations: Vec<CategoryComparison>,
    pub blocker_violations: usize,
    pub new_cases_incorporated: usize,
    pub required_new_cases: usize,
}

pub fn evaluate_release_gate(
    spec: &TetherSpec,
    baseline: &ReplaySuiteReport,
    candidate: &ReplaySuiteReport,
    new_cases_count: usize,
) -> ReleaseGateReport {
    let mut baseline_bools = Vec::new();
    let mut candidate_bools = Vec::new();

    let mut cand_results_map = HashMap::new();
    for r in &candidate.results {
        cand_results_map.insert(r.case_id.as_str(), r);
    }

    let mut b_count = 0; // base true, cand false
    let mut c_count = 0; // base false, cand true
    let mut blocker_violations = 0;

    for b_res in &baseline.results {
        if let Some(c_res) = cand_results_map.get(b_res.case_id.as_str()) {
            baseline_bools.push(b_res.passed);
            candidate_bools.push(c_res.passed);

            if b_res.passed && !c_res.passed {
                b_count += 1;
                if c_res.is_blocker {
                    blocker_violations += 1;
                }
            } else if !b_res.passed && c_res.passed {
                c_count += 1;
            }
        }
    }

    let n = baseline_bools.len();
    let baseline_wilson = wilson_score_interval(baseline.passed_cases, baseline.total_cases, 1.96);
    let candidate_wilson =
        wilson_score_interval(candidate.passed_cases, candidate.total_cases, 1.96);

    let bootstrap_ci = paired_bootstrap_ci(&baseline_bools, &candidate_bools, 1000, 0x184b76ff);
    let mcnemar_p = exact_mcnemar_p_value(b_count, c_count);
    let delta = candidate.pass_rate - baseline.pass_rate;

    // Check categories
    let mut category_evaluations = Vec::new();
    let mut category_fail = false;

    for (cat_name, cat_spec) in &spec.category {
        let base_rate = baseline
            .category_pass_rates
            .get(cat_name)
            .copied()
            .unwrap_or(0.0);
        let cand_rate = candidate
            .category_pass_rates
            .get(cat_name)
            .copied()
            .unwrap_or(0.0);
        let cat_delta = cand_rate - base_rate;

        let floor_ok = cand_rate >= cat_spec.floor_pass_rate;
        let drop_ok = cat_delta >= -cat_spec.max_drop;
        let passed = floor_ok && drop_ok;

        if !passed {
            category_fail = true;
        }

        let reason = if !floor_ok {
            format!(
                "Floor breached: {cand_rate:.3} < {floor:.3}",
                floor = cat_spec.floor_pass_rate
            )
        } else if !drop_ok {
            format!(
                "Max drop exceeded: delta {cat_delta:.3} < -{max:.3}",
                max = cat_spec.max_drop
            )
        } else {
            "Passed".to_string()
        };

        category_evaluations.push(CategoryComparison {
            category: cat_name.clone(),
            baseline_rate: base_rate,
            candidate_rate: cand_rate,
            delta: cat_delta,
            floor: cat_spec.floor_pass_rate,
            max_allowed_drop: cat_spec.max_drop,
            passed,
            reason,
        });
    }

    // Check held-out split regression (anti-overfitting check)
    let held_out_regression = if candidate.held_out_cases > 0 {
        let held_delta = candidate.held_out_pass_rate - baseline.held_out_pass_rate;
        candidate.held_out_pass_rate < spec.gate.min_held_out_pass_rate
            || (spec.gate.require_held_out_win_or_tie && held_delta < -spec.gate.max_drop)
    } else {
        false
    };

    // Check suite staleness
    let suite_stale = new_cases_count < spec.loop_policy.min_new_cases_per_release;

    // Determine verdict
    let (verdict, summary) = if blocker_violations > 0 {
        (
            TetherVerdict::BlockedBlockerFailure,
            format!("Release blocked: candidate failed {blocker_violations} critical blocker cases that passed on baseline"),
        )
    } else if held_out_regression {
        (
            TetherVerdict::BlockedHeldOutRegression,
            format!(
                "Release blocked: candidate regressed on held-out test partition ({:.1}% vs baseline {:.1}%), indicating prompt tuning overfitting",
                candidate.held_out_pass_rate * 100.0,
                baseline.held_out_pass_rate * 100.0
            ),
        )
    } else if category_fail {
        (
            TetherVerdict::BlockedCategoryRegression,
            "Release blocked: one or more category performance floors or drop limits were breached"
                .to_string(),
        )
    } else if suite_stale {
        (
            TetherVerdict::BlockedSuiteStale,
            format!(
                "Release blocked: suite is stale. Only {new_cases_count} new production failure cases incorporated (minimum {} required by policy). Close the loop before debating model switches.",
                spec.loop_policy.min_new_cases_per_release
            ),
        )
    } else if delta > 0.01 && mcnemar_p < spec.gate.mcnemar_alpha {
        (
            TetherVerdict::SwitchApproved,
            format!(
                "Switch approved: candidate model demonstrates statistically significant improvement (+{:.1}% overall, McNemar p = {:.4})",
                delta * 100.0,
                mcnemar_p
            ),
        )
    } else if delta >= -spec.gate.max_drop && candidate.pass_rate >= spec.gate.min_overall_pass_rate
    {
        (
            TetherVerdict::SwitchApproved,
            format!(
                "Switch approved: candidate meets all quality floors and held-out bounds ({:.1}% pass rate, delta {:.1}%)",
                candidate.pass_rate * 100.0,
                delta * 100.0
            ),
        )
    } else {
        (
            TetherVerdict::HoldNoSignificantDifference,
            format!(
                "Hold: candidate model does not provide a significant improvement (delta {:.1}%, McNemar p = {:.4}). Maintain current baseline.",
                delta * 100.0,
                mcnemar_p
            ),
        )
    };

    let passed = verdict.is_approved();

    ReleaseGateReport {
        verdict,
        passed,
        summary,
        baseline_model: baseline.model.clone(),
        candidate_model: candidate.model.clone(),
        total_cases: n,
        baseline_pass_rate: baseline.pass_rate,
        baseline_wilson_ci: baseline_wilson,
        candidate_pass_rate: candidate.pass_rate,
        candidate_wilson_ci: candidate_wilson,
        delta_pass_rate: delta,
        bootstrap_delta_ci: bootstrap_ci,
        mcnemar_p_value: mcnemar_p,
        discordant_b: b_count,
        discordant_c: c_count,
        dev_baseline_rate: baseline.dev_pass_rate,
        dev_candidate_rate: candidate.dev_pass_rate,
        held_out_baseline_rate: baseline.held_out_pass_rate,
        held_out_candidate_rate: candidate.held_out_pass_rate,
        category_evaluations,
        blocker_violations,
        new_cases_incorporated: new_cases_count,
        required_new_cases: spec.loop_policy.min_new_cases_per_release,
    }
}
