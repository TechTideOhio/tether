use crate::gate::ReleaseGateReport;
use serde_json::json;

pub fn render_reference_loop_table() -> String {
    let mut out = String::new();
    out.push_str(
        "=== TideOS Eval Kit (Tool 15): Continuous Evaluation & Release Invariants ===\n\n",
    );
    out.push_str("| Loop Invariant | Purpose | Enforcement Engine | Failure Consequence |\n");
    out.push_str("|---|---|---|---|\n");
    out.push_str(
        "| 1. Bug Reproduction Case | Production bug cannot close without test | tether close <failure-id> | Blocker: Refuses closure |\n",
    );
    out.push_str(
        "| 2. Secret-Scrubbed Capture | Strip all API keys, PII, paths | src/redact.rs Fail-closed | RedactionFailure exception |\n",
    );
    out.push_str(
        "| 3. SimHash Deduplication | Cluster near-duplicate crashes | SimHash64 Hamming dist <= 3 | Merges frequency counter |\n",
    );
    out.push_str(
        "| 4. Held-Out Anti-Overfit | Detect prompt tuning cherry-picking | 20% Held-Out Split | BlockedHeldOutRegression |\n",
    );
    out.push_str(
        "| 5. Suite Freshness | Prevent stagnant eval suite releases | min_new_cases_per_release | BlockedSuiteStale |\n",
    );
    out.push_str(
        "| 6. Category Regression Floor | Prevent stealth degradation | category.<name>.floor | BlockedCategoryRegression |\n",
    );
    out.push_str(
        "| 7. Cryptographic Sealing | Prevent tampering with cases | sha256-framed-v1 lockfile | Drift mismatch fails gate |\n",
    );
    out.push_str(
        "| 8. Sequential Provenance | Immutable loop history chain | SHA-256 Merkle Ledger | Chain breach fails gate |\n",
    );
    out
}

pub fn render_terminal_release_report(report: &ReleaseGateReport) -> String {
    let mut out = String::new();
    out.push_str(
        "\n================================================================================\n",
    );
    out.push_str(
        "                       TIDEOS TOOL 15: TETHER RELEASE GATE                      \n",
    );
    out.push_str(
        "================================================================================\n",
    );
    out.push_str(&format!(
        "Verdict:             {}\n",
        report.verdict.display_badge()
    ));
    out.push_str(&format!("Summary:             {}\n", report.summary));
    out.push_str(&format!("Baseline Model:      {}\n", report.baseline_model));
    out.push_str(&format!(
        "Candidate Model:     {}\n",
        report.candidate_model
    ));
    out.push_str(&format!("Total Cases Replayed: {}\n", report.total_cases));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    out.push_str(&format!(
        "Overall Pass Rate:   Baseline: {:.1}% [{:.1}%, {:.1}%] -> Candidate: {:.1}% [{:.1}%, {:.1}%]\n",
        report.baseline_pass_rate * 100.0,
        report.baseline_wilson_ci.0 * 100.0,
        report.baseline_wilson_ci.1 * 100.0,
        report.candidate_pass_rate * 100.0,
        report.candidate_wilson_ci.0 * 100.0,
        report.candidate_wilson_ci.1 * 100.0,
    ));
    out.push_str(&format!(
        "Delta Pass Rate:     {:+5.1}% (Bootstrap 95% CI: [{:+5.1}%, {:+5.1}%])\n",
        report.delta_pass_rate * 100.0,
        report.bootstrap_delta_ci.0 * 100.0,
        report.bootstrap_delta_ci.2 * 100.0,
    ));
    out.push_str(&format!(
        "McNemar Discordance: b(base win) = {}, c(cand win) = {} -> exact p-value = {:.4}\n",
        report.discordant_b, report.discordant_c, report.mcnemar_p_value,
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    out.push_str(&format!(
        "Dev Partition:       Baseline: {:.1}%  -> Candidate: {:.1}%\n",
        report.dev_baseline_rate * 100.0,
        report.dev_candidate_rate * 100.0,
    ));
    out.push_str(&format!(
        "Held-Out Partition:  Baseline: {:.1}%  -> Candidate: {:.1}%\n",
        report.held_out_baseline_rate * 100.0,
        report.held_out_candidate_rate * 100.0,
    ));
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    out.push_str("CATEGORY BREAKDOWN:\n");
    out.push_str(&format!(
        "{:<24} | {:>9} | {:>9} | {:>8} | {:>6} | {:<7} | {:<20}\n",
        "Category", "Baseline", "Candidate", "Delta", "Floor", "Status", "Details"
    ));
    out.push_str(&format!("{:-<90}\n", ""));
    for cat in &report.category_evaluations {
        out.push_str(&format!(
            "{:<24} | {:>8.1}% | {:>8.1}% | {:>+7.1}% | {:>5.1}% | {:<7} | {:<20}\n",
            cat.category,
            cat.baseline_rate * 100.0,
            cat.candidate_rate * 100.0,
            cat.delta * 100.0,
            cat.floor * 100.0,
            if cat.passed { "PASS" } else { "FAIL" },
            cat.reason,
        ));
    }
    out.push_str(
        "--------------------------------------------------------------------------------\n",
    );
    out.push_str(&format!(
        "Freshness:           {} new production failure cases locked in (minimum {} required)\n",
        report.new_cases_incorporated, report.required_new_cases
    ));
    out.push_str(&format!(
        "Blocker Failures:    {} blocker regressions\n",
        report.blocker_violations
    ));
    out.push_str(
        "================================================================================\n",
    );
    out
}

pub fn render_markdown_release_memo(report: &ReleaseGateReport) -> String {
    let mut out = String::new();
    out.push_str("# Model Release Evaluation Memo\n\n");
    out.push_str(&format!(
        "**Verdict:** `{}`\n\n",
        report.verdict.display_badge()
    ));
    out.push_str(&format!("**Summary:** {}\n\n", report.summary));
    out.push_str("## Core Metrics Comparison\n\n");
    out.push_str("| Metric | Baseline Model | Candidate Model | Delta | Gate Status |\n");
    out.push_str("|---|:---:|:---:|:---:|:---:|\n");
    out.push_str(&format!(
        "| Overall Pass Rate | {:.1}% | {:.1}% | {:+.1}% | {} |\n",
        report.baseline_pass_rate * 100.0,
        report.candidate_pass_rate * 100.0,
        report.delta_pass_rate * 100.0,
        if report.passed { "PASS" } else { "FAIL" },
    ));
    out.push_str(&format!(
        "| Dev Partition Pass Rate | {:.1}% | {:.1}% | {:+.1}% | {} |\n",
        report.dev_baseline_rate * 100.0,
        report.dev_candidate_rate * 100.0,
        (report.dev_candidate_rate - report.dev_baseline_rate) * 100.0,
        "INFO",
    ));
    out.push_str(&format!(
        "| Held-Out 20% Partition | {:.1}% | {:.1}% | {:+.1}% | {} |\n",
        report.held_out_baseline_rate * 100.0,
        report.held_out_candidate_rate * 100.0,
        (report.held_out_candidate_rate - report.held_out_baseline_rate) * 100.0,
        if report.held_out_candidate_rate >= report.held_out_baseline_rate - 0.02 {
            "PASS"
        } else {
            "FAIL"
        },
    ));
    out.push_str(&format!(
        "| McNemar p-value | N/A | N/A | p = {:.4} | {} |\n",
        report.mcnemar_p_value,
        if report.mcnemar_p_value < 0.05 {
            "SIGNIFICANT"
        } else {
            "NOT SIGNIFICANT"
        },
    ));
    out.push_str("\n## Category Analysis\n\n");
    out.push_str(
        "| Category | Baseline Pass Rate | Candidate Pass Rate | Delta | Floor | Status |\n",
    );
    out.push_str("|---|:---:|:---:|:---:|:---:|:---:|\n");
    for cat in &report.category_evaluations {
        out.push_str(&format!(
            "| {} | {:.1}% | {:.1}% | {:+.1}% | {:.1}% | {} |\n",
            cat.category,
            cat.baseline_rate * 100.0,
            cat.candidate_rate * 100.0,
            cat.delta * 100.0,
            cat.floor * 100.0,
            if cat.passed { "PASS" } else { "FAIL" },
        ));
    }
    out.push_str("\n## Loop Invariants & Freshness Audit\n\n");
    out.push_str(&format!(
        "- **New Production Cases Incorporated:** {} (Policy requirement: {})\n",
        report.new_cases_incorporated, report.required_new_cases
    ));
    out.push_str(&format!(
        "- **Blocker Regressions:** {}\n",
        report.blocker_violations
    ));
    out.push_str(&format!(
        "- **Paired Discordance (b / c):** {} / {}\n",
        report.discordant_b, report.discordant_c
    ));
    out.push_str("\n---\n*Generated by TideOS Eval Kit Tool 15 (tether)*\n");
    out
}

pub fn render_mermaid_diagram() -> String {
    r"flowchart LR
    P[Production Failures] --> C[tether capture: Redact + SimHash]
    C --> K[Candidate Cases]
    K --> L[tether label: Assign Categories + Assertions]
    L --> S[(Regression Suite: 80% Dev / 20% Held-Out)]
    S --> LK[tether lock: sha256-framed-v1]
    LK --> R[tether replay: Full Suite Evaluation]
    M[New Model Release] --> R
    R --> G{tether release Gate}
    G -->|Passes Floors + Held-Out| W[SwitchApproved]
    G -->|No Significant Delta| H[HoldNoSignificantDiff]
    G -->|Overfit or Category Regression| B[Blocked]
"
    .to_string()
}

pub fn generate_otel_spans(report: &ReleaseGateReport) -> serde_json::Value {
    json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    { "key": "service.name", "value": { "stringValue": "tether" } },
                    { "key": "tideos.tool_number", "value": { "intValue": 15 } }
                ]
            },
            "scopeSpans": [{
                "scope": { "name": "tether.release_gate" },
                "spans": [{
                    "traceId": "184b76ff6db646f288f5c255aa8f1230",
                    "spanId": "tethergate000001",
                    "name": "model_release_evaluation",
                    "kind": 1,
                    "attributes": [
                        { "key": "tether.verdict", "value": { "stringValue": format!("{:?}", report.verdict) } },
                        { "key": "tether.baseline_model", "value": { "stringValue": report.baseline_model.clone() } },
                        { "key": "tether.candidate_model", "value": { "stringValue": report.candidate_model.clone() } },
                        { "key": "tether.baseline_pass_rate", "value": { "doubleValue": report.baseline_pass_rate } },
                        { "key": "tether.candidate_pass_rate", "value": { "doubleValue": report.candidate_pass_rate } },
                        { "key": "tether.delta_pass_rate", "value": { "doubleValue": report.delta_pass_rate } },
                        { "key": "tether.mcnemar_p_value", "value": { "doubleValue": report.mcnemar_p_value } },
                        { "key": "tether.held_out_candidate_rate", "value": { "doubleValue": report.held_out_candidate_rate } },
                        { "key": "tether.new_cases_count", "value": { "intValue": report.new_cases_incorporated as i64 } }
                    ]
                }]
            }]
        }]
    })
}
