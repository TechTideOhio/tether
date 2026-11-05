use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tether::capture::{process_failure_ingest, CaptureOutcome, FailureIngestPayload};
use tether::case::{CaseState, ExpectAssertion, TetherCase};
use tether::dedupe::{compute_exact_hash, compute_simhash64, hamming_distance};
use tether::gate::{evaluate_release_gate, TetherVerdict};
use tether::ledger::TetherLedger;
use tether::lockfile::TetherLockfile;
use tether::redact::scrub_text;
use tether::replay::{evaluate_replay_against_suite, load_offline_replay_records};
use tether::repo_audit::audit_repository;
use tether::spec::{CategorySpec, GateConfig, LoopConfig, SuiteConfig, TetherSpec};
use tether::suite::SuiteManager;

fn fixture_spec() -> TetherSpec {
    let mut category = HashMap::new();
    category.insert(
        "security_firewall".to_string(),
        CategorySpec {
            baseline_pass_rate: Some(1.00),
            floor_pass_rate: 1.00,
            max_drop: 0.00,
            description: "Secret and credential protection".to_string(),
        },
    );
    category.insert(
        "loop_containment".to_string(),
        CategorySpec {
            baseline_pass_rate: Some(0.90),
            floor_pass_rate: 0.85,
            max_drop: 0.03,
            description: "Circuit breaker and retry loop bounds".to_string(),
        },
    );
    category.insert(
        "tool_execution".to_string(),
        CategorySpec {
            baseline_pass_rate: Some(0.90),
            floor_pass_rate: 0.85,
            max_drop: 0.03,
            description: "Tool dispatch and schema verification".to_string(),
        },
    );
    category.insert(
        "prompt_alignment".to_string(),
        CategorySpec {
            baseline_pass_rate: Some(0.85),
            floor_pass_rate: 0.80,
            max_drop: 0.04,
            description: "Format obedience and schema conformity".to_string(),
        },
    );

    TetherSpec {
        suite: SuiteConfig {
            name: "test-suite".to_string(),
            version: "0.1.0".to_string(),
            description: "Integration test suite".to_string(),
            held_out_ratio: 0.20,
        },
        loop_policy: LoopConfig {
            min_new_cases_per_release: 3,
            max_unlabeled_candidates: 10,
            require_reproduction_before_close: true,
        },
        gate: GateConfig {
            min_overall_pass_rate: 0.85,
            min_held_out_pass_rate: 0.80,
            max_drop: 0.02,
            mcnemar_alpha: 0.05,
            require_held_out_win_or_tie: true,
        },
        category,
    }
}

#[test]
fn test_redaction_engine_scrubs_sensitive_data() {
    let text = "User test@example.com ran sk-ant-api03-abcdef1234567890abcdef1234567890 at C:\\Users\\Admin\\project with sk-123456789012345678901234567890 and Bearer eyJhbGciOiJIUzI1NiJ9.abcdef";
    let scrubbed = scrub_text(text).expect("scrub should succeed");

    assert!(!scrubbed.contains("sk-ant-api03"));
    assert!(!scrubbed.contains("test@example.com"));
    assert!(!scrubbed.contains("Admin"));
    assert!(scrubbed.contains("[REDACTED_ANTHROPIC_KEY]"));
    assert!(scrubbed.contains("[REDACTED_EMAIL]"));
    assert!(scrubbed.contains(r"C:\Users\[REDACTED_USER]"));
}

#[test]
fn test_simhash_near_duplicate_clustering() {
    let err1 = "Codex failed at step 42 in file /Users/admin/repos/core.rs: compilation error";
    let err2 = "Codex failed at step 99 in file /Users/admin/repos/core.rs: compilation error";
    let unrelated = "Docker daemon connection refused on port 2375: daemon not running";

    let h1 = compute_simhash64(err1);
    let h2 = compute_simhash64(err2);
    let hu = compute_simhash64(unrelated);

    let dist_near = hamming_distance(h1, h2);
    let dist_far = hamming_distance(h1, hu);

    assert!(
        dist_near <= 3,
        "Near duplicates should have dist <= 3, got {dist_near}"
    );
    assert!(
        dist_far > 10,
        "Unrelated strings should have dist > 10, got {dist_far}"
    );
}

#[test]
fn test_case_state_machine_lifecycle() {
    let mut case = TetherCase {
        id: "tc-test-01".to_string(),
        schema: "tether-case-v1".to_string(),
        state: CaseState::Candidate,
        source: tether::case::CaseSource::Manual {
            author: "test".to_string(),
        },
        fingerprint: tether::case::CaseFingerprint {
            exact: "exact".to_string(),
            shingle: 12345,
        },
        category: "tool_execution".to_string(),
        stratum: "regression".to_string(),
        task: "task".to_string(),
        input_context: None,
        expect: vec![ExpectAssertion::StatusEquals {
            equals: "error".to_string(),
        }],
        weight: 1.0,
        frequency: 1,
        split: "dev".to_string(),
        is_blocker: false,
        created_at: "2026-11-04".to_string(),
        updated_at: "2026-11-04".to_string(),
        notes: String::new(),
    };

    // Candidate -> Labeled -> Active -> Retired
    assert!(case.transition(CaseState::Labeled, None).is_ok());
    assert!(case.transition(CaseState::Active, None).is_ok());
    assert!(case
        .transition(CaseState::Retired, Some("superseded"))
        .is_ok());

    // Retired is terminal: attempting to unretire fails
    assert!(case.transition(CaseState::Active, None).is_err());
    assert!(case.transition(CaseState::Candidate, None).is_err());
}

#[test]
fn test_closing_loop_invariant_enforcement() {
    let temp_dir = tempfile_dir("tether-close-test");
    let spec = fixture_spec();
    let mut suite = SuiteManager::init(&temp_dir, &spec).expect("init suite");

    let payload = FailureIngestPayload {
        source_kind: "harness-run".to_string(),
        run_ref: "run-2026-failure-1".to_string(),
        timestamp: "2026-11-04".to_string(),
        agent: Some("codex".to_string()),
        task: "Fix compilation in core.rs".to_string(),
        summary: "Compilation error: missing module foo".to_string(),
        details: None,
        category_hint: Some("tool_execution".to_string()),
    };

    let outcome =
        process_failure_ingest(payload, &mut suite.cases, 0.20, "tc-close-001".to_string())
            .expect("capture succeeds");

    if let CaptureOutcome::NewCandidate(c) = outcome {
        suite.cases.push(c);
        suite.save_all().expect("saved");
    }

    // 1. Attempting to close with no ACTIVE case (still Candidate) must fail
    let err_unlabeled = suite.close_failure("run-2026-failure-1", true, true);
    assert!(
        err_unlabeled.is_err(),
        "Must reject closure without active case"
    );

    // Promote case to active
    suite
        .label_case(
            "tc-close-001",
            "tool_execution",
            vec![ExpectAssertion::StatusEquals {
                equals: "success".to_string(),
            }],
            false,
        )
        .expect("label succeeds");

    // 2. Attempting to close when baseline DID NOT reproduce bug must fail
    let err_no_repro = suite.close_failure("run-2026-failure-1", false, true);
    assert!(
        err_no_repro.is_err(),
        "Must reject closure if baseline didn't fail"
    );

    // 3. Attempting to close when candidate fix FAILED reproduction must fail
    let err_fix_failed = suite.close_failure("run-2026-failure-1", true, false);
    assert!(
        err_fix_failed.is_err(),
        "Must reject closure if candidate fix failed"
    );

    // 4. Successful closure: active case exists, baseline reproduced (failed), candidate fix passed
    let ok_closed = suite.close_failure("run-2026-failure-1", true, true);
    assert!(
        ok_closed.is_ok(),
        "Closure should succeed when invariant is met"
    );

    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_release_gate_scenarios() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let spec_path = manifest_dir.join("packs/softfactory.toml");
    let spec_content = fs::read_to_string(&spec_path).expect("read spec");
    let spec: TetherSpec = toml::from_str(&spec_content).expect("parse toml");

    let base_records =
        load_offline_replay_records(manifest_dir.join("packs/fixtures/baseline_runs.jsonl"))
            .expect("read baseline");
    let cand_better =
        load_offline_replay_records(manifest_dir.join("packs/fixtures/candidate_better.jsonl"))
            .expect("read better");
    let cand_reg = load_offline_replay_records(
        manifest_dir.join("packs/fixtures/candidate_silent_regression.jsonl"),
    )
    .expect("read regression");
    let cand_overfit = load_offline_replay_records(
        manifest_dir.join("packs/fixtures/candidate_overfit_dev_only.jsonl"),
    )
    .expect("read overfit");

    let mut cases = Vec::new();
    for (idx, r) in base_records.iter().enumerate() {
        let split = if idx % 5 == 0 { "held_out" } else { "dev" };
        cases.push(TetherCase {
            id: r.case_id.clone(),
            schema: "tether-case-v1".to_string(),
            state: CaseState::Active,
            source: tether::case::CaseSource::Manual {
                author: "test".to_string(),
            },
            fingerprint: tether::case::CaseFingerprint {
                exact: compute_exact_hash(&r.case_id),
                shingle: idx as u64,
            },
            category: if r.case_id.contains("sec") {
                "security_firewall".to_string()
            } else if r.case_id.contains("loop") {
                "loop_containment".to_string()
            } else if r.case_id.contains("tool") {
                "tool_execution".to_string()
            } else {
                "prompt_alignment".to_string()
            },
            stratum: "regression".to_string(),
            task: format!("Task for {}", r.case_id),
            input_context: None,
            expect: vec![ExpectAssertion::StatusEquals {
                equals: "success".to_string(),
            }],
            weight: 1.0,
            frequency: 1,
            split: split.to_string(),
            is_blocker: r.case_id.contains("sec"),
            created_at: "2026-11-04".to_string(),
            updated_at: "2026-11-04".to_string(),
            notes: String::new(),
        });
    }

    let base_rep = evaluate_replay_against_suite(&cases, &base_records, "base").expect("eval base");
    let better_rep =
        evaluate_replay_against_suite(&cases, &cand_better, "better").expect("eval better");
    let reg_rep = evaluate_replay_against_suite(&cases, &cand_reg, "reg").expect("eval reg");
    let overfit_rep =
        evaluate_replay_against_suite(&cases, &cand_overfit, "overfit").expect("eval overfit");

    // 1. Better candidate should be approved
    let gate_better = evaluate_release_gate(&spec, &base_rep, &better_rep, 5);
    assert_eq!(gate_better.verdict, TetherVerdict::SwitchApproved);
    assert!(gate_better.passed);

    // 2. Category regression candidate should be blocked
    let gate_reg = evaluate_release_gate(&spec, &base_rep, &reg_rep, 5);
    assert_eq!(gate_reg.verdict, TetherVerdict::BlockedCategoryRegression);
    assert!(!gate_reg.passed);

    // 3. Dev-overfit candidate should be blocked by held-out check
    let gate_overfit = evaluate_release_gate(&spec, &base_rep, &overfit_rep, 5);
    assert_eq!(
        gate_overfit.verdict,
        TetherVerdict::BlockedHeldOutRegression
    );
    assert!(!gate_overfit.passed);

    // 4. Stale suite candidate should be blocked by freshness policy
    let gate_stale = evaluate_release_gate(&spec, &base_rep, &better_rep, 1);
    assert_eq!(gate_stale.verdict, TetherVerdict::BlockedSuiteStale);
    assert!(!gate_stale.passed);
}

#[test]
fn test_lockfile_cryptographic_verification() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let spec_path = manifest_dir.join("packs/softfactory.toml");
    let spec_content = fs::read_to_string(&spec_path).expect("read spec");
    let spec: TetherSpec = toml::from_str(&spec_content).expect("parse toml");

    let cases = vec![TetherCase {
        id: "tc-lock-01".to_string(),
        schema: "tether-case-v1".to_string(),
        state: CaseState::Active,
        source: tether::case::CaseSource::Manual {
            author: "test".to_string(),
        },
        fingerprint: tether::case::CaseFingerprint {
            exact: "exact-hash".to_string(),
            shingle: 9999,
        },
        category: "tool_execution".to_string(),
        stratum: "regression".to_string(),
        task: "task 1".to_string(),
        input_context: None,
        expect: vec![ExpectAssertion::StatusEquals {
            equals: "success".to_string(),
        }],
        weight: 1.0,
        frequency: 1,
        split: "dev".to_string(),
        is_blocker: false,
        created_at: "2026-11-04".to_string(),
        updated_at: "2026-11-04".to_string(),
        notes: String::new(),
    }];

    let lock = TetherLockfile::create(&spec_path, &spec, &cases).expect("lock creation");
    assert!(lock.verify(&spec_path, &cases).is_ok());

    // Tampered case should fail verification
    let mut tampered_cases = cases.clone();
    tampered_cases[0].task = "tampered task".to_string();
    assert!(lock.verify(&spec_path, &tampered_cases).is_err());
}

#[test]
fn test_merkle_ledger_chain_and_tamper_detection() {
    let mut ledger = TetherLedger::new();
    ledger.append("capture", Some("tc-01"), "captured failure", "2026-11-04");
    ledger.append(
        "label",
        Some("tc-01"),
        "labeled tool_execution",
        "2026-11-04",
    );
    ledger.append(
        "close",
        Some("tc-01"),
        "verified reproduction",
        "2026-11-04",
    );

    assert_eq!(ledger.total_entries, 3);
    assert!(ledger.verify_chain().is_ok());

    // Tamper with an entry
    ledger.entries[1].detail = "tampered detail".to_string();
    assert!(ledger.verify_chain().is_err());
}

#[test]
fn test_repository_hygiene_audit_passes_all_8_gates() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report = audit_repository(&manifest_dir);
    assert_eq!(
        report.passed_gates,
        8,
        "All 8 Soft Factory hygiene gates must pass! Failed: {:?}",
        report
            .gates
            .iter()
            .filter(|g| !g.passed)
            .collect::<Vec<_>>()
    );
    assert!(report.passed);
}

fn tempfile_dir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let hash = tether::dedupe::compute_exact_hash(prefix);
    let clean_hash = hash.replace(':', "_");
    let unique = format!("{}-{}-{}", prefix, std::process::id(), clean_hash);
    p.push(unique);
    fs::create_dir_all(&p).ok();
    p
}
