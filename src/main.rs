#![forbid(unsafe_code)]

use clap::{Args, Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use tether::capture::{
    ingest_harness_result, process_failure_ingest, CaptureOutcome, FailureIngestPayload,
};
use tether::case::ExpectAssertion;
use tether::envelope::{EnvelopeStatus, HarnessEnvelope};
use tether::gate::evaluate_release_gate;
use tether::ledger::TetherLedger;
use tether::lockfile::TetherLockfile;
use tether::replay::{
    evaluate_replay_against_suite, execute_runner_command, load_offline_replay_records,
};
use tether::repo_audit::audit_repository;
use tether::report::{
    generate_otel_spans, render_markdown_release_memo, render_reference_loop_table,
    render_terminal_release_report,
};
use tether::spec::TetherSpec;
use tether::suite::SuiteManager;

#[derive(Parser, Debug)]
#[command(
    name = "tether",
    about = "TideOS Eval Kit (Tool 15): Close the loop - production failures to labeled regression cases, full suite replay, and model release gating",
    version
)]
pub struct Cli {
    #[arg(
        long,
        default_value = "true",
        help = "Ring terminal audio alert bell on failure"
    )]
    pub bell: bool,

    #[arg(long, help = "Emit machine-readable JSON HarnessEnvelope")]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Display the continuous eval and model release loop reference table")]
    Table,

    #[command(about = "Initialize a new regression test suite and configuration")]
    Init(InitArgs),

    #[command(about = "Capture, redact, and fingerprint a production failure incident")]
    Capture(CaptureArgs),

    #[command(about = "Label and activate a candidate regression test case")]
    Label(LabelArgs),

    #[command(about = "Retire an obsolete test case with provenance reason")]
    Retire(RetireArgs),

    #[command(about = "Enforce invariant: close a failure incident with active test proof")]
    Close(CloseArgs),

    #[command(about = "Display statistics, coverage, and incident frequency of the suite")]
    Stats(StatsArgs),

    #[command(about = "Replay full suite offline or through an external runner subprocess")]
    Replay(ReplayArgs),

    #[command(about = "Evaluate paired model release gate against full regression suite")]
    Release(ReleaseArgs),

    #[command(about = "Cryptographically seal the evaluation suite and specification")]
    Lock(LockArgs),

    #[command(about = "Verify the cryptographic lockfile against suite cases and spec")]
    Verify(VerifyArgs),

    #[command(about = "Manage and verify the append-only SHA-256 Merkle loop ledger")]
    Ledger(LedgerArgs),

    #[command(about = "Audit repository hygiene against Soft Factory 8-gate standards")]
    Audit(AuditArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Optional template specification to copy")]
    pub spec: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CaptureArgs {
    #[arg(long, help = "Path to harness result.json or failure log file")]
    pub from: Option<PathBuf>,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Manual task text if not ingesting from file")]
    pub task: Option<String>,

    #[arg(long, help = "Manual failure summary if not ingesting from file")]
    pub summary: Option<String>,

    #[arg(long, help = "Optional category hint for initial categorization")]
    pub category: Option<String>,
}

#[derive(Args, Debug)]
pub struct LabelArgs {
    #[arg(long, help = "Case ID to label (e.g. tc-2026-11-04-0001)")]
    pub case: String,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Category to assign")]
    pub category: String,

    #[arg(
        long,
        default_value = "error",
        help = "Expected status assertion (e.g. error, success)"
    )]
    pub expect_status: String,

    #[arg(long, help = "Optional expected substring in output")]
    pub expect_contains: Option<String>,

    #[arg(long, help = "Optional forbidden regex pattern in output")]
    pub expect_regex_absent: Option<String>,

    #[arg(long, help = "Mark as critical blocker severity")]
    pub blocker: bool,
}

#[derive(Args, Debug)]
pub struct RetireArgs {
    #[arg(long, help = "Case ID to retire")]
    pub case: String,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Reason for retiring case")]
    pub reason: String,
}

#[derive(Args, Debug)]
pub struct CloseArgs {
    #[arg(long, help = "Production failure reference or run ID to close")]
    pub failure_id: String,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Confirmation that baseline failed on reproduction")]
    pub baseline_failed: bool,

    #[arg(long, help = "Confirmation that candidate fix passed reproduction")]
    pub candidate_passed: bool,
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,
}

#[derive(Args, Debug)]
pub struct ReplayArgs {
    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(long, help = "Offline JSONL replay records file")]
    pub runs: Option<PathBuf>,

    #[arg(long, help = "External runner subprocess command")]
    pub runner: Option<String>,

    #[arg(long, default_value = "candidate-model", help = "Model identifier")]
    pub model: String,
}

#[derive(Args, Debug)]
pub struct ReleaseArgs {
    #[arg(long, help = "Path to tether.toml specification")]
    pub spec: PathBuf,

    #[arg(long, help = "Path to baseline replay runs JSONL")]
    pub baseline: PathBuf,

    #[arg(long, help = "Path to candidate replay runs JSONL")]
    pub candidate: PathBuf,

    #[arg(long, help = "Optional suite directory to verify freshness")]
    pub suite: Option<PathBuf>,

    #[arg(long, help = "Optional output markdown release memo path")]
    pub memo: Option<PathBuf>,

    #[arg(long, help = "Optional output OpenTelemetry JSON spans path")]
    pub otel: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct LockArgs {
    #[arg(long, help = "Path to tether.toml specification")]
    pub spec: PathBuf,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,

    #[arg(
        long,
        default_value = "tether.lock.json",
        help = "Output lockfile destination"
    )]
    pub output: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(
        long,
        default_value = "tether.lock.json",
        help = "Path to lockfile to verify"
    )]
    pub lockfile: PathBuf,

    #[arg(long, help = "Path to tether.toml specification")]
    pub spec: PathBuf,

    #[arg(long, default_value = "evals/suite", help = "Suite root directory")]
    pub suite: PathBuf,
}

#[derive(Args, Debug)]
pub struct LedgerArgs {
    #[arg(
        long,
        default_value = "ledger.jsonl",
        help = "Path to append-only Merkle ledger file"
    )]
    pub ledger: PathBuf,

    #[arg(long, help = "Verify cryptographic integrity of all chained entries")]
    pub verify: bool,
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[arg(
        default_value = ".",
        help = "Repository root directory to audit for Soft Factory standards"
    )]
    pub path: PathBuf,
}

fn ring_terminal_bell() {
    eprint!("\x07");
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match execute_command(&cli) {
        Ok(code) => code,
        Err(err) => {
            if cli.bell {
                ring_terminal_bell();
            }
            if cli.json {
                let env = HarnessEnvelope::error(
                    format!("Command failed: {err}"),
                    vec!["Inspect error logs and check arguments".to_string()],
                    Vec::new(),
                    serde_json::json!({ "error": format!("{err}") }),
                );
                if let Ok(serialized) = serde_json::to_string_pretty(&env) {
                    println!("{serialized}");
                }
            } else {
                eprintln!("\n[ERROR] {err}\n");
            }
            ExitCode::FAILURE
        }
    }
}

fn execute_command(cli: &Cli) -> anyhow::Result<ExitCode> {
    match &cli.command {
        Commands::Table => {
            let table = render_reference_loop_table();
            if cli.json {
                let env = HarnessEnvelope::success("Loop invariants table", Vec::new(), table);
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("{table}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Init(args) => {
            let spec = if let Some(spec_path) = &args.spec {
                let content = fs::read_to_string(spec_path)?;
                toml::from_str::<TetherSpec>(&content)?
            } else {
                TetherSpec {
                    suite: tether::spec::SuiteConfig {
                        name: "softfactory-continuous-suite".to_string(),
                        version: "0.1.0".to_string(),
                        description: "Continuous regression eval suite".to_string(),
                        held_out_ratio: 0.20,
                    },
                    loop_policy: tether::spec::LoopConfig::default(),
                    gate: tether::spec::GateConfig::default(),
                    category: std::collections::HashMap::new(),
                }
            };

            let suite = SuiteManager::init(&args.suite, &spec)?;
            let msg = format!("Initialized suite at {}", suite.root.display());

            if cli.json {
                let env = HarnessEnvelope::success(
                    msg,
                    vec![suite.root.display().to_string()],
                    serde_json::json!({ "root": suite.root.display().to_string() }),
                );
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[SUCCESS] {msg}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Capture(args) => {
            let payload = if let Some(from_path) = &args.from {
                ingest_harness_result(from_path, None)?
            } else if let (Some(task), Some(summary)) = (&args.task, &args.summary) {
                FailureIngestPayload {
                    source_kind: "manual".to_string(),
                    run_ref: "manual-input".to_string(),
                    timestamp: "2026-11-04".to_string(),
                    agent: None,
                    task: task.clone(),
                    summary: summary.clone(),
                    details: None,
                    category_hint: args.category.clone(),
                }
            } else {
                anyhow::bail!("Must supply either --from <FILE> or both --task and --summary");
            };

            let mut suite = SuiteManager::load_or_create(&args.suite)?;
            let next_seq = suite.cases.len() + 1;
            let next_id = format!("tc-2026-11-04-{next_seq:04}");

            let outcome = process_failure_ingest(payload, &mut suite.cases, 0.20, next_id)?;

            match outcome {
                CaptureOutcome::NewCandidate(case) => {
                    suite.save_case(&case)?;
                    let summary = format!(
                        "Captured new candidate case '{}' (category: {}, split: {})",
                        case.id, case.category, case.split
                    );
                    if cli.json {
                        let env = HarnessEnvelope::success(
                            &summary,
                            vec![format!("cases/{}.json", case.id)],
                            &case,
                        );
                        println!("{}", serde_json::to_string_pretty(&env)?);
                    } else {
                        println!("[SUCCESS] {summary}");
                    }
                }
                CaptureOutcome::MergedDuplicate {
                    case_id,
                    new_frequency,
                    reason,
                } => {
                    suite.save_all()?;
                    let summary = format!(
                        "Merged duplicate into existing case '{case_id}' (new frequency: {new_frequency}, reason: {reason})"
                    );
                    if cli.json {
                        let env = HarnessEnvelope::success(
                            &summary,
                            Vec::new(),
                            serde_json::json!({
                                "case_id": case_id,
                                "frequency": new_frequency,
                                "reason": reason
                            }),
                        );
                        println!("{}", serde_json::to_string_pretty(&env)?);
                    } else {
                        println!("[MERGED] {summary}");
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Label(args) => {
            let mut suite = SuiteManager::load_or_create(&args.suite)?;
            let mut expect = Vec::new();
            expect.push(ExpectAssertion::StatusEquals {
                equals: args.expect_status.clone(),
            });
            if let Some(contains) = &args.expect_contains {
                expect.push(ExpectAssertion::Contains {
                    text: contains.clone(),
                });
            }
            if let Some(absent) = &args.expect_regex_absent {
                expect.push(ExpectAssertion::RegexAbsent {
                    pattern: absent.clone(),
                });
            }

            let labeled = suite.label_case(&args.case, &args.category, expect, args.blocker)?;
            let summary = format!(
                "Promoted case '{}' to active (category: {}, blocker: {})",
                labeled.id, labeled.category, labeled.is_blocker
            );

            if cli.json {
                let env = HarnessEnvelope::success(
                    &summary,
                    vec![format!("cases/{}.json", labeled.id)],
                    labeled,
                );
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[SUCCESS] {summary}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Retire(args) => {
            let mut suite = SuiteManager::load_or_create(&args.suite)?;
            suite.retire_case(&args.case, &args.reason)?;
            let summary = format!("Retired case '{}': {}", args.case, args.reason);

            if cli.json {
                let env = HarnessEnvelope::success(&summary, Vec::new(), serde_json::json!({}));
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[RETIRED] {summary}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Close(args) => {
            let suite = SuiteManager::load_or_create(&args.suite)?;
            suite.close_failure(
                &args.failure_id,
                args.baseline_failed,
                args.candidate_passed,
            )?;
            let summary = format!(
                "Verified closing loop invariant for failure '{}': reproduction test succeeded on fix",
                args.failure_id
            );

            if cli.json {
                let env = HarnessEnvelope::success(&summary, Vec::new(), serde_json::json!({}));
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[SUCCESS] {summary}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Stats(args) => {
            let suite = SuiteManager::load_or_create(&args.suite)?;
            let stats = suite.stats();

            if cli.json {
                let env = HarnessEnvelope::success("Suite statistics", Vec::new(), &stats);
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("=== Evaluation Suite Statistics ===");
                println!("Total Cases:           {}", stats.total_cases);
                println!("Active Cases:          {}", stats.active_cases);
                println!("Candidate Cases:       {}", stats.candidate_cases);
                println!("Labeled Cases:         {}", stats.labeled_cases);
                println!("Retired Cases:         {}", stats.retired_cases);
                println!("Dev Split Cases:       {}", stats.dev_cases);
                println!("Held-Out Split Cases:  {}", stats.held_out_cases);
                println!("Blocker Cases:         {}", stats.blocker_cases);
                println!("Total Incidents Track: {}", stats.total_incident_frequency);
                println!("Categories Breakdown:");
                for (cat, count) in &stats.category_counts {
                    println!("  - {cat:<24} : {count} cases");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Replay(args) => {
            let suite = SuiteManager::load_or_create(&args.suite)?;
            let records = if let Some(runs_path) = &args.runs {
                load_offline_replay_records(runs_path)?
            } else if let Some(runner_cmd) = &args.runner {
                let mut run_recs = Vec::new();
                for case in &suite.cases {
                    let rec = execute_runner_command(runner_cmd, case)?;
                    run_recs.push(rec);
                }
                run_recs
            } else {
                anyhow::bail!("Must specify either --runs <JSONL> or --runner <CMD>");
            };

            let report = evaluate_replay_against_suite(&suite.cases, &records, &args.model)?;
            let summary = format!(
                "Replayed suite for model '{}': pass rate {:.1}% ({}/{} cases)",
                report.model,
                report.pass_rate * 100.0,
                report.passed_cases,
                report.total_cases
            );

            if cli.json {
                let env = HarnessEnvelope::success(&summary, Vec::new(), &report);
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("=== Replay Report for {} ===", report.model);
                println!("Pass Rate:       {:.1}%", report.pass_rate * 100.0);
                println!("Dev Split:       {:.1}%", report.dev_pass_rate * 100.0);
                println!("Held-Out Split:  {:.1}%", report.held_out_pass_rate * 100.0);
                println!(
                    "Passed / Total:  {} / {}",
                    report.passed_cases, report.total_cases
                );
                println!("Blocker Fails:   {}", report.blocker_failures);
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Release(args) => {
            let spec_content = fs::read_to_string(&args.spec)?;
            let spec: TetherSpec = toml::from_str(&spec_content)?;

            let baseline_records = load_offline_replay_records(&args.baseline)?;
            let candidate_records = load_offline_replay_records(&args.candidate)?;

            let (cases, new_cases_count) = if let Some(suite_path) = &args.suite {
                let suite = SuiteManager::load_or_create(suite_path)?;
                let count = suite
                    .cases
                    .iter()
                    .filter(|c| c.created_at.as_str() >= "2026-11-01")
                    .count();
                (suite.cases, count)
            } else {
                // Synthesize cases from baseline records if no suite directory was passed
                let mut synth_cases = Vec::new();
                for (idx, r) in baseline_records.iter().enumerate() {
                    let split = if idx % 5 == 0 { "held_out" } else { "dev" };
                    synth_cases.push(tether::case::TetherCase {
                        id: r.case_id.clone(),
                        schema: "tether-case-v1".to_string(),
                        state: tether::case::CaseState::Active,
                        source: tether::case::CaseSource::Manual {
                            author: "synth".to_string(),
                        },
                        fingerprint: tether::case::CaseFingerprint {
                            exact: r.case_id.clone(),
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
                (synth_cases, 5) // 5 mock new cases
            };

            let base_report =
                evaluate_replay_against_suite(&cases, &baseline_records, "baseline-model")?;
            let cand_report =
                evaluate_replay_against_suite(&cases, &candidate_records, "candidate-model")?;

            let gate_report =
                evaluate_release_gate(&spec, &base_report, &cand_report, new_cases_count);

            if let Some(memo_path) = &args.memo {
                let markdown = render_markdown_release_memo(&gate_report);
                fs::write(memo_path, markdown)?;
            }

            if let Some(otel_path) = &args.otel {
                let otel = generate_otel_spans(&gate_report);
                fs::write(otel_path, serde_json::to_string_pretty(&otel)?)?;
            }

            if cli.json {
                let status = if gate_report.passed {
                    EnvelopeStatus::Success
                } else {
                    EnvelopeStatus::Error
                };
                let env = HarnessEnvelope {
                    status,
                    summary: gate_report.summary.clone(),
                    next_actions: if gate_report.passed {
                        vec!["Proceed with production model rollout".to_string()]
                    } else {
                        vec!["Block deployment and inspect regressed cases".to_string()]
                    },
                    artifacts: Vec::new(),
                    data: &gate_report,
                };
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                let terminal_rep = render_terminal_release_report(&gate_report);
                println!("{terminal_rep}");
            }

            if gate_report.passed {
                Ok(ExitCode::SUCCESS)
            } else {
                if cli.bell {
                    ring_terminal_bell();
                }
                Ok(ExitCode::FAILURE)
            }
        }

        Commands::Lock(args) => {
            let spec_content = fs::read_to_string(&args.spec)?;
            let spec: TetherSpec = toml::from_str(&spec_content)?;
            let suite = SuiteManager::load_or_create(&args.suite)?;

            let lock = TetherLockfile::create(&args.spec, &spec, &suite.cases)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            lock.save(&args.output)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let summary = format!(
                "Sealed suite with {} cases into {}",
                suite.cases.len(),
                args.output.display()
            );

            if cli.json {
                let env = HarnessEnvelope::success(
                    &summary,
                    vec![args.output.display().to_string()],
                    &lock,
                );
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[SUCCESS] {summary}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify(args) => {
            let lock = TetherLockfile::load(&args.lockfile).map_err(|e| anyhow::anyhow!("{e}"))?;
            let suite = SuiteManager::load_or_create(&args.suite)?;

            lock.verify(&args.spec, &suite.cases)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let summary = format!(
                "Verified cryptographic integrity of suite ({}/{} cases match)",
                suite.cases.len(),
                lock.total_cases
            );

            if cli.json {
                let env = HarnessEnvelope::success(
                    &summary,
                    vec![args.lockfile.display().to_string()],
                    serde_json::json!({ "verified": true }),
                );
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("[VERIFIED] {summary}");
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Ledger(args) => {
            let ledger = TetherLedger::load(&args.ledger).map_err(|e| anyhow::anyhow!("{e}"))?;

            if args.verify {
                ledger.verify_chain().map_err(|e| anyhow::anyhow!("{e}"))?;
                let summary = format!(
                    "Verified append-only Merkle ledger ({} chained entries, head: {})",
                    ledger.total_entries, ledger.head_hash
                );
                if cli.json {
                    let env = HarnessEnvelope::success(&summary, Vec::new(), &ledger);
                    println!("{}", serde_json::to_string_pretty(&env)?);
                } else {
                    println!("[VERIFIED] {summary}");
                }
            } else {
                println!(
                    "Ledger entries: {}, Head hash: {}",
                    ledger.total_entries, ledger.head_hash
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Audit(args) => {
            let report = audit_repository(&args.path);

            if cli.json {
                let status = if report.passed {
                    EnvelopeStatus::Success
                } else {
                    EnvelopeStatus::Error
                };
                let env = HarnessEnvelope {
                    status,
                    summary: format!(
                        "Repository hygiene audit: {}/{} gates passed",
                        report.passed_gates, report.total_gates
                    ),
                    next_actions: if report.passed {
                        vec!["All Soft Factory standards met".to_string()]
                    } else {
                        vec!["Resolve failing audit gates".to_string()]
                    },
                    artifacts: Vec::new(),
                    data: &report,
                };
                println!("{}", serde_json::to_string_pretty(&env)?);
            } else {
                println!("=== Soft Factory Repository Hygiene Audit ===");
                println!(
                    "Result: {}/{} gates passed\n",
                    report.passed_gates, report.total_gates
                );
                for (i, gate) in report.gates.iter().enumerate() {
                    let mark = if gate.passed { "[PASS]" } else { "[FAIL]" };
                    println!(
                        "{:>2}. {:<6} {:<42} : {}",
                        i + 1,
                        mark,
                        gate.name,
                        gate.details
                    );
                }
                println!();
            }

            if report.passed {
                Ok(ExitCode::SUCCESS)
            } else {
                if cli.bell {
                    ring_terminal_bell();
                }
                Ok(ExitCode::FAILURE)
            }
        }
    }
}
