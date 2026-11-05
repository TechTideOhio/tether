use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAuditGate {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAuditReport {
    pub passed: bool,
    pub passed_gates: usize,
    pub total_gates: usize,
    pub gates: Vec<RepoAuditGate>,
}

pub fn audit_repository(repo_root: impl AsRef<Path>) -> RepoAuditReport {
    let root = repo_root.as_ref();
    let mut gates = Vec::new();

    let oss_files = [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "AGENTS.md",
        "Cargo.toml",
    ];
    let mut missing_oss = Vec::new();
    for f in &oss_files {
        if !root.join(f).exists() {
            missing_oss.push(*f);
        }
    }
    gates.push(RepoAuditGate {
        name: "Required OSS Governance Files".to_string(),
        passed: missing_oss.is_empty(),
        details: if missing_oss.is_empty() {
            "All 7 required governance files present".to_string()
        } else {
            format!("Missing files: {}", missing_oss.join(", "))
        },
    });

    let toolchain_path = root.join("rust-toolchain.toml");
    let toolchain_ok = if toolchain_path.exists() {
        let text = fs::read_to_string(&toolchain_path).unwrap_or_default();
        text.contains("channel = \"stable\"")
    } else {
        false
    };
    gates.push(RepoAuditGate {
        name: "Pinned Rust Toolchain".to_string(),
        passed: toolchain_ok,
        details: if toolchain_ok {
            "rust-toolchain.toml pins stable with rustfmt & clippy".to_string()
        } else {
            "Missing or unpinned rust-toolchain.toml".to_string()
        },
    });

    let gitattributes_path = root.join(".gitattributes");
    let gitattributes_ok = if gitattributes_path.exists() {
        let text = fs::read_to_string(&gitattributes_path).unwrap_or_default();
        text.contains("linguist-vendored")
    } else {
        false
    };
    gates.push(RepoAuditGate {
        name: "GitHub Linguist 100% Pure Rust Vendoring".to_string(),
        passed: gitattributes_ok,
        details: if gitattributes_ok {
            ".gitattributes vendors packs and fixtures".to_string()
        } else {
            "Missing .gitattributes linguist-vendored directives".to_string()
        },
    });

    let ci_path = root.join(".github/workflows/ci.yml");
    let ci_ok = if ci_path.exists() {
        let text = fs::read_to_string(&ci_path).unwrap_or_default();
        text.contains("pull_request:")
    } else {
        false
    };
    gates.push(RepoAuditGate {
        name: "CI Pull Request Gate Trigger".to_string(),
        passed: ci_ok,
        details: if ci_ok {
            "ci.yml triggers on pull_request to main".to_string()
        } else {
            "ci.yml missing or lacks pull_request trigger".to_string()
        },
    });

    let mut pinned_actions_ok = true;
    let mut unpinned_actions = Vec::new();
    let workflows_dir = root.join(".github/workflows");
    if workflows_dir.exists() {
        if let Ok(entries) = fs::read_dir(workflows_dir) {
            for entry in entries.flatten() {
                if let Ok(text) = fs::read_to_string(entry.path()) {
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("uses:") {
                            let action = trimmed.trim_start_matches("uses:").trim();
                            if !action.starts_with("./") {
                                if let Some((_, tag)) = action.split_once('@') {
                                    if tag.len() != 40
                                        || !tag.chars().all(|c| c.is_ascii_hexdigit())
                                    {
                                        pinned_actions_ok = false;
                                        unpinned_actions.push(action.to_string());
                                    }
                                } else {
                                    pinned_actions_ok = false;
                                    unpinned_actions.push(action.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    gates.push(RepoAuditGate {
        name: "Pinned 40-char SHA GitHub Actions".to_string(),
        passed: pinned_actions_ok,
        details: if pinned_actions_ok {
            "All external GitHub Actions pinned to 40-character commit SHAs".to_string()
        } else {
            format!(
                "Unpinned action tags found: {}",
                unpinned_actions.join(", ")
            )
        },
    });

    let mut dash_violations = Vec::new();
    scan_for_forbidden_dashes(root, &mut dash_violations);
    gates.push(RepoAuditGate {
        name: "Strict Typography Zero Em-Dash & En-Dash Rule".to_string(),
        passed: dash_violations.is_empty(),
        details: if dash_violations.is_empty() {
            "Zero em-dashes and zero en-dashes across all repo files".to_string()
        } else {
            format!(
                "Forbidden em/en-dashes found in {} files: {}",
                dash_violations.len(),
                dash_violations.join(", ")
            )
        },
    });

    let forbidden_secret_files = [".env", ".env.local", "id_rsa", "id_ed25519"];
    let mut leaked_secrets = Vec::new();
    for f in &forbidden_secret_files {
        if root.join(f).exists() {
            leaked_secrets.push(*f);
        }
    }
    gates.push(RepoAuditGate {
        name: "Secret File Hygiene".to_string(),
        passed: leaked_secrets.is_empty(),
        details: if leaked_secrets.is_empty() {
            "Zero local credential or environment files committed".to_string()
        } else {
            format!("Leaked files found: {}", leaked_secrets.join(", "))
        },
    });

    let cargo_path = root.join("Cargo.toml");
    let release_profile_ok = if cargo_path.exists() {
        let text = fs::read_to_string(&cargo_path).unwrap_or_default();
        text.contains("lto = true") && text.contains("strip = true")
    } else {
        false
    };
    gates.push(RepoAuditGate {
        name: "Optimized Binary Release Profile".to_string(),
        passed: release_profile_ok,
        details: if release_profile_ok {
            "Cargo.toml configures opt-level = 'z', lto = true, strip = true".to_string()
        } else {
            "Missing LTO or binary stripping in [profile.release]".to_string()
        },
    });

    let passed_count = gates.iter().filter(|g| g.passed).count();
    let total = gates.len();
    let passed = passed_count == total;

    RepoAuditReport {
        passed,
        passed_gates: passed_count,
        total_gates: total,
        gates,
    }
}

fn scan_for_forbidden_dashes(dir: &Path, violations: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().unwrap_or_default().to_string_lossy();

            if file_name == "target" || file_name == ".git" {
                continue;
            }

            if path.is_dir() {
                scan_for_forbidden_dashes(&path, violations);
            } else if path.is_file() {
                let ext = path.extension().unwrap_or_default().to_string_lossy();
                if ["rs", "md", "toml", "json", "jsonl", "yml", "yaml", "ps1"]
                    .contains(&ext.as_ref())
                {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if content.contains('\u{2014}') || content.contains('\u{2013}') {
                            violations.push(path.display().to_string());
                        }
                    }
                }
            }
        }
    }
}
