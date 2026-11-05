# Contributing to tether

We welcome contributions to `tether`, Tool 15 of the TideOS Eval Kit.

## Engineering Standards

1. Pure Rust: `#![forbid(unsafe_code)]` at all times. Zero C/C++ FFI.
2. Pedantic Clippy: All code must compile with zero warnings under `cargo clippy --all-targets -- -D warnings`.
3. Strict Typography: Zero em-dashes and zero en-dashes across all files. Use standard hyphens, colons, or parentheses.
4. Deterministic Gating: All tests and verification gates must run offline without external network or service requirements.
5. JSON Envelopes: All commands must support `--json` output formatted as `HarnessEnvelope<T>`.

## Pull Request Checklist

- Run `cargo fmt --all -- --check`
- Run `cargo clippy --all-targets -- -D warnings`
- Run `cargo test --all-targets`
- Run `cargo run -- audit .`
