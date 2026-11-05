# tether Agent Guidelines

Instructions for autonomous coding agents working on `Tools/tether`.

## Invariants
- Language: Pure Rust 2021 (MSRV 1.82). Zero external FFI dependencies.
- Safety: Root declaration `#![forbid(unsafe_code)]` in `src/lib.rs` and `src/main.rs`.
- Typography: Strict zero em-dashes and zero en-dashes across all files.
- Testing: Execute tests through `node C:/Users/Admin/TechTide/Tools/agent-harness/q.mjs -- cargo test --manifest-path Tools/tether/Cargo.toml`.
- JSON Envelope: All CLI commands support `--json` emitting canonical `HarnessEnvelope<T>`.
