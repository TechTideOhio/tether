# Changelog

All notable changes to `tether` are documented in this file.

## [0.1.0] - 2026-11-04

### Added
- TideOS Eval Kit Tool 15: Close the loop from production failures to labeled regression cases, full suite replay, and fail-closed model release gating.
- Continuous failure capture with automated credential redaction and tokenization.
- Dual-fingerprint deduplication engine (canonical SHA-256 and 64-bit SimHash word 3-shingles).
- Invariant enforcement: refusal to mark production failures closed without active reproducing test cases.
- Full suite offline replay with pluggable runner subprocess and deterministic assertion engine.
- Paired model release gate with SplitMix64 bootstrap confidence intervals, exact McNemar test, and Wilson score intervals.
- Held-out 20% validation partition preventing prompt tuning and fine-tuning suite overfitting.
- Append-only sequential SHA-256 Merkle loop provenance chaining (tether-run-v1).
- Cryptographic lockfile engine (sha256-framed-v1).
- Soft Factory 8-gate repository hygiene auditor.
- Terminal scorecard, Markdown step summary, Mermaid loop diagrams, and OpenTelemetry span exports.
