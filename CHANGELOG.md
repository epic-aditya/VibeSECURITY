# Changelog

All notable changes to the VibeSec project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-13

### Added
- **0–10 Multiplicative Scoring Model**: Replaced legacy additive scoring with a bounded 0–10 model aligned with CVSS v3.1/v4.0. Incorporates confidence, taint reachability, exposure class, authentication context, and sensitive asset multipliers.
- **Reachability-Adjusted Dependency Scoring**: Unimported dependencies (`NOT_IMPORTED`) are demoted to LOW or below ($R=0.15$), keeping them visible in audits while eliminating spurious alert fatigue.
- **Secrets Hardening**:
  - Enforced strict invariant that genuine credentials located inside comments or docstrings are never suppressed.
  - String-aware JavaScript/TypeScript comment tokenizer distinguishing `//` inside string literals or URLs from actual comments.
  - Test-path secret classification with guided remediation.
  - Filtered findings audit ledger tracking every suppressed finding and its exact rule/reason.
- **Zero-Execution Scanner Hardening**:
  - Hard 60–90 second subprocess timeouts with graceful process termination.
  - Environment scrubbing removing cloud access tokens, SSH credentials, and telemetry.
  - 25 MB stdout/stderr memory cap to prevent memory exhaustion from verbose tools.
  - Offline network boundary enforcement verified via socket monkeypatching.
  - Multi-stage unprivileged Dockerfile (UID 1000) with tmpfs workspace mount capability.
- **Ingestion & Web Deployment Hardening**:
  - Streaming chunk decompression in ZIP extraction with strict uncompressed byte limit (`MAX_UNCOMPRESSED_BYTES`).
  - Dynamic binary file filtering (`is_binary_file`) checking null bytes and UTF-8 validity.
  - Strict HTTPS GitHub repository URL parser rejecting path traversal and shell metacharacters.
  - Complete elimination of host absolute filesystem paths in scan metadata, dashboard, and exports.
- **Evaluation Benchmark Suite**:
  - 46 paired test cases across 7 CWE categories with formal Dev (26) and held-out Test (20) splits.
  - Automated benchmark runner (`evaluation/run.py`) measuring Bandit, raw Semgrep, component ablations, and full VibeSec engine.
  - Published empirical, uninflated metrics in `evaluation/results/latest.json`.
- **Engine Correctness & Inert Canaries**:
  - Enforced $\ge 3$ traceable steps (source -> flow -> sink) invariant on all generated attack paths.
  - Benign, non-destructive canary strings (`echo vibe_canary`, `' OR '1'='1`) replacing invasive command templates.
  - CWE equivalence clustering consolidating multi-scanner duplicate alerts while preserving lockfile dependency isolation.
- **Standardized Output Formats**:
  - Official OASIS SARIF 2.1.0 schema compliance with relative URIs under `%SRCROOT%`, stable `primaryLocationLineHash` under `partialFingerprints`, and formatted `security-severity` properties.
  - CycloneDX 1.5 JSON SBOM with lockfile integrity hashes (SHA-512/SHA-256) and root-to-component `dependencies` graph.
  - VEX reachability status classification: `NOT_IMPORTED` findings are classified as `in_triage` with reachability taxonomy properties (never `not_affected`).
- **Automated Verification Safety Net**:
  - 8 verification gates in `scripts/verify.py` (compileall, ruff, mypy, pytest with coverage, schema validation, determinism, scanner resilience, headless AppTest).
  - Maintained $\ge 85\%$ line coverage across the 5 core modules.

### Changed
- Streamlit dashboard redesigned to a modern, light-themed 4-tab interface with live progress bars and Tool Status banners.
- Purged legacy viva/defense examination text and retired experimental modules (`autofix`, `llm_explainer`, `study`) to `_archive/`.

### Fixed
- Fixed false-positive comment suppression that incorrectly dismissed hardcoded credentials inside code comments.
- Fixed false-positive detection on harmless prose comments containing security-related keywords.
- Resolved npm alias resolution failure where `npm:target-pkg@version` was flagged as a hallucinated package.
- Fixed typosquatting detector to require low download counts or recent publish dates before alerting.
- Resolved arithmetic discrepancies between executive summary counts and breakdown tables in PDF and Markdown reports.
- Fixed potential Zip Slip path traversal and archive bomb vulnerability in browser ZIP upload.

