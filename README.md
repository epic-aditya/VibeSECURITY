# VibeSec

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Security Scanners](https://img.shields.io/badge/Scanners-Semgrep%20%7C%20Gitleaks%20%7C%20Trivy%20%7C%20Bandit-orange.svg)]()

> **Deterministic Application Security Assessment & Reachability Engine for Modern and AI-Generated Applications**

VibeSec is an automated static application security testing (SAST) and software composition analysis (SCA) platform. It orchestrates industry-standard security scanners, extracts a complete **Application Security Model (ASM)**, traces inter-procedural attack paths from entrypoints to critical execution sinks, and contextualizes third-party dependency vulnerabilities through deterministic reachability and runtime exposure analysis.

All analysis executes safely and deterministically without executing, compiling, or importing untrusted target code.

---

## Key Capabilities

- **Unified Scanner Orchestration**: Coordinates Semgrep (custom rules + security-audit), Gitleaks, Trivy, Bandit, pip-audit, and npm audit into a single normalized findings model.
- **Application Security Model (ASM)**: Automatically reconstructs application routes, URL prefixes, HTTP methods, authentication gates (`PUBLIC` vs `AUTHENTICATED`), and parameter validations across Python (FastAPI, Flask) and JavaScript/TypeScript (Express, Next.js).
- **Inter-Procedural Attack Path Taint Analysis**: Traces source-to-sink data flows from public HTTP entrypoints directly to dangerous execution sinks (SQL injection, code execution, command injection, SSRF, IDOR, and prompt injection), producing safe, non-executable `curl` verification templates.
- **Dependency Reachability & Exposure Classification**: Analyzes project lockfiles (`package-lock.json`, `poetry.lock`, `requirements.txt`) and call graphs to categorize vulnerabilities:
  - **Exposure classes**: `RUNTIME_SERVER`, `RUNTIME_BUNDLE`, `TOOLCHAIN_BUILD`, `TOOLCHAIN_DEVSERVER`, `TEST`.
  - **Reachability states**: `CALLED`, `IMPORTED`, `TRANSITIVE_OF_RUNTIME`, `NOT_IMPORTED`.
- **Single Source of Truth Severity System**: Context-adjusts raw scanner severity using reachability, authentication boundaries, and runtime exposure to reduce false positive alarm fatigue.
- **Standardized Multi-Format Reporting**:
  - **Executive PDF Report**: Structured assessment summarizing risk posture, top findings, attack surface metrics, dependency fix plans, and license reviews.
  - **Developer Markdown Report**: Line-by-line code context, evidence snippets, and actionable remediation steps.
  - **SARIF 2.1.0 Export**: Fully compliant with GitHub Code Scanning, including step-by-step `codeFlows` for attack paths.
  - **CycloneDX 1.5 JSON SBOM**: Standardized Software Bill of Materials complete with vulnerability definitions and analysis status.
- **Interactive Streamlit Web Dashboard**: 4-tab security portal featuring live scan execution, visual attack path graphs, dependency upgrade plans, and downloadable reports.

---

## Architecture

```
Scanned Codebase (Python, JavaScript, TypeScript, Lockfiles)
  │
  ├──► Ingestion & Profiling (src/vibesec/extractor.py)
  │       └── Safe directory/archive extraction; framework & application type detection (server, CLI, library, frontend)
  │
  ├──► Multi-Scanner Orchestration (src/vibesec/scanners/)
  │       ├── Semgrep (custom AST rules + security-audit)
  │       ├── Gitleaks (secrets & credential leakage)
  │       ├── Trivy (CVE vulnerability & misconfiguration scanning)
  │       ├── Bandit (Python AST security checks)
  │       └── pip-audit & npm audit (Lockfile vulnerability analysis)
  │
  ├──► Normalization & Correlation (src/vibesec/normalizer.py, correlator.py)
  │       └── Deduplicates overlapping scanner findings; normalizes CWEs, severities, and locations
  │
  ├──► Application Security Model (src/vibesec/asm.py)
  │       ├── Entrypoints & Route Resolution
  │       ├── Auth State Inference (PUBLIC vs AUTHENTICATED)
  │       └── Datastore, External Network, & Execution Sinks
  │
  ├──► Attack-Path Taint Engine (src/vibesec/attack_paths.py)
  │       ├── Inter-procedural AST taint flows from entrypoints to critical sinks
  │       └── Non-executable verification curl PoC templates
  │
  ├──► SCA Reachability & Fix Intelligence (src/vibesec/exposure.py, reachability.py, grouping.py)
  │       ├── Lockfile graph traversal (RUNTIME vs TOOLCHAIN vs TEST)
  │       └── Minimal breaking-change upgrade recommendations
  │
  └──► Reporting & Storage (src/vibesec/report.py, exports.py, sarif.py, sbom.py, storage.py)
          ├── Executive PDF Report (fpdf2)
          ├── Developer Markdown Report
          ├── GitHub SARIF 2.1.0 (with codeFlows)
          ├── CycloneDX 1.5 JSON SBOM
          └── Local SQLite Scan History (~/.vibesec/vibesec.db)
```

---

## Prerequisites

VibeSec orchestrates external security scanners when available on your `PATH`. For full multi-scanner coverage, install the following tools:

| Tool | Recommended Version | Installation Command |
|---|---|---|
| **Python** | 3.11+ | [python.org](https://www.python.org/) |
| **Node.js & npm** | 18+ / 20+ | [nodejs.org](https://nodejs.org/) |
| **Semgrep** | 1.90+ | `pip install semgrep` |
| **Gitleaks** | 8.18+ | `brew install gitleaks` or [GitHub Releases](https://github.com/gitleaks/gitleaks/releases) |
| **Trivy** | 0.50+ | `brew install trivy` or [Aqua Security Releases](https://github.com/aquasecurity/trivy/releases) |
| **Bandit** | 1.7+ | `pip install bandit` |
| **pip-audit** | 2.7+ | `pip install pip-audit` |

*Note: If any scanner is missing, VibeSec gracefully records its status as `SKIPPED` or `DEGRADED` and completes the scan using the remaining tools without crashing.*

---

## Installation

### Option 1: Quick Install via `requirements.txt`

```bash
git clone https://github.com/epic-aditya/VibeSECURITY.git
cd VibeSECURITY

# Create and activate a virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Editable Package Installation

```bash
pip install -e .
```

After installation, verify that the CLI is accessible:

```bash
vibesec doctor
```

---

## CLI Usage

VibeSec provides an intuitive command-line interface:

### 1. Toolchain Audit (`doctor`)
Inspect the availability and versions of all underlying security scanners:
```bash
vibesec doctor
```

### 2. Scanning a Target (`scan`)

Scan a local directory:
```bash
vibesec scan --dir /path/to/project
```

Scan a ZIP archive and generate all 4 report formats:
```bash
vibesec scan --zip app.zip \
  --pdf report.pdf \
  --markdown report.md \
  --sarif report.sarif \
  --sbom sbom.json
```

Scan a remote GitHub repository:
```bash
vibesec scan --github https://github.com/org/repo
```

Fail CI/CD pipeline if any critical or high finding is detected:
```bash
vibesec scan --dir . --fail-on high
```

Filter dependencies by minimum reachability level:
```bash
vibesec scan --dir . --min-reachability IMPORTED
```

### 3. Application Security Model (`asm`)
Inspect discovered HTTP entrypoints, authentication requirements, and sinks in JSON format:
```bash
vibesec asm --dir /path/to/project
```

### 4. Attack Paths (`paths`)
Output proven taint flow attack paths from public routes to sensitive sinks:
```bash
vibesec paths --dir /path/to/project
```

### 5. Managing Scan History (`list`, `show`, `clear`)
```bash
# List all previous scan runs recorded in local storage
vibesec list

# Inspect findings from a specific scan ID
vibesec show 1

# Clear scan history transactionally
vibesec clear
```

---

## Streamlit Web Dashboard & Cloud Deployment

### 1. Running Locally
Launch the browser-based security assessment portal:

```bash
streamlit run app.py
```

### 2. Deployment on Streamlit Community Cloud & Docker
VibeSec is fully hardened for cloud and containerized deployment:
- **Primary Input**: Browser-based ZIP archive upload with defense-in-depth security guards against directory traversal, symlinks, zip bombs (ratio > 100:1), and malicious executable binaries.
- **GitHub Ingestion**: Shallow clones public repositories or falls back to direct HTTPS archive downloads when `git` binary is not installed in the container.
- **Path Isolation**: Uploaded archives extract into isolated ephemeral directories; internal server paths are never exposed to users or in exported reports.
- **Ephemeral Storage Resilience**: Scan history utilizes SQLite with automatic fallback to in-memory mode if the filesystem is read-only.
- **Graceful Scanner Degradation**: When optional external binaries (Gitleaks, Trivy) are absent from the environment, VibeSec records `SKIPPED` tool status and proceeds with internal SAST, AST taint, and configuration exposure analyzers without failure.

### 3. Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `VIBESEC_ALLOW_LOCAL_PATH` | `0` | Enable local filesystem path scanning in the web UI (useful for self-hosted instances). |
| `VIBESEC_DB_PATH` | `~/.vibesec/vibesec.db` | Custom filesystem path for SQLite scan record storage. |

### 4. Interactive Tabs

The portal is designed with a clean light theme featuring 4 focused production sections:

1. **Scan**: Configure target sources (ZIP upload or GitHub repo URL), trigger scans with real-time execution progress, and inspect the findings ledger with actionable cards, code evidence, and remediation advice.
2. **Attack Surface & Paths**: Review discovered entrypoints, authentication states, parameter validations, application map graph visualizer, and ranked attack paths with step-by-step traces.
3. **Dependencies**: Inspect lockfile packages, license compliance summaries, and prioritized dependency upgrade plans ordered by runtime exposure and reachability.
4. **Reports**: Generate and download structured PDF executive reports, Developer Markdown files, GitHub-compatible SARIF files, and CycloneDX 1.5 JSON SBOMs.

---

## Risk Posture & Scoring Engine

VibeSec evaluates security risks through transparent, evidence-backed mathematical formulations rather than opaque heuristics:

<!-- SCORING_FORMULA:START -->
### Code & Secret Findings Formula (0–10 Multiplicative Scale)
$$\text{Score} = \min(10.0, \text{base} \cdot \text{Conf} \cdot T \cdot A \cdot D \cdot S_{\text{asset}})$$ 

- $\text{base}$: CVSS base score ($0.0 - 10.0$) if available, otherwise mapped from raw severity:
  - CRITICAL: `9.5`, HIGH: `7.5`, MEDIUM: `5.0`, LOW: `2.0`, INFO: `0.0`
- $\text{Conf}$: Confidence factor $= 0.6 + 0.4 \times \text{confidence}$ (range: `0.6 - 1.0`)
- $T$: Taint / reachability factor:
  - `1.0` for proven taint flow or non-sink rules (secrets, config, license)
  - `0.75` for unconfirmed code sinks without proven user input flow
- $A$: Authentication exposure context:
  - Public / unauthenticated: `1.0`
  - Unknown context: `0.9`
  - Authenticated: `0.75`
- $D$: Deployment exposure multiplier:
  - `RUNTIME_SERVER` / `RUNTIME_BUNDLE`: `1.0`
  - `UNKNOWN`: `0.7`
  - `TOOLCHAIN_BUILD`: `0.35`
  - `TOOLCHAIN_DEVSERVER`: `0.25`
  - `TEST`: `0.2`
- $S_{\text{asset}}$: Sensitive asset multiplier (`1.15` if credentials/PII/tokens, else `1.0`)

### Attack Path Formula (0–10 Scale)
$$\text{Path Score} = 10 \times \text{Impact}(\text{sink}) \times \text{Exposure}(\text{auth}) \times \text{Confidence}$$ 
- **Impact**: Code/Command Execution `1.0`, SQL Injection `0.9`, Deserialization `0.85`, SSRF/Path Traversal `0.7`, IDOR `0.75`, LLM Prompt Injection `0.6`, XSS `0.5`.
- **Exposure**: Public `1.0`, Unknown `0.8`, Authenticated `0.5`.

### Dependency Vulnerability Formula (0–10 Scale)
$$\text{Dependency Score} = \min(10.0, \text{base} \cdot R \cdot D \cdot (1 + 0.3 \cdot \text{EPSS}) + \text{KEV\_bonus})$$ 

- $\text{base}$: CVSS base score ($0.0 - 10.0$) or severity base score map
- $R$: Reachability status factor:
  - `CALLED`: `1.0`
  - `IMPORTED`: `0.75`
  - `UNKNOWN`: `0.5`
  - `TRANSITIVE_OF_RUNTIME`: `0.4`
  - `TOOLCHAIN`: `0.25`
  - `NOT_IMPORTED`: `0.15` *(demoted to LOW or below, never hidden)*
- $D$: Deployment exposure multiplier (same as code findings)
- $\text{EPSS}$: Exploit Prediction Scoring System probability ($0.0 - 1.0$). Dropped when unmeasured or offline (multiplier $1.0$, labeled 'not measured').
- $\text{KEV\_bonus}$: CISA Known Exploited Vulnerability bonus (`3.0 \times D` if listed). Invariant: CALLED in RUNTIME and in CISA KEV is guaranteed $\ge 7.0$ (HIGH).

### Unified Severity Buckets (CVSS-Aligned)
| Score Range | Severity Bucket | Action Priority |
|---|---|---|
| $[9.0, 10.0]$ | **CRITICAL** | Immediate remediation |
| $[7.0, 9.0)$ | **HIGH** | Required fix before production deployment |
| $[4.0, 7.0)$ | **MEDIUM** | Scheduled backlog remediation |
| $(0.0, 4.0)$ | **LOW** | Informational / low-exposure hardening |
| $0.0$ | **INFO** | Informational observation |
<!-- SCORING_FORMULA:END -->

---

## Project Structure

```
VibeSECURITY/
├── docs/
│   ├── ARCHITECTURE.md           # 10-stage technical data flow & architecture
│   ├── DESIGN_RATIONALE.md       # CVSS-aligned 0–10 scoring model specification
│   └── THREAT_MODEL.md           # Threat model, sandboxing, and defenses
├── rules/
│   └── vibe_code/
│       ├── vibe_javascript.yaml  # Custom Semgrep AST rules for JS/TS
│       └── vibe_python.yaml      # Custom Semgrep AST rules for Python
├── src/
│   └── vibesec/
│       ├── scanners/             # Subprocess adapters for external tools
│       │   ├── bandit_scanner.py
│       │   ├── base.py
│       │   ├── gitleaks.py
│       │   ├── npm_audit.py
│       │   ├── pip_audit.py
│       │   ├── semgrep_scanner.py
│       │   └── trivy.py
│       ├── data/
│       │   └── sarif-schema-2.1.0.json # OASIS SARIF validation schema
│       ├── asm.py                # Application Security Model construction
│       ├── attack_paths.py       # Inter-procedural taint tracing
│       ├── cli.py                # Command-line interface definitions
│       ├── config_exposure.py    # CI/CD and configuration exposure checks
│       ├── correlator.py         # Multi-scanner finding deduplication
│       ├── dep_graph.py          # Lockfile dependency graph builder
│       ├── exploit_intel.py      # EPSS & CISA KEV exploit intelligence
│       ├── exports.py            # Markdown report generation
│       ├── exposure.py           # Dependency and code exposure classification
│       ├── extractor.py          # Ingestion and framework detection
│       ├── grouping.py           # Dependency fix action planning
│       ├── license_eval.py       # SPDX license compliance evaluator
│       ├── models.py             # Core dataclasses and taxonomies
│       ├── normalizer.py         # Scanner output normalization
│       ├── pipeline.py           # End-to-end scan orchestrator
│       ├── prioritizer.py        # Context-adjusted risk scoring
│       ├── reachability.py       # AST call-graph reachability analyzer
│       ├── report.py             # Executive PDF report builder (fpdf2)
│       ├── sarif.py              # GitHub SARIF 2.1.0 generator
│       ├── sbom.py               # CycloneDX 1.5 JSON SBOM builder
│       └── storage.py            # SQLite scan record persistence
├── app.py                        # Streamlit 4-tab web application
├── Dockerfile                    # Hardened unprivileged container (UID 1000)
├── pyproject.toml                # Build system & package configuration
├── requirements.txt              # Production Python package requirements
├── Technical Architecture & Internal Working Specification.md
├── vibesec_sbom.json             # CycloneDX 1.5 JSON self-SBOM
├── SECURITY.md                   # Vulnerability disclosure policy
├── CONTRIBUTING.md               # Contribution guidelines
├── CHANGELOG.md                  # Release change ledger
├── README.md                     # Comprehensive documentation
└── .gitignore                    # Git exclusions
```

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
