# VibeSec

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg)](https://streamlit.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Security Scanners](https://img.shields.io/badge/Scanners-Semgrep%20%7C%20Gitleaks%20%7C%20Trivy%20%7C%20Bandit-orange.svg)]()

> **Deterministic Application Security Assessment & Reachability Engine for Modern and AI-Generated Applications**

VibeSec is an automated static application security testing (SAST) and software composition analysis (SCA) platform. It orchestrates industry-standard security scanners, constructs an **Application Security Model (ASM)**, traces inter-procedural attack paths from public HTTP entrypoints to dangerous execution sinks, and prioritizes dependency advisories using static AST call-graph reachability and runtime exposure classification.

All analysis runs passively without executing, compiling, or importing untrusted target code.

---

## Key Capabilities

- **Unified Scanner Orchestration**: Runs Semgrep (custom rule packs + security-audit), Gitleaks, Trivy, Bandit, `pip-audit`, and `npm audit` inside a hardened subprocess sandbox (`shell=False`, scrubbed environment variables, telemetry disabled, 60–90s timeouts, 25 MB capture caps).
- **Application Security Model (ASM)**: Statically reconstructs application routes, URL prefixes, HTTP methods, authentication gates (`PUBLIC` vs. `AUTHENTICATED`), data stores, external API calls, and parameter definitions across Python (FastAPI, Flask, Django) and JavaScript/TypeScript (Express, Next.js).
- **Inter-Procedural Attack Path Taint Analysis**: Traces data flows across 3+ verifiable steps ($\text{source} \rightarrow \text{flow} \rightarrow \text{sink}$) for SQL injection, command/code execution, SSRF, path traversal, IDOR, XSS, deserialization, and LLM prompt injection, producing non-executable canary `curl` verification templates.
- **AST-Validated False-Positive Reduction**: Uses Python AST parsing and a string-aware JS/TS tokenizer to ignore commented-out code and benign environment variable lookups while strictly preserving genuine leaked credentials inside comments/docstrings and evaluating fallback literals.
- **Dependency Reachability, Supply Chain & Exposure Intelligence**: Parses lockfiles (`package-lock.json`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`) with integrity hashes to classify every package:
  - **Exposure Classes**: `RUNTIME_SERVER`, `RUNTIME_BUNDLE`, `TOOLCHAIN_BUILD`, `TOOLCHAIN_DEVSERVER`, `TEST`.
  - **Reachability States**: `CALLED`, `IMPORTED`, `TRANSITIVE_OF_RUNTIME`, `NOT_IMPORTED`.
  - **Supply Chain Checks**: Typosquatting detection with registry evidence, npm alias resolution, hallucinated package checks, CISA KEV / EPSS enrichment, and SPDX license policy evaluation.
- **CVSS-Aligned 0–10 Risk Scoring Engine**: Context-adjusts raw scanner findings using reachability, taint confirmation, authentication context, and deployment exposure to focus developer attention on actionable risks.
- **Standardized Multi-Format Exports**:
  - **Executive PDF Report** (`fpdf2`): Structured risk posture, attack surface metrics, ranked actionable findings, dependency fix plans, and license compliance.
  - **Developer Markdown Report**: Code snippets, CWE/OWASP mappings, filtered findings ledger, and remediation guidance.
  - **OASIS SARIF 2.1.0 Export**: Compliant with IDE and GitHub Code Scanning, using `%SRCROOT%` relative URIs, `primaryLocationLineHash` fingerprints, and `codeFlows` for attack paths.
  - **CycloneDX 1.5 JSON SBOM**: Complete bill of materials with SHA-512/SHA-256 lockfile hashes, hierarchical dependency graph, and VEX reachability analysis (`in_triage`).
- **Streamlined Light-Theme Web Dashboard**: Focused 4-tab interface (`Scan`, `Attack Surface & Paths`, `Dependencies`, `Reports`) supporting up to **1 GB ZIP uploads (50,000 files)** and public GitHub repositories.

---

## Architecture

```
Target Source (ZIP Archive up to 1 GB / Public GitHub URL / CLI Directory)
  │
  ├──► Ingestion & Sandbox Hardening (src/vibesec/extractor.py)
  │       └── Streaming 64 KB decompression, ZipSlip/symlink/bomb guards, binary filter, app profiling
  │
  ├──► Multi-Scanner Orchestration (src/vibesec/scanners/)
  │       ├── Semgrep (custom AST rules + security-audit)
  │       ├── Gitleaks (secrets & credential leakage)
  │       ├── Trivy (CVE vulnerability & misconfiguration scanning)
  │       ├── Bandit (Python AST security checks)
  │       └── pip-audit & npm audit (Lockfile vulnerability analysis)
  │
  ├──► Normalization, Correlation & Internal Checks (normalizer.py, correlator.py, config_exposure.py)
  │       └── String-aware comment/docstring FP filtering, secrets ledger, CWE equivalence dedup
  │
  ├──► Application Security Model & Attack Paths (asm.py, attack_surface.py, taint.py, attack_paths.py)
  │       └── Entrypoint/auth resolution, data stores, 3+ step taint flows, inert canary PoCs
  │
  ├──► SCA Reachability & Supply Chain (dep_graph.py, exposure.py, reachability.py, grouping.py, supply_chain.py)
  │       └── Lockfile hashes, RUNTIME vs TOOLCHAIN vs TEST classification, grouped FixActions
  │
  ├──► Unified Risk Prioritization (src/vibesec/prioritizer.py)
  │       └── Bounded 0–10 CVSS-aligned multiplicative scoring & authoritative risk posture
  │
  └──► Web Dashboard & Multi-Format Exports (app.py, report.py, exports.py, sarif.py, sbom.py)
          ├── Streamlit 4-Tab Portal (Scan, Attack Surface & Paths, Dependencies, Reports)
          ├── Executive PDF Report (fpdf2) & Developer Markdown Report
          ├── OASIS SARIF 2.1.0 (with %SRCROOT% & codeFlows)
          └── CycloneDX 1.5 JSON SBOM (with dependency graph & VEX reachability)
```

For full technical internals, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md), and [Technical Architecture & Internal Working Specification.md](Technical%20Architecture%20&%20Internal%20Working%20Specification.md).

---

## Prerequisites

VibeSec orchestrates external security scanners when available on `PATH`. If any scanner binary is absent, VibeSec records its status cleanly (`SKIPPED` / `DEGRADED`) and completes the assessment with the remaining tools and internal analyzers.

| Tool | Recommended Version | Installation Command |
|---|---|---|
| **Python** | 3.11+ | [python.org](https://www.python.org/) |
| **Node.js & npm** | 18+ / 20+ | [nodejs.org](https://nodejs.org/) |
| **Semgrep** | 1.90+ | `pip install semgrep` |
| **Gitleaks** | 8.18+ | `brew install gitleaks` or [GitHub Releases](https://github.com/gitleaks/gitleaks/releases) |
| **Trivy** | 0.50+ | `brew install trivy` or [Aqua Security Releases](https://github.com/aquasecurity/trivy/releases) |
| **Bandit** | 1.9+ | `pip install bandit` |
| **pip-audit** | 2.7+ | `pip install pip-audit` |

---

## Installation

### Option 1: Install from `requirements.txt`

```bash
git clone https://github.com/epic-aditya/VibeSECURITY.git
cd VibeSECURITY

# Create and activate a virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install pinned runtime dependencies
pip install -r requirements.txt
```

### Option 2: Editable Package Installation

```bash
pip install -e .
vibesec doctor
```

### Option 3: Hardened Non-Root Docker Container

```bash
docker build -t vibesec:latest .
docker run --rm -p 8501:8501 vibesec:latest
```

---

## CLI Usage

VibeSec provides a full-featured CLI (`vibesec`) with CI/CD exit code contracts (`0`: clean, `1`: `--fail-on` threshold breached, `2`: invalid input, `3`: execution error):

### 1. Toolchain Audit (`doctor`)
Check installed security scanners and versions:
```bash
vibesec doctor
```

### 2. Scanning Targets (`scan`)

Scan a local directory (`--dir` or `--path`):
```bash
vibesec scan --dir /path/to/project
```

Scan a ZIP archive and write all report formats into an output directory:
```bash
vibesec scan --zip app.zip --output ./reports
```

Or specify individual report outputs:
```bash
vibesec scan --zip app.zip \
  --pdf report.pdf \
  --markdown report.md \
  --sarif report.sarif \
  --sbom sbom.json
```

Scan a public GitHub repository and enforce a CI/CD quality gate:
```bash
vibesec scan --github https://github.com/owner/repo --fail-on high
```

Filter dependencies by minimum reachability level or print the upgrade plan:
```bash
vibesec scan --dir . --min-reachability IMPORTED --fix-plan
```

### 3. Application Security Model (`asm`) & Attack Paths (`paths`)
```bash
vibesec asm --dir /path/to/project
vibesec paths --dir /path/to/project
```

### 4. Local CLI History (`list`, `show`, `clear`)
```bash
vibesec list
vibesec show 1
vibesec clear --yes
```

---

## Streamlit Web Dashboard

Launch the web portal locally:
```bash
streamlit run app.py
```

### Web Portal Design & Security Controls
- **Exclusive Light Theme**: Configured via `.streamlit/config.toml` and centralized CSS (`#F8FAFC` canvas, `#FFFFFF` cards, Inter + JetBrains Mono typography, zero emojis).
- **Focused Single-Scan Experience**: Streamlined around the active assessment with clean sidebar collapse/expand controls (`<<` / `>>`), no historical clutter, and no redundant toolchain or offline toggles.
- **High-Capacity Streaming ZIP Ingestion**: Supports `.zip` archives up to **1 GB compressed** (`maxUploadSize = 1024` MB), **50,000 files**, and **5 GB uncompressed**, streamed to disk in 8 MB chunks and extracted safely in 64 KB chunks.
- **Archive & Path Hardening**: Rejects Zip Slip traversal, Windows drive letters, symlinks, excessive compression ratios (>100:1 over 50 MB), and executable binaries (`.exe`, `.dll`, `.com`, `.msi`). Masks internal server filesystem paths before rendering or exporting reports.
- **GitHub Ingestion Fallback**: Shallow-clones public HTTPS GitHub URLs and automatically falls back to direct ZIP archive downloads when `git` is unavailable.

### Dashboard Tabs
1. **Scan**: Upload a ZIP archive or enter a public GitHub URL, track live scan progress, inspect severity KPI metrics, filter findings by severity/category/keyword, review actionable cards with code evidence and remediation, and inspect collapsed non-actionable findings.
2. **Attack Surface & Paths**: Inspect total/unauthenticated/state-changing route metrics, discovered endpoints and parameters table, interactive Graphviz Application Map, and ranked attack paths with step-by-step traces and canary `curl` PoCs.
3. **Dependencies**: View license policy compliance counts, grouped upgrade fix plans ordered by runtime exposure and reachability, vulnerable dependency tables, and CycloneDX SBOM component previews.
4. **Reports**: Download the Executive PDF, Developer Markdown, OASIS SARIF 2.1.0, and CycloneDX 1.5 JSON SBOM files, plus preview the rendered Markdown report inline.

### Environment Variables
| Variable | Default | Purpose |
|---|---|---|
| `VIBESEC_OFFLINE` | `0` | Set to `1` to suppress outbound intelligence queries and use local caches / neutral signals. |
| `VIBESEC_DB_PATH` | `~/.vibesec/vibesec.db` | Custom path for CLI SQLite persistence (automatically falls back to `:memory:` if read-only). |

---

## Risk Posture & Scoring Engine

VibeSec evaluates security risks through transparent, bounded mathematical formulations aligned with CVSS v3.1 / v4.0 qualitative severity ratings:

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
  - `NOT_IMPORTED`: `0.15`
- $D$: Deployment exposure multiplier (same as code findings)
- $\text{EPSS}$: Exploit Prediction Scoring System probability ($0.0 - 1.0$). Dropped when unmeasured or offline (multiplier $1.0$, labeled `'not measured'`).
- $\text{KEV\_bonus}$: CISA Known Exploited Vulnerability bonus (`3.0 * D` if listed).

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
├── .streamlit/
│   └── config.toml               # Exclusive light theme & 1 GB upload limit configuration
├── docs/
│   ├── ARCHITECTURE.md           # 10-stage technical data flow & module inventory
│   ├── DESIGN_RATIONALE.md       # CVSS-aligned 0–10 scoring model specification
│   └── THREAT_MODEL.md           # Threat model, sandboxing, and defense-in-depth practices
├── rules/
│   └── vibe_code/
│       ├── vibe_javascript.yaml  # Custom Semgrep AST rules for JS/TS
│       └── vibe_python.yaml      # Custom Semgrep AST rules for Python
├── src/
│   └── vibesec/
│       ├── data/                 # Schemas, CWE mappings, taint catalog, package baselines
│       │   ├── bom-1.5.schema.json
│       │   ├── cwe_equivalence.yaml
│       │   ├── license_policy.yaml
│       │   ├── sarif-schema-2.1.0.json
│       │   ├── taint_catalog.yaml
│       │   ├── toolchain_roots.yaml
│       │   ├── top_npm_packages.json
│       │   └── top_pypi_packages.json
│       ├── scanners/             # Hardened subprocess adapters for external tools
│       │   ├── __init__.py
│       │   ├── bandit_scanner.py
│       │   ├── base.py
│       │   ├── gitleaks.py
│       │   ├── npm_audit.py
│       │   ├── pip_audit.py
│       │   ├── semgrep_scanner.py
│       │   └── trivy.py
│       ├── __init__.py           # Package exports
│       ├── asm.py                # Application Security Model construction
│       ├── attack_paths.py       # Inter-procedural taint path builder & canary PoCs
│       ├── attack_surface.py     # Route heuristics & attack surface mapping
│       ├── cli.py                # Command-line interface & exit code contracts
│       ├── config_exposure.py    # CI/CD, CORS, Dockerfile & config checks
│       ├── correlator.py         # Multi-scanner deduplication & CWE clustering
│       ├── dep_graph.py          # Lockfile dependency graph & hash parser
│       ├── exploit_intel.py      # EPSS & CISA KEV exploit intelligence
│       ├── exports.py            # Markdown & JSON report exporters
│       ├── exposure.py           # Dependency and code exposure classification
│       ├── extractor.py          # Hardened streaming extraction & project profiling
│       ├── grouping.py           # Grouped dependency FixAction planner
│       ├── imports.py            # Static import discovery
│       ├── license_eval.py       # SPDX license compliance evaluator
│       ├── models.py             # Core dataclasses and taxonomies
│       ├── normalizer.py         # Normalization, string-aware JS parser & FP ledger
│       ├── owasp.py              # CWE to OWASP Top 10 (2021) mapping
│       ├── pipeline.py           # 10-stage synchronous scan orchestrator
│       ├── prioritizer.py        # 0–10 multiplicative risk scoring & posture engine
│       ├── reachability.py       # Static AST call-graph reachability analyzer
│       ├── report.py             # Executive PDF report builder (fpdf2)
│       ├── sarif.py              # OASIS SARIF 2.1.0 generator
│       ├── sbom.py               # CycloneDX 1.5 JSON SBOM builder
│       ├── secrets_intel.py      # Secret intelligence & placeholder detection
│       ├── storage.py            # SQLite CLI persistence with :memory: fallback
│       ├── supply_chain.py       # Typosquatting & hallucinated package detection
│       └── taint.py              # Inter-procedural AST taint propagation engine
├── app.py                        # Streamlit 4-tab light-theme web application
├── Dockerfile                    # Hardened unprivileged container (UID 1000)
├── .dockerignore                 # Docker build context exclusions
├── packages.txt                  # System apt packages (graphviz) for Streamlit Cloud
├── pyproject.toml                # Build system & Hatchling configuration
├── requirements.txt              # Pinned runtime Python dependencies
├── Technical Architecture & Internal Working Specification.md
├── vibesec_sbom.json             # CycloneDX 1.5 JSON self-SBOM
├── SECURITY.md                   # Vulnerability disclosure policy
├── CONTRIBUTING.md               # Contribution guidelines
├── CHANGELOG.md                  # Release change ledger
├── LICENSE                       # Apache License 2.0
├── README.md                     # Project overview & usage guide
└── .gitignore                    # Git exclusions
```

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
