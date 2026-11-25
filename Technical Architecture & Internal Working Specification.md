# VibeSec — Comprehensive Technical Architecture & Internal Working Specification

> **Deterministic Application Security Assessment & Reachability Engine for Modern & AI-Generated Software**

---

## 1. Executive Summary & Design Philosophy

**VibeSec** is an automated static application security testing (SAST), software composition analysis (SCA), and attack-surface reachability platform designed specifically to evaluate modern web applications, microservices, and AI-generated codebases.

### 1.1 Core Mission & Purpose
Modern development workflows—especially those utilizing AI coding assistants (e.g., GitHub Copilot, Cursor, Claude, ChatGPT)—frequently introduce predictable security defects:
1. **Hallucinated or Typosquatted Dependencies**: Package names suggested by LLMs that do not exist or resemble popular packages.
2. **Missing Input Validation & Route Authorization**: Endpoints exposed without authentication or authorization guards.
3. **Dangerous Execution Sinks**: Direct concatenation into SQL queries, operating system commands (`shell=True`), eval loops, server-side template engines, and prompt injection vectors in LLM integrations.
4. **Credential & Secret Leakage**: API tokens, private keys, database connection strings, and JWT secrets committed into source code and environment templates.
5. **False-Positive Fatigue**: Traditional SAST scanners flag non-executable comments, docstrings, build scripts, test fixtures, and unreachable library code, overwhelming development teams.

VibeSec solves these problems by pairing industry-standard security scanners with an **inter-procedural AST taint engine**, an automated **Application Security Model (ASM)**, and **dependency reachability analysis**. It normalizes all scanner outputs into a unified data structure, filters out non-executable code without hiding genuine leaked credentials, adjusts risk scores on a bounded 0–10 CVSS-aligned scale based on runtime exposure and authentication boundaries, and outputs standardized multi-format reports.

### 1.2 Core Architectural Invariants
- **Deterministic & Offline-Capable**: Security analysis relies on static analysis, abstract syntax trees (ASTs), string-aware tokenizers, and cached intelligence. Code is evaluated predictably without nondeterministic LLM evaluation in the critical path.
- **Strictly Passive (Zero-Execution Sandbox)**: VibeSec **never compiles, imports, or executes** target code. Analysis inspects source files purely as text, AST nodes, and lockfile data inside isolated subprocesses (`shell=False`, scrubbed environment variables, strict timeouts, and memory caps).
- **Single Source of Truth Scoring**: The executive risk posture statement, severity breakdown, OASIS SARIF export, executive PDF report, Markdown technical report, and Streamlit web dashboard all compute from the exact same bounded 0–10 multiplicative mathematical model.
- **Actionable vs. Non-Actionable Separation**: Findings in test directories, mock fixtures, build scripts, or informational categories are collapsed into per-rule/per-folder summary ledgers (while keeping genuine test-path secrets actionable for credential rotation), keeping primary focus on active production vulnerabilities.

---

## 2. Complete Technology Stack & Toolchain Dependencies

### 2.1 Core Runtime & Languages
- **Python 3.11+** (Tested through Python 3.14): Primary runtime for the pipeline, orchestrator, AST analyzers, reporting engines, CLI, and Streamlit web dashboard.
- **JavaScript / TypeScript**: Target language support for route detection (Express, Next.js), lockfile parsing (`package.json`, `package-lock.json`), string-aware comment/secret inspection, and AST rule matching.

### 2.2 Frameworks & Libraries (`requirements.txt` / `pyproject.toml`)
| Component | Library / Version | Purpose |
|---|---|---|
| **Web Dashboard** | `streamlit>=1.40.0` | Light-themed interactive 4-tab web portal with real-time scan progress. |
| **Data Manipulation** | `pandas>=2.0.0` | Tabular presentation for findings, routes, dependency fix plans, and SBOM components. |
| **PDF Generation** | `fpdf2>=2.7.0` | Programmatic vector PDF executive report generation with custom tables and layouts. |
| **Config & Data Parsing** | `pyyaml>=6.0.0` | YAML parsing for custom Semgrep rules, taint catalogs, CWE equivalence maps, and license policies. |
| **HTTP & Intelligence** | `requests>=2.32.0` | Outbound queries for EPSS probabilities, CISA KEV catalogs, and PyPI/npm registry verification. |
| **Version Comparison** | `packaging>=23.0` | Semantic version parsing (`Version`, `SpecifierSet`) for dependency advisory and upgrade range matching. |
| **Python Lockfile SCA** | `pip-audit>=2.7.0` | Python dependency vulnerability auditing against PyPI/OSV advisories. |
| **Python SAST** | `bandit>=1.9.0` | Secondary Python AST static security analysis. |
| **Packaging & Build** | `hatchling` | PEP 517 build backend for editable and wheel distribution. |

### 2.3 Integrated Scanner Toolchain
VibeSec acts as a multi-scanner orchestrator, executing and normalizing findings from the following external tools when available:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        External Scanner Toolchain                      │
├───────────────────┬───────────────────┬────────────────────────────────┤
│ Tool              │ Category          │ Focus / Purpose                │
├───────────────────┼───────────────────┼────────────────────────────────┤
│ Semgrep           │ SAST              │ AST rule matching (Python & JS)│
│ Gitleaks          │ Secrets           │ High-entropy regex token scan  │
│ Trivy             │ SCA / Config      │ CVE lookups & misconfigurations│
│ Bandit            │ SAST (Python)     │ Python AST vulnerability audit │
│ pip-audit         │ SCA (Python)      │ PyPI OSV vulnerability advisory│
│ npm audit         │ SCA (Node)        │ npm registry security advisory │
└───────────────────┴───────────────────┴────────────────────────────────┘
```

*Graceful Degradation*: If any binary is missing from the system `PATH`, VibeSec marks the tool's status as `SKIPPED` or `DEGRADED`, records the reason, updates `AnalysisCoverage` (`INCOMPLETE`), and continues the scan with remaining scanners and internal AST analyzers without crashing.

---

## 3. End-to-End Architectural Data Flow

The following diagram illustrates the complete data flow from input submission to multi-format report export:

```
[Target: ZIP Upload / GitHub URL] (CLI also supports --dir)
                       │
                       ▼
         ┌───────────────────────────┐
         │     extractor.py          │
         │  - Streaming 64KB Extract │
         │  - ZipSlip / Bomb Guards  │
         │  - Shallow Git / HTTPS DL │
         │  - Binary Filter & Profil │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      dep_graph.py         │
         │  - Lockfile & Hash Parse  │
         │  - Graph Construction     │
         │  - Exposure Classification│
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │     scanners/ (Sandbox)   │
         │  - shell=False & Scrubbed │
         │  - 60-90s Timeout / 25MB  │
         │  - Semgrep / Gitleaks     │
         │  - Trivy / pip / npm / Bnd│
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      normalizer.py        │
         │  - Python AST Validator   │
         │  - String-Aware JS Parser │
         │  - Env Fallback Literal   │
         │  - Preserved Secret Guard │
         │  - Filtered Audit Ledger  │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │  config_exposure.py &     │
         │  supply_chain.py          │
         │  - Docker / ENV / CORS    │
         │  - Typosquat / Hallucinate│
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      correlator.py        │
         │  - Multi-Scanner Dedup    │
         │  - CWE Equivalence Merge  │
         │  - Lockfile SCA Isolation │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │     asm.py & taint.py     │
         │  - Route Resolution       │
         │  - Auth State Inference   │
         │  - 3+ Step Taint Paths    │
         │  - Inert Canary curl PoCs │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      prioritizer.py       │
         │  - 0-10 Multiplicative    │
         │  - CVSS Severity Buckets  │
         │  - Risk Posture Equation  │
         └─────────────┬─────────────┘
                       │
                       ▼
    ┌──────────────────┴──────────────────┐
    ▼                                     ▼
[Web Dashboard: app.py]           [Report Export Engines]
- Light Theme (4 Focused Tabs)    - Executive PDF (report.py)
- Coverage & Posture Banners      - Developer Markdown (exports.py)
- Severity KPI Metrics            - OASIS SARIF 2.1.0 (sarif.py)
- Interactive Findings Ledger     - CycloneDX 1.5 JSON (sbom.py)
- ASM & Graphviz Attack Paths     - Optional CLI SQLite (storage.py)
- Dependency Fix Plan Tables
```

---

## 4. Repository & File System Organization

```
VibeSECURITY/
│
├── .streamlit/
│   └── config.toml             # Headless light theme, XSRF protection, 1 GB upload limit
│
├── docs/
│   ├── ARCHITECTURE.md         # 10-stage pipeline flow, trust boundaries & module inventory
│   ├── DESIGN_RATIONALE.md     # Mathematical foundations of the 0–10 scoring model
│   └── THREAT_MODEL.md         # Assets, attacker profiles, sandbox defenses & deployment practices
│
├── rules/
│   └── vibe_code/
│       ├── vibe_python.yaml    # Custom Semgrep AST rules for Python vulnerabilities
│       └── vibe_javascript.yaml# Custom Semgrep AST rules for JS/TS vulnerabilities
│
├── src/
│   └── vibesec/
│       ├── __init__.py         # Package entry & exports
│       ├── asm.py              # Application Security Model (routes, auth, sinks)
│       ├── attack_paths.py     # Inter-procedural taint path constructor & inert canary PoCs
│       ├── attack_surface.py   # Route heuristics & endpoint structures
│       ├── cli.py              # CLI dispatcher & exit code contracts (0, 1, 2, 3)
│       ├── config_exposure.py  # Hardcoded credentials, Dockerfile, CI & CORS rules
│       ├── correlator.py       # Cross-scanner finding deduplication & CWE equivalence
│       ├── dep_graph.py        # Lockfile dependency tree & integrity hash parser
│       ├── exploit_intel.py    # EPSS & CISA KEV exploit intelligence with SQLite cache
│       ├── exports.py          # Markdown & JSON technical report builders
│       ├── exposure.py         # Runtime vs toolchain vs test scope classifier
│       ├── extractor.py        # Streaming archive ingestion, sandbox isolation, profiling
│       ├── grouping.py         # Ordered dependency upgrade actions (FixAction)
│       ├── imports.py          # AST import statement analyzer
│       ├── license_eval.py     # License compliance against license_policy.yaml
│       ├── models.py           # Shared data models (Finding, Severity, Location, ASM)
│       ├── normalizer.py       # Scanner normalization, AST/JS comment FP filter, ledger
│       ├── owasp.py            # OWASP Top 10 (2021) mapping
│       ├── pipeline.py         # Central 10-stage assessment pipeline orchestrator
│       ├── prioritizer.py      # 0–10 multiplicative risk scoring & single-source posture
│       ├── reachability.py     # Static call-graph dependency reachability analysis
│       ├── report.py           # Executive PDF report generator (fpdf2)
│       ├── sarif.py            # OASIS SARIF 2.1.0 JSON exporter
│       ├── sbom.py             # CycloneDX 1.5 JSON SBOM generator with VEX properties
│       ├── secrets_intel.py    # Secret intelligence & placeholder detection helpers
│       ├── storage.py          # Optional SQLite CLI persistence with :memory: fallback
│       ├── supply_chain.py     # Typosquatting, hallucinated packages, npm aliases
│       ├── taint.py            # Static AST source-to-sink taint propagation
│       │
│       ├── data/               # Schemas, policy files, and baseline datasets
│       │   ├── bom-1.5.schema.json
│       │   ├── cwe_equivalence.yaml
│       │   ├── license_policy.yaml
│       │   ├── sarif-schema-2.1.0.json
│       │   ├── taint_catalog.yaml
│       │   ├── toolchain_roots.yaml
│       │   ├── top_npm_packages.json
│       │   └── top_pypi_packages.json
│       │
│       └── scanners/           # Hardened subprocess external tool wrappers
│           ├── __init__.py
│           ├── bandit_scanner.py
│           ├── base.py
│           ├── gitleaks.py
│           ├── npm_audit.py
│           ├── pip_audit.py
│           ├── semgrep_scanner.py
│           └── trivy.py
│
├── app.py                      # Main Streamlit 4-tab light-theme web dashboard
├── Dockerfile                  # Multi-stage hardened non-root container (UID 1000)
├── .dockerignore               # Build context exclusions
├── packages.txt                # System package dependency (`graphviz`)
├── pyproject.toml              # Build metadata & Hatchling configuration
├── requirements.txt            # Pinned production pip dependencies (0 CVEs via pip-audit)
├── Technical Architecture & Internal Working Specification.md
├── vibesec_sbom.json           # VibeSec self-SBOM in CycloneDX 1.5 JSON
├── SECURITY.md                 # Security disclosure policy
├── CONTRIBUTING.md             # Contribution guidelines
├── CHANGELOG.md                # Release changelog
└── README.md                   # User documentation and deployment instructions
```

---

## 5. Module-by-Module Technical Deep-Dive

### 5.1 `src/vibesec/extractor.py` — Ingestion & Sandbox Isolation
Responsible for taking untrusted user input (ZIP file or GitHub repository URL) and safely establishing an isolated, inspected workspace.

- **Resource Limits**:
  - `MAX_ARCHIVE_BYTES = 1_073_741_824` (1 GB compressed limit).
  - `MAX_ARCHIVE_MEMBERS = 50_000` (50,000 files).
  - `MAX_UNCOMPRESSED_BYTES = 5_000_000_000` (5 GB uncompressed limit).
- **Security Defenses in `extract_zip()`**:
  1. *ZipSlip Path Traversal Protection*: Inspects `parts = Path(filename).parts` and verifies `(dest / filename).resolve().relative_to(dest)`. Any `..` or leading slash raises `ExtractionError`.
  2. *Windows Drive Letter Defense*: Rejects entries containing `:` at position 1 (e.g., `C:/Windows`).
  3. *Symlink Neutralization*: Evaluates Unix mode flags `(member.external_attr >> 16) & 0o170000 == 0o120000` and safely skips symlinks so they cannot escape the sandbox.
  4. *Streaming Decompression Byte Cap*: Extracts archive entries in **64 KB chunks** while maintaining a running extracted byte counter. Even if ZIP metadata headers spoof smaller sizes, extraction aborts immediately and cleans up partial data if the live byte counter exceeds `MAX_UNCOMPRESSED_BYTES`.
  5. *Zip Bomb Protection*: Rejects entries where compression ratio exceeds `100:1` on entries larger than `50 MB`.
  6. *Dangerous Binary Rejection*: Rejects executable binaries matching `DANGEROUS_EXTENSIONS = {".exe", ".dll", ".com", ".msi"}`.
  7. *Single Top-Level Directory Auto-Unwrap*: When an archive wraps everything in a single folder (e.g., `repo-main/`), `extract_zip` ignores OS metadata (`.DS_Store`, `__MACOSX`, `Thumbs.db`) and descends directly into the project root.
- **GitHub Ingestion in `clone_github()`**:
  1. Validates URL against strict regex `GITHUB_URL_RE` (`https://github.com/<owner>/<repo>`), rejecting traversal, query parameters, and shell metacharacters.
  2. Executes shallow clone: `git clone --depth 1 --single-branch <url> <dest>`.
  3. *Fallback*: If `git` is missing or fails, downloads archive ZIP via HTTPS (`https://codeload.github.com/<owner>/<repo>/zip/refs/heads/<branch>`).
- **Dynamic Binary Filtering & Project Profiling in `profile_project()`**:
  - `is_binary_file()` inspects the first 1,024 bytes of each file for null bytes (`\x00`) or UTF-8 decoding errors so compiled/binary files are skipped dynamically.
  - Scans text files up to `MAX_FILE_BYTES = 1_000_000` (1 MB per file).
  - Detects frameworks (FastAPI, Flask, Django, Express, Next.js, React, NestJS) and infers application type (`server`, `cli`, `frontend`, or `library`).

---

### 5.2 `src/vibesec/pipeline.py` & `scanners/base.py` — Hardened Orchestration
The central orchestrator connects all 10 assessment stages while keeping subprocess execution strictly isolated:

1. **Workspace Setup**: Creates a unique ephemeral directory `tempfile.mkdtemp(prefix="vibesec-")`. Host absolute paths are masked to `dir: <basename>` or repo URL before populating `ScanResult`.
2. **Hardened Scanner Sandbox (`scanners/base.py`)**:
   - All scanner tools run via `subprocess.run` with explicit `argv` lists and `shell=False`.
   - `get_scrubbed_env()` filters environment variables to an explicit allowlist, stripping cloud tokens and credentials (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`), and sets `SEMGREP_SEND_METRICS=off`, `SEMGREP_VERSION_CHECK=off`, `TRIVY_NO_PROGRESS=true`, and `DO_NOT_TRACK=1`.
   - Captures are hard-capped at `MAX_CAPTURE_BYTES = 25 * 1024 * 1024` (25 MB) with strict `60–90` second timeouts (`proc.kill()` on timeout).
3. **Inline Suppressions**: Evaluates `# vibesec-ignore: <rule-id> <reason>` or `// vibesec-ignore: <rule-id> <reason>` comments with mandatory justification reasons.
4. **Cleanup**: Destroys the ephemeral workspace on completion unless `keep_workspace=True`.

---

### 5.3 `src/vibesec/normalizer.py` — AST Validation, String-Aware JS Parsing & Ledger
`normalizer.py` standardizes heterogeneous scanner outputs while eliminating false positives safely:

- **Genuine Credential Preservation Invariant**: Comment and docstring suppression rules **never drop real leaked credentials** (e.g., AWS `AKIA...` keys, GitHub tokens `ghp_...`, OpenAI keys `sk-...`, PEM private keys `-----BEGIN ... PRIVATE KEY-----`) even when discovered inside comments or docstrings.
- **Python AST Comment/Docstring Validation**: Parses Python modules with `ast.AST` to distinguish executable lines from comments and multiline docstrings.
- **String-Aware JS/TS Comment Tokenizer**: Scans JS/TS code character-by-character tracking string literals (`'...'`, `"..."`, template literals `` `...` ``) and comments (`//...`, `/*...*/`) so URLs like `"https://example.com"` containing `//` are never misclassified as comments, while true comment-only findings are safely filtered.
- **Environment Variable Fallback Evaluation**: Distinguishes benign environment reads (`os.getenv("DB_PASS")`) from hardcoded secret defaults (`os.getenv("API_KEY", "sk_live_...")` or `process.env.SECRET || "hardcoded"`), flagging insecure fallback literals while dropping safe lookups.
- **Filtered Findings Audit Ledger**: Every dropped or suppressed finding is recorded in `get_filtered_findings_ledger()` and surfaced in technical exports for complete auditability.

---

### 5.4 `src/vibesec/asm.py`, `taint.py`, & `attack_paths.py` — Attack Surface & Taint Engine
- **Application Security Model (`asm.py`)**: Statically reconstructs FastAPI, Flask, Django, Express, and Next.js routes, prefixes, HTTP methods, authentication middleware/decorators (`PUBLIC` vs. `AUTHENTICATED`), data stores, and outbound network calls.
- **Inter-Procedural Taint Flows (`taint.py` & `attack_paths.py`)**:
  - Connects entrypoints to critical sinks (Command Execution, SQL Injection, Code Execution, Deserialization, SSRF, Path Traversal, IDOR, Prompt Injection, XSS).
  - Enforces a minimum of **3 traceable flow steps** ($\text{source} \rightarrow \text{intermediate flow} \rightarrow \text{sink}$) on every attack path.
  - Synthesizes **inert, non-destructive canary PoC templates** (e.g., `echo vibe_canary` instead of destructive commands, `' OR '1'='1` for SQLi) ready for safe manual verification.

---

### 5.5 `src/vibesec/dep_graph.py`, `exposure.py`, & `reachability.py` — Dependency Intelligence
1. **Lockfile & Hash Parsing (`dep_graph.py`)**: Parses `package-lock.json` (v1/v2/v3), `requirements.txt`, `poetry.lock`, and `Pipfile.lock`, extracting package integrity hashes (`sha512-...`, `sha256-...`) and direct/transitive dependency edges.
2. **Exposure Classification (`exposure.py`)**: Assigns packages and code paths to `RUNTIME_SERVER`, `RUNTIME_BUNDLE`, `TOOLCHAIN_BUILD`, `TOOLCHAIN_DEVSERVER`, or `TEST`.
3. **Static Reachability (`reachability.py`)**: Determines whether a dependency is `CALLED`, `IMPORTED`, `TRANSITIVE_OF_RUNTIME`, `TOOLCHAIN`, or `NOT_IMPORTED`.
4. **Supply Chain & License Intelligence (`supply_chain.py`, `license_eval.py`)**: Evaluates Levenshtein typosquatting paired with registry evidence (age < 30d or downloads < 1,000), resolves npm package aliases (`npm:pkg@ver`), enriches CVEs with CISA KEV / EPSS intelligence (suppressing network calls when `VIBESEC_OFFLINE=1`), and checks SPDX licenses against `license_policy.yaml`.

---

### 5.6 `src/vibesec/prioritizer.py` — 0–10 Multiplicative Scoring Model (Single Source of Truth)

All risk scores are bounded in $[0.0, 10.0]$ and aligned with CVSS v3.1 / v4.0 qualitative severity ratings:

#### 1. Code, Secret, Configuration, and License Findings
$$\text{Score}_{\text{code}} = \min\left(10.0, \text{base} \cdot \text{Conf} \cdot T \cdot A \cdot D \cdot S_{\text{asset}}\right)$$

- $\text{base}$: CVSS base score ($0.0 - 10.0$) if available, else mapped from raw severity ($\text{CRITICAL}=9.5, \text{HIGH}=7.5, \text{MEDIUM}=5.0, \text{LOW}=2.0, \text{INFO}=0.0$).
- $\text{Conf}$: Confidence factor $= 0.6 + 0.4 \cdot \text{confidence}$ ($\text{range}: 0.6 - 1.0$).
- $T$: Taint factor ($1.0$ if taint reachable or non-sink finding; $0.75$ for unconfirmed static code sinks).
- $A$: Auth context ($\text{PUBLIC}=1.0, \text{UNKNOWN}=0.9, \text{AUTHENTICATED}=0.75$).
- $D$: Exposure multiplier ($\text{RUNTIME\_SERVER}=1.0, \text{RUNTIME\_BUNDLE}=1.0, \text{UNKNOWN}=0.7, \text{TOOLCHAIN\_BUILD}=0.35, \text{TOOLCHAIN\_DEVSERVER}=0.25, \text{TEST}=0.2$).
- $S_{\text{asset}}$: Sensitive asset multiplier ($1.15$ for credentials/PII/tokens, else $1.0$).

#### 2. Dependency Vulnerabilities
$$\text{Score}_{\text{dep}} = \min\left(10.0, \text{base} \cdot R \cdot D \cdot (1 + 0.3 \cdot \text{EPSS}) + \text{KEV\_bonus}\right)$$

- $R$: Reachability factor ($\text{CALLED}=1.0, \text{IMPORTED}=0.75, \text{UNKNOWN}=0.5, \text{TRANSITIVE\_OF\_RUNTIME}=0.4, \text{TOOLCHAIN}=0.25, \text{NOT\_IMPORTED}=0.15$).
- $\text{EPSS}$: Exploit Prediction Scoring System probability ($0.0 - 1.0$). Dropped when unmeasured or offline (`"not measured"`).
- $\text{KEV\_bonus}$: CISA Known Exploited Vulnerability bonus ($3.0 \cdot D$ if listed). `CALLED` + `RUNTIME` + `KEV` is guaranteed $\ge 7.0$ (HIGH).

#### Unified CVSS-Aligned Severity Thresholds
- $[9.0, 10.0] \implies \mathbf{CRITICAL}$
- $[7.0, 9.0) \implies \mathbf{HIGH}$
- $[4.0, 7.0) \implies \mathbf{MEDIUM}$
- $(0.0, 4.0) \implies \mathbf{LOW}$
- $0.0 \implies \mathbf{INFO}$

#### Actionable vs. Deprioritized Separation
Findings with `INFO` severity, `TOOLCHAIN_*` exposure, or `TEST` / non-runtime paths (except genuine hardcoded secrets/tokens in test paths, which remain actionable for rotation) are collapsed into per-rule/per-folder summary tables.

---

### 5.7 `src/vibesec/storage.py` — Optional CLI Persistence
- Provides optional SQLite persistence (`scans` and `findings` tables at `~/.vibesec/vibesec.db` or `VIBESEC_DB_PATH`) for CLI commands (`vibesec list`, `show`, `clear`).
- Falls back automatically to `:memory:` on read-only host filesystems.
- The Streamlit web application operates purely on active session state (`st.session_state`) with no scan history database exposure in the UI.

---

### 5.8 `src/vibesec/report.py`, `exports.py`, `sarif.py`, & `sbom.py` — Export Engines

1. **Executive PDF Report (`report.py`)**: Built with `fpdf2` containing risk posture summary, attack surface metrics, ranked actionable findings, collapsed non-runtime ledger, dependency reachability plan, SPDX license summary, and top attack paths.
2. **Developer Markdown & JSON (`exports.py`)**: Generates technical Markdown (`export_markdown`) and structured JSON (`export_json`) including code evidence, filtered findings audit ledger, and remediation guidance.
3. **OASIS SARIF 2.1.0 (`sarif.py`)**: Schema-validated against `sarif-schema-2.1.0.json`, using POSIX relative URIs under `%SRCROOT%` `originalUriBaseIds`, deterministic `primaryLocationLineHash` partial fingerprints, CVSS-aligned `security-severity` strings, and step-by-step `codeFlows` for attack paths.
4. **CycloneDX 1.5 JSON SBOM (`sbom.py`)**: Schema-validated against `bom-1.5.schema.json`, containing lockfile integrity hashes (SHA-512 / SHA-256), hierarchical `dependencies` tree connecting root to direct/transitive components, Package URLs (PURL), and VEX vulnerability analysis (classifying static-only `NOT_IMPORTED` vulnerabilities conservatively as `in_triage` with `vibesec:reachability` taxonomy properties).

---

### 5.9 `app.py` — Streamlit Web Dashboard Architecture
- **Exclusive Light Theme**: Configured via `.streamlit/config.toml` (`base="light"`) and centralized CSS variables (`#F8FAFC` canvas, `#FFFFFF` surfaces, `#0F172A` text, `#2563EB` primary accent, Inter + JetBrains Mono fonts, zero emojis).
- **Streamlined UI Scope**: Intentionally removes Scan History tabs, Toolchain Status dashboards, and Offline Mode UI toggles to keep the workflow clean and focused on the active scan.
- **UI Chrome & Sidebar Toggle Polish**:
  - Hides Streamlit Community Cloud hosting chrome (`[data-testid="stToolbarActions"]`, `[data-testid="stAppDeployButton"]`, `[data-testid="stMainMenu"]`, `_profileContainer_`, `_viewerBadge_`) while keeping `[data-testid="stExpandSidebarButton"]` (`>>`), `[data-testid="collapsedControl"]`, and `[data-testid="stSidebarCollapseButton"]` (`<<`) cleanly visible and styled on light backgrounds.
  - Hides Streamlit's `[data-testid="InputInstructions"]` ("Press Enter to apply") overlay so URLs never clip or overlap.
  - Streams uploaded ZIPs from browser memory to temp files in 8 MB chunks.
- **Four Production Tabs**:
  1. `Scan`: Target input (`ZIP Archive` up to 1 GB / 50k files, `Public GitHub Repository`), live scan progress bar, 6 KPI metrics, filters, expandable actionable cards, and collapsed non-actionable summary table.
  2. `Attack Surface & Paths`: Route metrics, discovered endpoints table, Graphviz Application Map, and ranked attack paths with flow steps, canary PoCs, and Graphviz graphs.
  3. `Dependencies`: License evaluation banner, grouped dependency fix plan table, vulnerable dependencies ledger, and CycloneDX component preview.
  4. `Reports`: One-click downloads for PDF, Markdown, OASIS SARIF 2.1.0, and CycloneDX 1.5 JSON SBOM plus rendered Markdown preview.

---

## 6. Detection Rules & Supply Chain Signatures

### 6.1 Python Rule Pack (`rules/vibe_code/vibe_python.yaml`)
- `vibe.python.sqli`: Unsanitized format strings or `%` operators flowing into SQL cursors.
- `vibe.python.command_injection`: Command execution with `shell=True` and untrusted variables.
- `vibe.python.path_traversal`: Unsanitized path concatenation in file openers.
- `vibe.python.ssrf`: User-controlled URLs flowing into HTTP clients (`requests`, `httpx`).
- `vibe.python.llm_prompt_injection`: Unsanitized inputs concatenated into LLM prompts (context-checked for active LLM SDK imports).

### 6.2 JavaScript Rule Pack (`rules/vibe_code/vibe_javascript.yaml`)
- `vibe.js.sqli`: String concatenation in `pg`, `mysql2`, or `sequelize` queries.
- `vibe.js.command_injection`: `child_process.exec` with unvalidated inputs (safely distinguishing parameterized `execFile` / `spawn` array invocations).
- `vibe.js.prototype_pollution`: Unsafe recursive object merges and `Object.assign` calls.
- `vibe.js.hardcoded_jwt`: Hardcoded secret keys in `jwt.sign()` / `jwt.verify()`.

### 6.3 Supply Chain Intelligence (`src/vibesec/supply_chain.py`)
- **Typosquatting Detection**: Evaluates Levenshtein edit distance against `top_pypi_packages.json` / `top_npm_packages.json`, requiring concrete registry evidence (recently published < 30 days or < 1,000 downloads).
- **NPM Alias Resolution**: Resolves `"name": "npm:pkg@ver"` aliases to actual target packages without false hallucination alerts.

---

## 7. Security Controls, Sandbox Isolation & Resource Guards

1. **Zero-Execution Sandbox**: VibeSec never executes or imports scanned target code. Subprocesses run with `shell=False`, scrubbed environment variables (`get_scrubbed_env()`), telemetry disabled (`DO_NOT_TRACK=1`), 60–90s timeouts, and 25 MB output caps.
2. **Archive Security**: Enforces `1 GB` compressed limit, `50,000` max entries, `5 GB` streaming uncompressed limit, `100:1` compression bomb check, symlink skipping, Zip Slip validation, and dangerous binary rejection (`.exe`, `.dll`, `.com`, `.msi`).
3. **Host Path Sanitization**: Internal temporary directories (`/tmp/vibesec-...`, `C:\Users\...`) are masked to relative names (`dir: <basename>`) or `%SRCROOT%` URIs across `ScanResult`, UI banners, PDF, Markdown, SARIF, and SBOM exports.
4. **Hardened Container Image (`Dockerfile`)**: Multi-stage `python:3.12-slim-bookworm` container running strictly under unprivileged user `vibesec` (`UID 1000`, `GID 1000`) with non-root `/workspace` and telemetry disabled.

---

## 8. Configuration & Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `VIBESEC_OFFLINE` | `0` | Set to `1` to disable external intelligence API calls and fall back to local caches / neutral values. |
| `VIBESEC_DB_PATH` | `~/.vibesec/vibesec.db` | Optional SQLite database location for CLI persistence (falls back to `:memory:` if unwritable). |

---

## 9. Packaging, CLI Contracts & Supply Chain Verification

- **Clean Runtime Dependencies (`requirements.txt`)**: Pinned core dependencies audited with `pip-audit -r requirements.txt` confirming **0 known vulnerabilities**.
- **Self-SBOM (`vibesec_sbom.json`)**: Generated CycloneDX 1.5 JSON bill of materials documenting VibeSec's own runtime components and PURLs.
- **Deterministic CLI Exit Codes (`src/vibesec/cli.py`)**:
  - `0`: Assessment completed cleanly with no `--fail-on` threshold breach.
  - `1`: Security threshold breach (`--fail-on <severity>` or `--fail-on critical_path` triggered).
  - `2`: Invalid CLI arguments or missing target path/ZIP.
  - `3`: Pipeline execution or extraction error.

---

## 10. Summary

VibeSec unifies deterministic multi-scanner orchestration, static AST taint flow analysis, dependency call-graph reachability, and CVSS-aligned 0–10 risk scoring inside a zero-execution sandbox. Paired with schema-validated OASIS SARIF 2.1.0, CycloneDX 1.5 SBOM, executive PDF/Markdown reporting, and a clean 4-tab light-theme web dashboard, it provides clear, actionable security intelligence for modern and AI-generated applications.
