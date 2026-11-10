# VibeSec — Comprehensive Technical Architecture & Internal Working Specification

> **Deterministic Application Security Assessment & Reachability Engine for Modern & AI-Generated Software**

---

## 1. Executive Summary & Design Philosophy

**VibeSec** is an automated static application security testing (SAST), software composition analysis (SCA), and attack-surface reachability platform designed specifically to evaluate modern web applications, microservices, and AI-generated codebases.

### 1.1 Core Mission & Purpose
Modern development pipelines—especially those utilizing AI coding assistants (e.g. GitHub Copilot, Cursor, Claude, ChatGPT)—frequently introduce predictable security defects:
1. **Hallucinated or Typosquatted Dependencies**: Package names suggested by LLMs that do not exist or resemble popular packages.
2. **Missing Input Validation & Route Authorization**: Endpoints exposed without authentication or authorization guards.
3. **Dangerous Execution Sinks**: Direct concatenation into SQL queries, operating system commands (`shell=True`), eval loops, server-side template engines, and prompt injection vectors in LLM integrations.
4. **Credential & Secret Leakage**: API tokens, private keys, database connection strings, and JWT secrets committed into source code and environment templates.
5. **False-Positive Fatigue**: Traditional SAST scanners flag non-executable comments, docstrings, build scripts, test fixtures, and unreachable library code, overwhelming development teams.

VibeSec solves these problems by pairing industry-standard security scanners with an **inter-procedural AST taint engine**, an automated **Application Security Model (ASM)**, and **dependency reachability analysis**. It normalizes all scanner outputs into a unified data structure, filters out non-executable code, adjusts risk scores based on runtime exposure and authentication boundaries, and outputs audit-grade reports.

### 1.2 Core Architectural Invariants
- **Deterministic & Offline-Capable**: Security analysis relies on static analysis, abstract syntax trees (ASTs), regex tokenizers, and cached intelligence. Code is evaluated predictably without nondeterministic LLM evaluation in the critical path.
- **Strictly Passive (Zero-Execution Sandbox)**: VibeSec **never compiles, imports, or executes** target code. Analysis inspects source files purely as text, AST nodes, and configuration data, preventing remote code execution (RCE) during scanning.
- **Single Source of Truth Scoring**: The executive risk posture statement, severity breakdown, SARIF export, PDF report, Markdown summary, and web dashboard compute from the exact same mathematical model.
- **Actionable vs. Non-Actionable Separation**: Findings in test directories, mock fixtures, build scripts, or informational categories are automatically collapsed into summary ledgers, keeping the primary focus on genuine production vulnerabilities.

---

## 2. Complete Technology Stack & Toolchain Dependencies

### 2.1 Core Runtime & Languages
- **Python 3.11+** (Tested through Python 3.14): Primary runtime for the pipeline, orchestrator, AST analyzers, reporting engines, and web dashboard.
- **JavaScript / TypeScript**: Target language support for route detection (Express, Next.js), dependency parsing (`package.json`, `package-lock.json`), and AST pattern matching.

### 2.2 Frameworks & Libraries
| Component | Library / Version | Purpose |
|---|---|---|
| **Web Dashboard** | `streamlit>=1.40.0` | Enterprise light-themed interactive dashboard with real-time scan progress. |
| **Data Manipulation** | `pandas>=2.0.0` | Tabular data presentation for findings, routes, dependency fix plans, and SBOM components. |
| **PDF Generation** | `fpdf2>=2.7.0` | Programmatic vector PDF executive report generation with custom layouts, tables, and typography. |
| **Config & Data Parsing** | `pyyaml>=6.0.0` | YAML configuration parsing for custom Semgrep rules, taint catalogs, CWE mappings, and license policies. |
| **HTTP & Intelligence** | `requests>=2.31.0` | Outbound queries for EPSS probabilities, CISA KEV catalogs, PyPI/npm registry verification. |
| **Version Comparison** | `packaging>=23.0` | Semantic version parsing (`Version`, `SpecifierSet`) for dependency vulnerability and upgrade range matching. |
| **Packaging & Build** | `hatchling` | PEP 517 build backend for editable and wheel distribution. |
| **Code Quality & Linter** | `ruff>=0.8` | High-performance Python linter and code formatter. |
| **Test Harness** | `pytest>=8.0`, `pytest-asyncio` | Unit testing, integration testing, and regression verification. |
| **Headless UI Testing** | `streamlit.testing.v1.AppTest` | Headless in-process Streamlit component and state assertion framework. |

### 2.3 Integrated Scanner Toolchain
VibeSec acts as a multi-scanner orchestrator, executing and normalizing findings from the following external tools when present:

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

*Graceful Degradation*: If any binary is missing from the system `PATH`, VibeSec marks the tool's status as `SKIPPED` or `DEGRADED`, records the reason, marks `AnalysisCoverage.INCOMPLETE`, and continues the scan without crashing.

---

## 3. End-to-End Architectural Data Flow

The following diagram illustrates the complete data flow from input submission to multi-format report export:

```
[Target: ZIP Upload / GitHub URL / Local Path]
                       │
                       ▼
         ┌───────────────────────────┐
         │     extractor.py          │
         │  - ZipSlip / Bomb Guards  │
         │  - Shallow Git / HTTPS DL │
         │  - Framework & App Profil │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      dep_graph.py         │
         │  - Lockfile Ingestion     │
         │  - Graph Construction     │
         │  - Exposure Classification│
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │     scanners/ (Engine)    │
         │  - Semgrep (Custom Rules) │
         │  - Gitleaks (Secrets)     │
         │  - Trivy / pip / npm audit│
         │  - Bandit AST Analysis    │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      normalizer.py        │
         │  - Python AST Validator   │
         │  - Comment & Docstring FP │
         │  - Benign Assignment Drop │
         │  - Common Finding Schema  │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │  config_exposure.py &     │
         │  supply_chain.py          │
         │  - Docker / ENV / Secrets │
         │  - Typosquat / Hallucinate│
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      correlator.py        │
         │  - Multi-Scanner Dedup    │
         │  - CWE Equivalence Merge  │
         │  - Slack Window Overlap   │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │     asm.py & taint.py     │
         │  - Route Resolution       │
         │  - Auth State Inference   │
         │  - Inter-procedural Taint │
         │  - Ranked Attack Paths    │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │      prioritizer.py       │
         │  - Context-Adjusted Score │
         │  - Risk Posture Equation  │
         │  - Actionable Separation  │
         └─────────────┬─────────────┘
                       │
                       ▼
         ┌───────────────────────────┐
         │        storage.py         │
         │  - SQLite Local State     │
         │  - In-Memory Fallback     │
         └─────────────┬─────────────┘
                       │
                       ▼
    ┌──────────────────┴──────────────────┐
    ▼                                     ▼
[Web Dashboard: app.py]           [Report Export Engines]
- Coverage & Posture Banner       - PDF Executive (report.py)
- Severity KPI Metrics            - Markdown (exports.py)
- Interactive Findings Ledger     - OASIS SARIF 2.1 (sarif.py)
- ASM & Graphviz Attack Paths     - CycloneDX 1.5 JSON (sbom.py)
- Dependency Fix Plan Tables
```

---

## 4. Repository & File System Organization

```
VibeSECURITY/
│
├── .streamlit/
│   └── config.toml             # Headless light theme, server settings, 1 GB upload limit
│
├── rules/
│   └── vibe_code/
│       ├── vibe_python.yaml    # Custom Semgrep AST rules for Python vulnerabilities
│       └── vibe_javascript.yaml# Custom Semgrep AST rules for JS/TS vulnerabilities
│
├── src/
│   └── vibesec/
│       ├── __init__.py         # Package entry & exports
│       ├── app.py              # Main Streamlit web dashboard
│       ├── asm.py              # Application Security Model (routes, auth, sinks)
│       ├── attack_paths.py     # Source-to-sink taint path constructor & curl PoC
│       ├── attack_surface.py   # Surface heuristics & endpoint structures
│       ├── cli.py              # Command-line interface dispatcher
│       ├── config_exposure.py  # Hardcoded credentials, Dockerfile & CORS rules
│       ├── correlator.py       # Cross-scanner finding deduplication & CWE equivalence
│       ├── dep_graph.py        # Lockfile dependency tree parser
│       ├── exploit_intel.py    # EPSS & CISA KEV exploit intelligence with SQLite cache
│       ├── exports.py          # Markdown technical report builder
│       ├── exposure.py         # Runtime vs toolchain scope classifier
│       ├── extractor.py        # Archive ingestion, sandbox isolation, profiling
│       ├── grouping.py         # Ordered dependency upgrade actions (FixAction)
│       ├── imports.py          # AST import statement analyzer
│       ├── license_eval.py     # License compliance against license_policy.yaml
│       ├── models.py           # Shared data models (Finding, Severity, Location, ASM)
│       ├── normalizer.py       # Scanner output normalization & AST comment FP filter
│       ├── owasp.py            # OWASP Top 10 (2021) classification
│       ├── pipeline.py         # Central assessment pipeline orchestrator
│       ├── prioritizer.py      # Risk scoring formula & single source of truth posture
│       ├── reachability.py     # Static call-graph dependency reachability analysis
│       ├── report.py           # Audit-ready executive PDF report generator (fpdf2)
│       ├── sarif.py            # OASIS SARIF 2.1.0 JSON exporter
│       ├── sbom.py             # CycloneDX 1.5 JSON SBOM generator
│       ├── secrets_intel.py    # Entropy & pattern secret detection rules
│       ├── storage.py          # SQLite persistence with in-memory fallback
│       ├── supply_chain.py     # Typosquatting, hallucinated packages, npm aliases
│       ├── taint.py            # Static AST source-to-sink taint propagation
│       │
│       ├── data/               # Static policy files and baseline datasets
│       │   ├── bom-1.5.schema.json
│       │   ├── cwe_equivalence.yaml
│       │   ├── license_policy.yaml
│       │   ├── taint_catalog.yaml
│       │   ├── toolchain_roots.yaml
│       │   ├── top_npm_packages.json
│       │   └── top_pypi_packages.json
│       │
│       └── scanners/           # External tool wrappers
│           ├── __init__.py
│           ├── bandit_scanner.py
│           ├── base.py
│           ├── gitleaks.py
│           ├── npm_audit.py
│           ├── pip_audit.py
│           ├── semgrep_scanner.py
│           └── trivy.py
│
├── tests/                      # Pytest verification suite
│   ├── test_comment_fp.py      # AST comment false-positive elimination tests
│   ├── test_extraction.py      # Archive security, zip bomb, and traversal tests
│   ├── test_ui_redesign.py     # Light theme, 1GB upload, and UI layout assertions
│   └── test_web_deployment.py  # Headless Streamlit AppTest & report export tests
│
├── pyproject.toml              # Build metadata & dependencies (Hatchling)
├── requirements.txt            # Direct pip installation dependencies
└── README.md                   # User documentation and deployment instructions
```

---

## 5. Module-by-Module Technical Deep-Dive

### 5.1 `src/vibesec/extractor.py` — Ingestion & Sandbox Isolation
Responsible for taking untrusted user input (ZIP file, GitHub repository URL, or local directory) and safely establishing an isolated, inspected workspace.

- **Resource Limits**:
  - `MAX_ARCHIVE_BYTES = 1_073_741_824` (1 GB compressed limit).
  - `MAX_ARCHIVE_MEMBERS = 50_000` (50,000 files).
  - `MAX_UNCOMPRESSED_BYTES = 5_000_000_000` (5 GB uncompressed limit).
- **Security Defenses in `extract_zip()`**:
  1. *ZipSlip Path Traversal Protection*: Checks `parts = Path(filename).parts` and verifies `(dest / filename).resolve().relative_to(dest)`. Any attempt to escape via `..` or leading slashes raises `ExtractionError`.
  2. *Windows Drive Letter Defense*: Rejects entries containing `:` at position 1 (e.g., `C:/Windows`).
  3. *Symlink Neutralization*: Evaluates Unix mode flags `(member.external_attr >> 16) & 0o170000 == 0o120000`. Symlinks are safely skipped during extraction so they cannot point outside the sandbox.
  4. *Zip Bomb Protection*: Rejects entries where compression ratio exceeds 100:1 on files larger than 50 MB.
  5. *Dangerous Binary Rejection*: Rejects dangerous executable binaries matching `DANGEROUS_EXTENSIONS = {".exe", ".dll", ".com", ".msi"}`.
  6. *Single Top-Level Directory Auto-Unwrap*: When an archive wraps everything in one folder (e.g. `repo-main/`), `extract_zip` ignores OS metadata (`.DS_Store`, `__MACOSX`, `Thumbs.db`) and descends directly into the project root.
- **GitHub Ingestion in `clone_github()`**:
  1. Validates URL against `r"^https://github\.com/(?P<owner>[a-zA-Z0-9_\-\.]+)/(?P<repo>[a-zA-Z0-9_\-\.]+)($|/)"`.
  2. Executes shallow clone: `git clone --depth 1 --single-branch <url> <dest>`.
  3. *Fallback*: If `git` is missing or fails, downloads archive ZIP via HTTPS: `https://codeload.github.com/<owner>/<repo>/zip/refs/heads/<branch>`.
- **Project Profiling in `profile_project()`**:
  - Scans files up to `MAX_FILE_BYTES = 1_000_000` (1 MB per file).
  - Detects frameworks: FastAPI, Flask, Django, Express, Next.js, React, NestJS.
  - Determines application type: `server`, `cli`, `frontend`, or `library`.

---

### 5.2 `src/vibesec/pipeline.py` — Pipeline Orchestration Lifecycle
The central orchestrator connecting all assessment phases:

1. **Workspace Setup**: Creates a unique ephemeral directory `tempfile.mkdtemp(prefix="vibesec-")`.
2. **Extraction & Profiling**: Dispatches to `extractor.py` and emits progress events (`progress_callback(pct, msg)`).
3. **Dependency Graph Construction**: Invokes `build_project_dependency_graph(root)` and `analyze_reachability(root, dep_graph)`.
4. **Tool Execution**: Spawns scanner adapters concurrently:
   - Gitleaks (Secrets)
   - Semgrep (Custom rules + security-audit)
   - Trivy (Filesystem CVE scan)
   - Bandit (Python AST checks)
   - pip-audit / npm audit (Lockfile vulnerability lookups)
5. **Normalization**: Invokes `normalizer.py` to filter non-executable lines, comments, and docstrings.
6. **Internal Analyzers**:
   - `config_exposure.py`: Hardcoded credentials and insecure Docker/CORS setups.
   - `supply_chain.py`: Typosquatted dependencies and hallucinated package checks.
7. **Correlation & Deduplication**: Merges overlapping findings via `correlator.py`.
8. **Application Security Model & Attack Paths**: Synthesizes entrypoints, sinks, and taint flow paths via `asm.py` and `taint.py`.
9. **Prioritization & Scoring**: Calculates risk posture, actionable findings, and severity buckets via `prioritizer.py`.
10. **Persistence**: Saves records to SQLite via `storage.py`.
11. **Export Generation**: Compiles PDF, Markdown, SARIF, and SBOM outputs.
12. **Cleanup**: Destroys the ephemeral workspace unless `keep_workspace=True`.

---

### 5.3 `src/vibesec/normalizer.py` — AST-Aware False-Positive Elimination
Raw scanner results (especially Gitleaks and Semgrep regex/token rules) frequently match comments, documentation strings, or non-secret variable assignments. `normalizer.py` applies AST validation to eliminate these false positives:

- **`is_comment_or_docstring_only()`**:
  - For Python files: Parses the source file into an `ast.AST`.
  - Computes `exec_lines`: the set of line numbers containing executable statements (excluding docstrings and string constants not assigned to variables).
  - Computes `docstring_lines`: line ranges of module, class, and function docstrings.
  - Checks finding line range (`start_line` to `end_line`): If the finding does not intersect any line in `exec_lines`, or if all non-empty lines in the range start with `#` or fall within `docstring_lines`, the finding is **dropped as non-executable**.
  - For JavaScript/TypeScript files: Uses comment-stripping tokenizers to ensure the match does not reside exclusively within `//` or `/* ... */` comment blocks.
- **Benign Assignment Detection**:
  - For secret detection rules: Inspects AST assignment nodes. If a variable is named `username = "admin"` or its value is loaded via `os.getenv(...)`, `os.environ.get(...)`, or `process.env[...]`, the finding is dropped because reading an environment variable or setting a default username is not a hardcoded secret vulnerability (CWE-798).

---

### 5.4 `src/vibesec/asm.py` & `src/vibesec/taint.py` — Attack Surface & Taint Flow Engine

#### `asm.py` (Application Security Model)
Statically parses routing definitions to map the attack surface without executing code:
- **FastAPI / Flask**: Detects `@app.get(...)`, `@router.post(...)`, `Blueprint`, URL path prefixes, and parameter decorators (`Query`, `Path`, `Body`, Pydantic models).
- **Express / Next.js**: Detects `app.get(...)`, `router.post(...)`, and Next.js App Router route handlers (`export async function GET(...)`).
- **Auth State Inference**:
  - Checks route decorators and middleware for authentication tokens (`login_required`, `jwt_required`, `Depends(get_current_user)`, `passport.authenticate`, `requireAuth`).
  - Classifies route as `AUTHENTICATED` or `PUBLIC`.
- **Data Access & External Call Sites**:
  - Maps database queries (SQLAlchemy, Prisma, Mongoose, raw SQL).
  - Maps outbound network calls (`requests.get`, `fetch`, `axios`).

#### `taint.py` & `attack_paths.py` (Inter-Procedural Taint Engine)
- **Sources**: HTTP route parameters (`request.args`, `req.query`, `req.body`, function arguments mapped to route parameters).
- **Sinks**:
  - Command Execution: `subprocess.Popen`, `subprocess.run`, `os.system`, `child_process.exec`.
  - SQL Injection: `cursor.execute`, `db.query` with string formatting.
  - SSRF: `requests.get(url)`, `fetch(url)`.
  - Prompt Injection: Concatenating unvalidated user input into an LLM client invocation (`openai.chat.completions.create`).
  - Path Traversal: `open(path)`, `fs.readFile(path)`.
- **Attack Path Construction**: Chains source parameters through function assignments to sinks, calculating an attack path score and producing a non-executable verification `curl` PoC.

---

### 5.5 `src/vibesec/dep_graph.py`, `exposure.py`, & `reachability.py` — Dependency Intelligence

1. **Lockfile Parsing (`dep_graph.py`)**:
   - Parses `package-lock.json` (v1, v2, v3), `requirements.txt`, `poetry.lock`, and `Pipfile.lock`.
   - Constructs a directed graph of all direct and transitive dependencies.
2. **Exposure Classification (`exposure.py`)**:
   - Categorizes every dependency into an exposure class:
     - `RUNTIME_SERVER`: Production backend server dependencies.
     - `RUNTIME_BUNDLE`: Frontend client bundle dependencies.
     - `TOOLCHAIN_BUILD`: Build tools, bundlers, compilers (e.g. `webpack`, `esbuild`, `tsc`).
     - `TOOLCHAIN_DEVSERVER`: Local test servers, hot-reloaders (e.g. `nodemon`).
     - `TEST`: Test runners and assertion libraries (e.g. `jest`, `pytest`).
3. **Reachability Analysis (`reachability.py`)**:
   - Traverses imports and call sites in application code:
     - `CALLED`: Symbols from the package are invoked in application code.
     - `IMPORTED`: Package is imported, but specific function invocations are not proven.
     - `TRANSITIVE_OF_RUNTIME`: Sub-dependency of a runtime package.
     - `NOT_IMPORTED`: Present in lockfile, but never referenced in application code.

---

### 5.6 `src/vibesec/prioritizer.py` — Mathematical Scoring & Single Source of Truth

#### Scoring Formulas

##### 1. Code, Secret, Configuration, and License Findings
$$\text{Score} = (4 \cdot S_{\text{rank}} + 2 \cdot C + 1.5 \cdot T + A + S_{\text{sensitive}}) \cdot D_{\text{exposure}}$$

- $S_{\text{rank}}$: Severity rank ($\text{CRITICAL}=4, \text{HIGH}=3, \text{MEDIUM}=2, \text{LOW}=1, \text{INFO}=0$)
- $C$: Rule confidence ($0.0 \text{ to } 1.0$)
- $T$: Taint reachable ($1.0$ if user input flows to sink, else $0.0$)
- $A$: Auth context ($\text{PUBLIC}=0.5, \text{AUTHENTICATED}=0.1, \text{UNKNOWN}=0.0$)
- $S_{\text{sensitive}}$: Sensitive asset flag ($1.0$ for credentials/PII/tokens, else $0.0$)
- $D_{\text{exposure}}$: Exposure multiplier ($\text{RUNTIME}=1.0, \text{TOOLCHAIN}=0.35, \text{TEST}=0.2$)

##### 2. Dependency Vulnerabilities
$$\text{Score} = (4 \cdot S + 2 \cdot X + 1.5 \cdot R + K) \cdot D$$

- $S$: Advisory severity rank ($0 \text{ to } 4$)
- $X$: EPSS exploit probability ($0.0 \text{ to } 1.0$, default $0.3$ if unknown)
- $R$: Reachability weight ($\text{CALLED}=1.0, \text{IMPORTED}=0.7, \text{TRANSITIVE}=0.4, \text{TOOLCHAIN}=0.1, \text{NOT\_IMPORTED}=0.0$)
- $K$: CISA KEV bonus ($2.0$ if present in CISA Known Exploited Vulnerabilities catalog, else $0.0$)
- $D$: Exposure multiplier ($\text{RUNTIME\_SERVER}=1.0, \text{UNKNOWN}=0.7, \text{TOOLCHAIN\_BUILD}=0.35, \text{TEST}=0.2$)

##### Severity Thresholds
- $\text{Score} \ge 16.0 \implies \mathbf{CRITICAL}$
- $\text{Score} \ge 12.0 \implies \mathbf{HIGH}$
- $\text{Score} \ge 8.0 \implies \mathbf{MEDIUM}$
- $\text{Score} \ge 4.0 \implies \mathbf{LOW}$
- $\text{Score} < 4.0 \implies \mathbf{INFO}$

#### Actionable vs. Deprioritized Separation
A finding is classified as `is_actionable(f) == True` only if:
1. Severity is not `INFO`.
2. Exposure class is not `TEST`, `TOOLCHAIN_BUILD`, or `TOOLCHAIN_DEVSERVER`.
3. File path does not belong to test or script directories (`tests/`, `fixtures/`, `scripts/`, `spec/`).

All non-actionable findings are grouped into a collapsed per-rule, per-folder summary.

---

### 5.7 `src/vibesec/storage.py` — Zero-Setup Persistence
- Uses SQLite with schema tables: `scans` and `findings`.
- Default storage location: `~/.vibesec/vibesec.db`.
- Can be overridden via environment variable `VIBESEC_DB_PATH`.
- *In-Memory Fallback*: If the host filesystem is read-only (common in cloud container sandboxes) or encounters permission errors, `storage.py` automatically falls back to `:memory:`, ensuring zero deployment crashes.

---

### 5.8 `src/vibesec/report.py`, `exports.py`, `sarif.py`, & `sbom.py` — The Four Export Engines

1. **Executive PDF Report (`report.py`)**:
   - Built using `fpdf2`.
   - Generates a formal security assessment report:
     - Section 1: Executive Summary & Risk Posture Statement.
     - Section 2: Application Security Model & Attack Surface Metrics.
     - Section 3: Ranked Actionable Security Findings.
     - Section 4: Collapsed Test & Non-Runtime Findings Summary.
     - Section 5: Dependency Intelligence & Reachability Breakdown.
     - Section 6: License Policy Evaluation & Compliance Auditing.
     - Section 7: Top Attack Paths with Flow Steps & Verification Proof of Concept.
2. **Developer Markdown Report (`exports.py`)**:
   - Formats complete technical findings into clean GitHub-flavored Markdown.
   - Includes code snippets, CWE references, and remediation guidance.
3. **OASIS SARIF 2.1.0 (`sarif.py`)**:
   - Generates standard Static Analysis Results Interchange Format JSON.
   - Maps attack paths into `codeFlows` and `threadFlows` for native display in GitHub Security tabs.
4. **CycloneDX 1.5 JSON SBOM (`sbom.py`)**:
   - Compiles Software Bill of Materials with component names, versions, scopes, Package URLs (PURL), and vulnerability records.

---

### 5.9 `app.py` — Streamlit Web Dashboard Architecture
The frontend web application provides a browser-based portal:

- **Light-Only Enterprise Theme**:
  - Enforced via `.streamlit/config.toml` (`base="light"`) and centralized CSS variables.
  - Pure white surfaces (`#FFFFFF`), canvas backgrounds (`#F8FAFC`), dark text (`#0F172A`), and primary accents (`#2563EB`).
  - Font stack: Inter with JetBrains Mono.
  - Zero emojis across the entire UI.
- **Four Production Tabs**:
  1. `Scan`: Target source selection (ZIP upload up to 1 GB, GitHub URL), real-time progress bar, executive KPI metrics, search & severity filter, and actionable findings ledger.
  2. `Attack Surface & Paths`: ASM entrypoints table, Graphviz Application Map, and ranked attack paths with PoC curl commands.
  3. `Dependencies`: License policy summary card, ordered upgrade fix plan table, vulnerable dependencies, and CycloneDX component table.
  4. `Reports`: Export cards with download buttons for PDF, Markdown, SARIF, and SBOM, plus an expandable technical report markdown preview.
- **UI Glitch Fixes**:
  - Streamlit's `[data-testid="InputInstructions"]` overlay ("Press Enter to apply") is hidden via CSS, preventing it from clipping or overlapping repository URLs.
  - Large ZIP files stream in 8 MB chunks to prevent RAM exhaustion.

---

## 6. Detection Rules & Custom Signatures

### 6.1 Python Rule Pack (`rules/vibe_code/vibe_python.yaml`)
- `vibe.python.sqli`: Unsanitized format strings or `%` operators flowing into SQL query cursors.
- `vibe.python.command_injection`: Command execution where `shell=True` is enabled with untrusted variables, resolving safe bindings such as `execFile`.
- `vibe.python.path_traversal`: Unsanitized path concatenation flowing into file openers.
- `vibe.python.ssrf`: User-controlled query strings flowing directly into `requests.get` or `httpx`.
- `vibe.python.llm_prompt_injection`: Unsanitized user inputs concatenated into LLM system or user prompts without validation, requiring an LLM SDK import.

### 6.2 JavaScript Rule Pack (`rules/vibe_code/vibe_javascript.yaml`)
- `vibe.js.sqli`: String concatenation in `pg`, `mysql2`, or `sequelize` queries.
- `vibe.js.command_injection`: `child_process.exec` with unvalidated input arguments.
- `vibe.js.prototype_pollution`: Unsafe recursive object merges and `Object.assign` calls.
- `vibe.js.hardcoded_jwt`: Hardcoded secret keys passed to `jwt.sign()` or `jwt.verify()`.

### 6.3 Supply Chain & Package Rules (`src/vibesec/supply_chain.py`)
- **Typosquatting Detection**: Evaluates Levenshtein edit distance against top PyPI/npm packages (`top_pypi_packages.json`, `top_npm_packages.json`). Requires registry evidence: published less than 30 days ago or download count below 1,000 to prevent false positives on legitimate packages.
- **NPM Alias Resolution**: Resolves npm alias specifications (e.g. `"name": "npm:pkg@ver"`) to the target package name rather than treating them as hallucinated packages.

---

## 7. Security Controls, Sandbox Isolation, & Resource Guards

1. **Passive Execution Boundary**:
   - VibeSec never imports target modules into the running Python interpreter (`sys.modules`).
   - Analyzers use `ast.parse()` on Python source and regular expression tokenizers on JavaScript.
2. **Archive Security**:
   - Maximum upload size: 1 GB (1,073,741,824 bytes).
   - Maximum uncompressed size: 5 GB (5,000,000,000 bytes).
   - Maximum archive members: 50,000 entries.
   - Dangerous executable formats (`.exe`, `.dll`, `.com`, `.msi`) are rejected.
3. **Information Disclosure Prevention**:
   - Internal server paths (`/tmp/vibesec-...`, `C:\Users\...`) are masked before being displayed in reports or UI. Target names use relative repository paths or repo URLs.
4. **Local Directory Gating**:
   - Local directory path scanning is hidden from the web interface by default. It can only be activated by explicitly setting `VIBESEC_ALLOW_LOCAL_PATH=1` in self-hosted deployments.

---

## 8. Configuration & Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `VIBESEC_ALLOW_LOCAL_PATH` | `0` | Set to `1`, `true`, or `yes` to enable local filesystem directory scanning in the Streamlit web dashboard. |
| `VIBESEC_DB_PATH` | `~/.vibesec/vibesec.db` | Custom file path for the SQLite database. Automatically falls back to `:memory:` if the location is unwritable. |
| `VIBESEC_OFFLINE` | `0` | Set to `1` to force offline operation, disabling external network queries and using neutral EPSS/KEV signals. |

---

## 9. Test Suite & Verification Matrix

The repository includes a comprehensive test suite executed via `pytest`:

1. **`tests/test_extraction.py`**:
   - Verifies valid ZIP extraction and single top-level directory unwrap.
   - Asserts rejection of path traversal (`../../evil.txt`), absolute paths (`/etc/passwd`), Windows drives (`C:/Windows`), and dangerous executables (`malware.exe`).
   - Asserts rejection of oversized archives (> 1 GB) and member counts (> 50,000).
   - Validates proper descending into project directories when `.DS_Store` or `__MACOSX` metadata is present.
2. **`tests/test_comment_fp.py`**:
   - Verifies that commented vulnerabilities and multiline docstrings are not flagged by Semgrep, Bandit, or Gitleaks.
   - Verifies that genuine vulnerabilities (e.g. actual hardcoded API keys and `shell=True` command injections) are still detected accurately.
3. **`tests/test_ui_redesign.py`**:
   - Verifies light theme configuration in `.streamlit/config.toml`.
   - Confirms zero emojis exist across the codebase.
   - Verifies complete removal of Scan History, Toolchain Status, and Offline Mode UI elements.
   - Tests headless execution of `app.py` via `AppTest` in both initial state and with simulated scan results.
   - Asserts 1 GB upload size and 50,000 file contents limits.
   - Verifies CSS rules hiding the "Press Enter to apply" UI glitch.
4. **`tests/test_web_deployment.py`**:
   - Verifies storage fallback to `:memory:` on read-only environments.
   - Verifies report filename sanitization when targets contain slashes or URLs.
   - Confirms truthful `AnalysisCoverage.INCOMPLETE` reporting on scanner tool failures.

---

## 10. Summary

VibeSec combines deterministic multi-scanner orchestration, static AST taint analysis, and dependency reachability into a production-grade application security platform. By eliminating comment false positives, calculating mathematically consistent risk postures, and enforcing an enterprise light theme, it delivers actionable, verifiable security intelligence for modern software.
