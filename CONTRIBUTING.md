# Contributing to VibeSec

Thank you for your interest in contributing to VibeSec. We welcome contributions that improve scanner accuracy, performance, and developer experience.

## Non-Negotiable Ground Rules

1. **Truth Over Appearance**: Never commit fabricated test passes, metrics, or benchmark numbers. All measurements and claims must be reproducible by running code in the repository.
2. **No Marketing Buzzwords**: Avoid unsupported claims (e.g., "zero false positives", "enterprise-grade", "audit-ready"). Use precise, measured terminology grounded in test results.
3. **Zero Untrusted Execution**: Security analysis must never execute untrusted target repository code. Parsing is strictly static.
4. **Coverage & Quality Net**: Core modules (`prioritizer`, `normalizer`, `correlator`, `grouping`, `reachability`) must maintain $\ge 80\%$ line coverage. All 8 verification gates must pass cleanly.

## Development Setup

### 1. Clone & Environment
```bash
git clone https://github.com/epic-aditya/VibeSECURITY.git
cd VibeSECURITY

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
pip install -r requirements.txt
pip install ruff mypy pytest pytest-cov jsonschema hypothesis
```

### 2. Verify Toolchain
Check that required scanners and runtime dependencies are available:
```bash
vibesec doctor
```

## Running Verification Gates

Before submitting any Pull Request, ensure that all quality gates pass:

```bash
# 1. Format and lint checks
python -m ruff check src app.py tests scripts evaluation

# 2. Strict type checking
python -m mypy src

# 3. Documentation drift check
python scripts/update_docs.py --check

# 4. Full test suite with coverage
pytest --cov=src/vibesec

# 5. Complete gate verification suite
python scripts/verify.py
```

## Code Guidelines

- **Style**: Python code must follow PEP 8 and pass `ruff` with 100-character line lengths.
- **Type Annotations**: All new functions and public methods in `src/vibesec/` require explicit type annotations.
- **Error Handling**: Graceful degradation is required when optional external scanners (Trivy, Semgrep, Gitleaks) are missing or encounter parsing errors.
- **Tests**: Every new feature or bug fix must include corresponding tests under `tests/`.

## Pull Request Process

1. Create a feature or bugfix branch (`git checkout -b feature/your-feature-name`).
2. Make atomic commits with clear, descriptive messages following conventional commit style (`feat:`, `fix:`, `docs:`, `test:`).
3. Ensure all tests and `scripts/verify.py` pass.
4. Open a Pull Request against `main` describing the changes, motivation, and verification steps.

