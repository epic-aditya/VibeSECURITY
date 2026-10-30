"""pip-audit wrapper — Python dependency vulnerability scanning.

Parses requirements.txt / pyproject.toml using pip-audit for known CVEs.
Falls back gracefully when pip-audit is not installed.
"""

from __future__ import annotations

from pathlib import Path

from .base import find_executable, get_tool_version, run_json, tool_available


def _is_pinned_requirements(req_path: Path) -> bool:
    try:
        lines = req_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return False
    has_pkg = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        has_pkg = True
        if "==" not in line or any(op in line for op in (">=", "<=", "~=", "!=", "<", ">")):
            return False
    return has_pkg


def run_pip_audit(target: Path) -> dict:
    """Run pip-audit against Python dependency files in the target directory.

    Enforces I-01:
    - Runs only as `pip-audit --disable-pip --no-deps -r <file> -f json`
    - Checks for pinned requirements (==). If not fully pinned, SKIPPED with reason:
      "requirements not pinned; Trivy covers Python dependencies"
    """
    version = get_tool_version("pip-audit")
    if not tool_available("pip-audit"):
        return {
            "dependencies": [],
            "_skipped": "pip-audit not installed",
            "_state": "SKIPPED",
            "_reason": "pip-audit not installed",
            "_version": version,
        }

    exe = find_executable("pip-audit") or "pip-audit"

    # Look for requirements files
    req_files = [
        f for f in target.rglob("requirements*.txt")
        if not any(part.lower() in {".venv", "venv", ".git", "node_modules"} for part in f.parts)
    ]
    if not req_files:
        return {
            "dependencies": [],
            "_skipped": "no Python dependency file found",
            "_state": "SKIPPED",
            "_reason": "no Python dependency file found",
            "_version": version,
        }

    # Verify requirements are pinned with ==
    for rf in req_files:
        if not _is_pinned_requirements(rf):
            return {
                "dependencies": [],
                "_skipped": "requirements not pinned; Trivy covers Python dependencies",
                "_state": "SKIPPED",
                "_reason": "requirements not pinned; Trivy covers Python dependencies",
                "_version": version,
            }

    all_deps: list = []
    for rf in req_files:
        cmd = [
            exe,
            "--disable-pip",
            "--no-deps",
            "-r", str(rf),
            "-f", "json",
        ]
        try:
            result = run_json(cmd, cwd=target, timeout=60)
            if isinstance(result, list):
                all_deps.extend(result)
            elif isinstance(result, dict):
                all_deps.extend(result.get("dependencies", []))
        except Exception as exc:
            return {
                "dependencies": all_deps,
                "_skipped": f"pip-audit execution failed: {exc}",
                "_state": "FAILED",
                "_reason": str(exc),
                "_version": version,
            }

    return {
        "dependencies": all_deps,
        "_state": "OK",
        "_version": version,
    }
