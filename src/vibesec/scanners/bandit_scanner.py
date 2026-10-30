"""Bandit wrapper — secondary Python-specific SAST scanner.

Provides additional coverage beyond Semgrep for Python-specific security
issues. Falls back gracefully when bandit is not installed.
"""

from __future__ import annotations

from pathlib import Path

from .base import find_executable, get_tool_version, run_json, tool_available


def run_bandit(target: Path) -> dict:
    """Run bandit against Python files in the target directory.

    Enforces I-03:
    - Checks applicability (presence of Python files) before running
    - Not applicable = SKIPPED with reason, no warning
    """
    version = get_tool_version("bandit")
    if not tool_available("bandit"):
        return {
            "results": [],
            "_skipped": "bandit not installed",
            "_state": "SKIPPED",
            "_reason": "bandit not installed",
            "_version": version,
        }

    # Check if any Python files exist outside excluded dirs
    py_files = [
        f for f in target.rglob("*.py")
        if not any(part.lower() in {".venv", "venv", "env", "node_modules", "__pycache__", ".git"} for part in f.parts)
    ]
    if not py_files:
        return {
            "results": [],
            "_skipped": "no Python files found",
            "_state": "SKIPPED",
            "_reason": "no Python files found",
            "_version": version,
        }

    exe = find_executable("bandit") or "bandit"
    cmd = [
        exe,
        "-r", str(target),
        "-f", "json",
        "--quiet",
        "-x", ".venv,venv,env,node_modules,__pycache__,.git",
    ]

    try:
        data = run_json(cmd, timeout=300)
        if isinstance(data, dict):
            data["_state"] = "OK"
            data["_version"] = version
            return data
        return {"results": data if isinstance(data, list) else [], "_state": "OK", "_version": version}
    except Exception as exc:
        return {
            "results": [],
            "_skipped": f"bandit execution failed: {exc}",
            "_state": "FAILED",
            "_reason": str(exc),
            "_version": version,
        }
