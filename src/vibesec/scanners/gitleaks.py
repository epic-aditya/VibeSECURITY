"""Gitleaks wrapper — hardcoded secrets (CWE-798)."""

from __future__ import annotations

import json
from pathlib import Path

from .base import find_executable, get_tool_version, run_json, tool_available


def run_gitleaks(target: Path) -> dict:
    """Run gitleaks in no-git (filesystem) mode; exit code 14 means findings."""
    version = get_tool_version("gitleaks")
    if not tool_available("gitleaks"):
        return {
            "results": [],
            "_skipped": "gitleaks not installed",
            "_state": "SKIPPED",
            "_reason": "gitleaks not installed",
            "_version": version,
        }

    exe = find_executable("gitleaks") or "gitleaks"
    report_path = target / ".gitleaks-report.json"
    cmd = [
        exe, "detect",
        "--source", str(target),
        "--no-git",
        "--report-format", "json",
        "--report-path", str(report_path),
        "--exit-code", "0",
        "--quiet",
    ]
    try:
        run_json(cmd, timeout=300)
    except Exception as exc:
        return {
            "results": [],
            "_skipped": f"gitleaks execution failed: {exc}",
            "_state": "FAILED",
            "_reason": str(exc),
            "_version": version,
        }

    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            report_path.unlink(missing_ok=True)
            return {"results": data if isinstance(data, list) else [], "_state": "OK", "_version": version}
        except Exception as exc:
            report_path.unlink(missing_ok=True)
            return {"results": [], "_state": "FAILED", "_reason": f"Corrupt report: {exc}", "_version": version}

    return {"results": [], "_state": "OK", "_version": version}
