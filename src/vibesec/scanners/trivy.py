"""Trivy wrapper — dependency CVEs, secrets, misconfigurations, and licenses.

Runs trivy filesystem scan with expanded scanner coverage:
  - vuln: dependency CVEs from lockfiles
  - secret: hardcoded secrets (overlaps with Gitleaks for cross-validation)
  - misconfig: Dockerfile, docker-compose, IaC misconfigurations
  - license: risky/restrictive open-source license detection
"""

from __future__ import annotations

import os
from pathlib import Path

from .base import find_executable, get_tool_version, run_json, tool_available


def run_trivy(target: Path, offline: bool = False) -> dict:
    """Run trivy filesystem scan for vulnerabilities, secrets, misconfigs, and licenses."""
    version = get_tool_version("trivy")
    if not tool_available("trivy"):
        return {
            "Results": [],
            "_skipped": "trivy not installed",
            "_state": "SKIPPED",
            "_reason": "trivy not installed",
            "_version": version,
        }

    is_off = offline or (os.environ.get("VIBESEC_OFFLINE", "").strip() in ("1", "true", "yes", "on"))
    exe = find_executable("trivy") or "trivy"
    cmd = [
        exe, "fs",
        "--format", "json",
        "--scanners", "vuln,secret,misconfig,license",
        "--quiet",
        "--exit-code", "0",
    ]
    if is_off:
        cmd.extend(["--offline-scan", "--skip-db-update", "--skip-java-db-update"])
    cmd.append(str(target))

    try:
        data = run_json(cmd, timeout=90)
        if isinstance(data, dict):
            data["_state"] = "OK"
            data["_version"] = version
            return data
        return {"Results": data if isinstance(data, list) else [], "_state": "OK", "_version": version}
    except Exception as exc:
        return {
            "Results": [],
            "_skipped": f"trivy execution failed: {exc}",
            "_state": "FAILED",
            "_reason": str(exc),
            "_version": version,
        }
