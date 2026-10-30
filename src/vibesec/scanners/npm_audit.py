"""npm audit wrapper — JavaScript/TypeScript dependency vulnerability scanning.

Runs `npm audit --package-lock-only --json --ignore-scripts` in each lockfile's directory.
Falls back gracefully when npm is not installed or no package-lock.json exists.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .base import find_executable, get_tool_version, tool_available


def run_npm_audit(target: Path) -> dict:
    """Run npm audit against Node.js package-lock.json files in the target directory.

    Enforces I-02:
    - Runs `npm audit --package-lock-only --json --ignore-scripts`
    - Parses stdout regardless of exit code (exit code 1 means vulnerabilities exist)
    - Supports v7+ JSON format (auditReportVersion: 2, vulnerabilities map)
    - Timeout 60s
    - No package-lock.json = SKIPPED with reason
    - Only marks FAILED when JSON cannot be parsed or registry unreachable
    """
    version = get_tool_version("npm")
    if not tool_available("npm"):
        return {
            "vulnerabilities": {},
            "_skipped": "npm not installed",
            "_state": "SKIPPED",
            "_reason": "npm not installed",
            "_version": version,
        }

    npm_bin = find_executable("npm") or "npm"

    # Search for all package-lock.json files excluding node_modules
    lockfiles = [
        f for f in target.rglob("package-lock.json")
        if not any(part.lower() in {"node_modules", ".git", "dist", "build"} for part in f.parts)
    ]
    if not lockfiles:
        return {
            "vulnerabilities": {},
            "_skipped": "no package-lock.json found",
            "_state": "SKIPPED",
            "_reason": "no package-lock.json found",
            "_version": version,
        }

    combined_vulns: dict = {}
    combined_advisories: dict = {}
    last_error = ""
    successful_runs = 0

    for lockfile in lockfiles:
        cmd = [npm_bin, "audit", "--package-lock-only", "--json", "--ignore-scripts"]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(lockfile.parent),
            )
        except subprocess.TimeoutExpired:
            last_error = "npm audit timed out after 60s"
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        stdout = res.stdout.strip()
        if not stdout:
            stderr = res.stderr.strip()
            if stderr:
                first_line = stderr.splitlines()[0]
                last_error = first_line
            continue

        try:
            data = json.loads(stdout)
            successful_runs += 1
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], dict):
                combined_vulns.update(data["vulnerabilities"])
            if "advisories" in data and isinstance(data["advisories"], dict):
                combined_advisories.update(data["advisories"])
        except json.JSONDecodeError:
            stderr = res.stderr.strip()
            first_line = stderr.splitlines()[0] if stderr else "npm audit returned non-JSON"
            last_error = first_line

    if successful_runs == 0 and last_error:
        # Determine if offline/network registry error
        is_net_err = any(k in last_error.lower() for k in ("enotfound", "eai_again", "network", "fetch failed", "registry"))
        state = "DEGRADED" if is_net_err else "FAILED"
        return {
            "vulnerabilities": {},
            "_skipped": f"npm audit failed: {last_error}",
            "_state": state,
            "_reason": last_error,
            "_version": version,
        }

    return {
        "vulnerabilities": combined_vulns,
        "advisories": combined_advisories,
        "_state": "OK",
        "_version": version,
    }
