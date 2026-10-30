"""Semgrep wrapper — default ruleset + the custom vibe-code rules (core contribution)."""

from __future__ import annotations

import os
from pathlib import Path

from .base import find_executable, get_tool_version, run_json, tool_available

# Custom vibe-code rules shipped with the platform (plan Section 5).
VIBE_RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "vibe_code"


def run_semgrep(
    target: Path,
    *,
    include_vibe_rules: bool = True,
    default_rules: bool = True,
    offline: bool = False,
) -> dict:
    """Run semgrep with p/security-audit plus our vibe-code rules.

    Supports graceful fallback and DEGRADED state if registry rules are
    unreachable in offline mode.
    """
    version = get_tool_version("semgrep")
    if not tool_available("semgrep"):
        return {
            "results": [],
            "_skipped": "semgrep not installed",
            "_state": "SKIPPED",
            "_reason": "semgrep not installed",
            "_version": version,
        }

    is_off = offline or (os.environ.get("VIBESEC_OFFLINE", "").strip() in ("1", "true", "yes", "on"))
    exe = find_executable("semgrep") or "semgrep"

    base_cmd = [
        exe, "scan",
        "--json",
        "--timeout", "60",
        "--max-target-bytes", "1000000",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--quiet",
    ]

    configs = []
    if default_rules and not is_off:
        configs.append("p/security-audit")
    if include_vibe_rules and VIBE_RULES_DIR.is_dir():
        rule_files = sorted(list(VIBE_RULES_DIR.glob("*.yaml")) + list(VIBE_RULES_DIR.glob("*.yml")))
        if rule_files:
            for rf in rule_files:
                configs.append(str(rf))
        else:
            configs.append(str(VIBE_RULES_DIR))
    if not configs and VIBE_RULES_DIR.is_dir():
        configs.append(str(VIBE_RULES_DIR))

    cmd = list(base_cmd)
    for config in configs:
        cmd.extend(["--config", config])
    cmd.append(str(target))

    try:
        data = run_json(cmd, timeout=600)
        state = "DEGRADED" if (default_rules and is_off) else "OK"
        reason = "registry rules unreachable offline; custom rules ran" if (default_rules and is_off) else ""
        if isinstance(data, dict):
            data["_state"] = state
            data["_reason"] = reason
            data["_version"] = version
            return data
        return {"results": data if isinstance(data, list) else [], "_state": state, "_reason": reason, "_version": version}
    except Exception as exc:
        # If running both configs failed, fallback to local vibe rules only
        if "p/security-audit" in configs and VIBE_RULES_DIR.is_dir():
            fallback_cmd = list(base_cmd) + ["--config", str(VIBE_RULES_DIR), str(target)]
            try:
                data = run_json(fallback_cmd, timeout=300)
                if isinstance(data, dict):
                    data["_state"] = "DEGRADED"
                    data["_reason"] = "registry rules unreachable; custom rules ran"
                    data["_version"] = version
                    return data
                return {"results": data if isinstance(data, list) else [], "_state": "DEGRADED", "_reason": "registry rules unreachable; custom rules ran", "_version": version}
            except Exception:
                pass
        return {
            "results": [],
            "_skipped": f"semgrep execution failed: {exc}",
            "_state": "FAILED",
            "_reason": str(exc),
            "_version": version,
        }
