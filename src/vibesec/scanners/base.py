"""Shared subprocess helpers and hardened execution sandbox for scanner wrappers."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

MAX_CAPTURE_BYTES = 25 * 1024 * 1024  # 25 MB cap

_ALLOWED_ENV_VARS = {
    # System essentials
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "WINDIR",
    "COMSPEC",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    # Localization / shell
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    # Python & Node runtime indicators
    "PYTHONPATH",
    "PYTHONHOME",
    "VIRTUAL_ENV",
    "NODE_PATH",
    # Scanner configuration & cache
    "TRIVY_CACHE_DIR",
    "SEMGREP_RULES",
    # Platform flags
    "VIBESEC_OFFLINE",
}

_SENSITIVE_PATTERNS = re.compile(
    r".*(?:KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL|PRIVATE|APIKEY|ACCESS_KEY).*",
    re.IGNORECASE,
)


class ScannerError(Exception):
    pass


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return find_executable(name) is not None


_VERSION_CACHE: dict[str, str | None] = {}


def get_scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return a sanitized copy of os.environ with all secrets and non-whitelisted vars removed."""
    clean: dict[str, str] = {}
    for k, v in os.environ.items():
        k_upper = k.upper()
        if k_upper in _ALLOWED_ENV_VARS:
            if not _SENSITIVE_PATTERNS.match(k_upper) or k_upper == "PATHEXT":
                clean[k] = v

    # Prohibit telemetry and version checking across all scanner tools
    clean["SEMGREP_SEND_METRICS"] = "off"
    clean["SEMGREP_VERSION_CHECK"] = "off"
    clean["TRIVY_NO_PROGRESS"] = "true"
    clean["DO_NOT_TRACK"] = "1"

    if extra:
        clean.update(extra)
    return clean


def run_subprocess(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
    max_bytes: int = MAX_CAPTURE_BYTES,
) -> tuple[str, str, int]:
    """Execute a scanner subprocess with strict argv array, timeout, scrubbed env, and output caps."""
    if not isinstance(cmd, list) or not cmd:
        raise ScannerError("Command must be a non-empty list of strings")
    cmd_str = [str(arg) for arg in cmd]
    clean_env = get_scrubbed_env(env)

    try:
        proc = subprocess.Popen(
            cmd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=clean_env,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"Scanner binary not found: {cmd_str[0]}") from exc
    except Exception as exc:
        raise ScannerError(f"Failed to start {cmd_str[0]}: {exc}") from exc

    try:
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
        raise ScannerError(f"{cmd_str[0]} timed out after {timeout}s") from exc
    except Exception as exc:
        proc.kill()
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
        raise ScannerError(f"{cmd_str[0]} execution error: {exc}") from exc

    # Cap captured outputs to prevent memory exhaustion
    if len(stdout_bytes) > max_bytes:
        stdout_bytes = stdout_bytes[:max_bytes]
    if len(stderr_bytes) > max_bytes:
        stderr_bytes = stderr_bytes[:max_bytes]

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    return stdout, stderr, proc.returncode


def get_tool_version(name: str) -> str | None:
    if name in _VERSION_CACHE:
        return _VERSION_CACHE[name]
    exe = find_executable(name)
    if not exe:
        return None
    flag = "version" if name in ("gitleaks",) else "--version"
    try:
        stdout, stderr, _ = run_subprocess([exe, flag], timeout=5)
        out = (stdout or stderr).strip()
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
        v = m.group(1) if m else None
        _VERSION_CACHE[name] = v
        return v
    except Exception:
        _VERSION_CACHE[name] = None
        return None


def run_json(
    cmd: list[str],
    cwd: Path | None = None,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> dict | list:
    """Run a scanner subprocess and parse its stdout as JSON."""
    stdout, _, _ = run_subprocess(cmd=cmd, cwd=cwd, timeout=timeout, env=env)
    stdout_trimmed = stdout.strip()
    if not stdout_trimmed:
        return {}
    try:
        return json.loads(stdout_trimmed)
    except json.JSONDecodeError as exc:
        snippet = stdout_trimmed[:200]
        raise ScannerError(f"{cmd[0]} produced non-JSON output: {snippet}") from exc
