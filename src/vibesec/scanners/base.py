"""Shared subprocess helpers for scanner wrappers."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class ScannerError(Exception):
    pass


def find_executable(name: str) -> str | None:
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return find_executable(name) is not None


_VERSION_CACHE: dict[str, str | None] = {}


def get_tool_version(name: str) -> str | None:
    if name in _VERSION_CACHE:
        return _VERSION_CACHE[name]
    exe = find_executable(name)
    if not exe:
        return None
    flag = "version" if name in ("gitleaks",) else "--version"
    try:
        res = subprocess.run([exe, flag], capture_output=True, text=True, timeout=5)
        out = (res.stdout or res.stderr).strip()
        import re
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", out)
        v = m.group(1) if m else None
        _VERSION_CACHE[name] = v
        return v
    except Exception:
        _VERSION_CACHE[name] = None
        return None


def run_json(cmd: list[str], cwd: Path | None = None, timeout: int = 600) -> dict | list:
    """Run a scanner subprocess and parse its stdout as JSON."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"Scanner binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"{cmd[0]} timed out after {timeout}s") from exc

    stdout = result.stdout.strip()
    if not stdout:
        # Some tools exit non-zero when findings exist; tolerate that if JSON-less.
        return {}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        snippet = stdout[:200]
        raise ScannerError(f"{cmd[0]} produced non-JSON output: {snippet}") from exc
