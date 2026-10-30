"""License policy evaluation against SPDX expressions and exposure classes.

SPDX logic:
- 'A OR B' is acceptable if any branch is permissive.
- 'A AND B' needs all branches acceptable.
- Permissive licenses produce no findings.
- Strong/network copyleft (GPL, AGPL, SSPL, EUPL) = VIOLATION (severity by exposure).
- Weak copyleft (LGPL, MPL, EPL, CDDL) = REVIEW (INFO for toolchain/test scope).
- Unknown/missing/custom = REVIEW.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Severity

try:
    import yaml
    _YAML_OK = True
except Exception:
    _YAML_OK = False

_DATA_DIR = Path(__file__).resolve().parent / "data"


def load_license_policy() -> dict[str, set[str]]:
    policy_path = _DATA_DIR / "license_policy.yaml"
    policy: dict[str, set[str]] = {
        "permissive": {
            "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "bsd-4-clause",
            "bsd-3-clause-clear", "isc", "0bsd", "unlicense", "cc0-1.0",
            "blueoak-1.0.0", "python-2.0", "cc-by-4.0", "zlib",
        },
        "strong_copyleft": {
            "gpl-2.0", "gpl-2.0-only", "gpl-2.0-or-later", "gpl-3.0", "gpl-3.0-only",
            "gpl-3.0-or-later", "agpl-3.0", "agpl-3.0-only", "agpl-3.0-or-later",
            "sspl-1.0", "eupl-1.1", "eupl-1.2",
        },
        "weak_copyleft": {
            "lgpl-2.0", "lgpl-2.1", "lgpl-2.1-only", "lgpl-2.1-or-later", "lgpl-3.0",
            "lgpl-3.0-only", "lgpl-3.0-or-later", "mpl-1.1", "mpl-2.0", "epl-1.0",
            "epl-2.0", "cddl-1.0", "cddl-1.1",
        },
    }

    if _YAML_OK and policy_path.is_file():
        try:
            data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
            for k in ("permissive", "strong_copyleft", "weak_copyleft"):
                if k in data and isinstance(data[k], list):
                    policy[k] = {str(item).lower().strip() for item in data[k]}
        except Exception:
            pass
    return policy


_POLICY = load_license_policy()


def _is_permissive_single(lic: str) -> bool:
    l_clean = lic.lower().strip()
    if not l_clean or l_clean in ("unknown", "unlicensed", "none"):
        return False
    if l_clean.startswith("bsd-") or l_clean == "bsd":
        return True
    return l_clean in _POLICY["permissive"]


def _is_strong_copyleft_single(lic: str) -> bool:
    l_clean = lic.lower().strip()
    if any(k in l_clean for k in ("agpl", "sspl", "eupl")):
        return True
    if re.search(r"\bgpl\b", l_clean) and "lgpl" not in l_clean:
        return True
    return l_clean in _POLICY["strong_copyleft"]


def _is_weak_copyleft_single(lic: str) -> bool:
    l_clean = lic.lower().strip()
    if any(k in l_clean for k in ("lgpl", "mpl", "epl", "cddl")):
        return True
    return l_clean in _POLICY["weak_copyleft"]


def evaluate_license(
    license_str: str,
    exposure_class: str = "UNKNOWN",
    scope: str = "prod",
) -> tuple[str, Severity, str]:
    """Evaluate a license name or SPDX expression.

    Returns:
      (status, severity, notes)
      where status is 'ACCEPTABLE', 'REVIEW', or 'VIOLATION'.
    """
    expr = (license_str or "").strip()
    if not expr or expr.lower() in ("unknown", "none", "?", "custom"):
        return "REVIEW", Severity.INFO, "Missing or unknown license expression"

    # Handle SPDX OR: acceptable if ANY branch is permissive
    if " OR " in expr:
        branches = [b.strip(" ()") for b in expr.split(" OR ")]
        if any(_is_permissive_single(b) for b in branches):
            return "ACCEPTABLE", Severity.INFO, "Permissive branch in OR expression"
        if any(_is_weak_copyleft_single(b) for b in branches):
            sev = Severity.INFO if (exposure_class.startswith("TOOLCHAIN") or scope == "dev" or exposure_class == "TEST") else Severity.LOW
            return "REVIEW", sev, f"Weak copyleft in dual license: {expr}"
        sev = Severity.HIGH if exposure_class.startswith("RUNTIME") else Severity.LOW
        return "VIOLATION", sev, f"Strong copyleft dual license: {expr}"

    # Handle SPDX AND: needs ALL branches acceptable
    if " AND " in expr:
        branches = [b.strip(" ()") for b in expr.split(" AND ")]
        if all(_is_permissive_single(b) for b in branches):
            return "ACCEPTABLE", Severity.INFO, "All branches permissive in AND expression"
        if any(_is_strong_copyleft_single(b) for b in branches):
            sev = Severity.HIGH if exposure_class.startswith("RUNTIME") else Severity.LOW
            return "VIOLATION", sev, f"Strong copyleft in multi-license: {expr}"
        sev = Severity.INFO if (exposure_class.startswith("TOOLCHAIN") or scope == "dev" or exposure_class == "TEST") else Severity.LOW
        return "REVIEW", sev, f"Weak copyleft in multi-license: {expr}"

    clean = expr.strip(" ()")
    if _is_permissive_single(clean):
        return "ACCEPTABLE", Severity.INFO, "Permissive license"

    if _is_strong_copyleft_single(clean):
        sev = Severity.HIGH if exposure_class.startswith("RUNTIME") else Severity.LOW
        return "VIOLATION", sev, f"Strong/network copyleft license: {clean}"

    if _is_weak_copyleft_single(clean):
        sev = Severity.INFO if (exposure_class.startswith("TOOLCHAIN") or scope == "dev" or exposure_class == "TEST") else Severity.LOW
        return "REVIEW", sev, f"Weak copyleft license: {clean}"

    return "REVIEW", Severity.INFO, f"Review custom/unrecognized license: {clean}"
