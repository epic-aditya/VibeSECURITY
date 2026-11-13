"""Stage 5 — Finding Correlator + Dedup.

Partition findings into:
1. Code, secret, config, license, supply_chain findings:
   Heuristic merge: exact rule+file collisions, then overlapping lines + related
   CWE family in the same file.
2. Dependency findings (SCA):
   NEVER merge by file+line. Correlate by (ecosystem, package, installed_version, vuln_id_or_alias).
   Merge Trivy, pip-audit, and npm-audit findings only when they share a CVE/GHSA alias.
   If multiple installed versions of the same package share a CVE, record them
   as affected_instances on one finding, eliminating unrelated "also affected" noise.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

try:
    import yaml

    _YAML_OK = True
except Exception:  # pragma: no cover
    _YAML_OK = False

_DATA_DIR = Path(__file__).resolve().parent / "data"

# Related-CWE clusters: code issues from the same family merge when co-located.
_CWE_FAMILY = {
    "CWE-89": "injection",
    "CWE-78": "injection",
    "CWE-77": "injection",
    "CWE-94": "injection",
    "CWE-95": "injection",
    "CWE-798": "secrets",
    "CWE-321": "secrets",
    "CWE-259": "secrets",
    "CWE-256": "secrets",
    "CWE-522": "secrets",
    "CWE-605": "network_binding",
    "CWE-1327": "network_binding",
    "CWE-16": "network_binding",
    "CWE-489": "network_binding",
    "CWE-942": "config",
    "CWE-22": "path_traversal",
    "CWE-73": "path_traversal",
    "CWE-918": "ssrf",
    "CWE-502": "deserialization",
    "CWE-611": "deserialization",
    "CWE-284": "authz",
    "CWE-285": "authz",
    "CWE-639": "authz",
    "CWE-862": "authz",
    "CWE-863": "authz",
    "CWE-306": "authz",
    "CWE-352": "csrf",
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-116": "xss",
}


def _load_cwe_catalog() -> dict[str, str]:
    catalog = dict(_CWE_FAMILY)
    path = _DATA_DIR / "cwe_equivalence.yaml"
    if _YAML_OK and path.is_file():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for cls, meta in (data.get("classes") or {}).items():
                for cwe in (meta or {}).get("mixed", []):
                    catalog[str(cwe).upper()] = str(cls)
        except Exception:
            pass
    return catalog


_CWE_CATALOG = _load_cwe_catalog()


def _family(cwe: str) -> str:
    c = (cwe or "").upper().strip()
    return _CWE_CATALOG.get(c, c)


def _prefer_code(a: Finding, b: Finding) -> Finding:
    """Pick the stronger code finding as the merge base; absorb the other."""
    if a.severity.rank > b.severity.rank:
        base, other = a, b
    elif b.severity.rank > a.severity.rank:
        base, other = b, a
    elif a.rule_id.startswith("vibe.") and not b.rule_id.startswith("vibe."):
        base, other = a, b
    elif b.rule_id.startswith("vibe.") and not a.rule_id.startswith("vibe."):
        base, other = b, a
    else:
        base, other = a, b

    if "dockerfile" in (base.location.file.lower() if base.location else ""):
        if a.location.start_line == 1 and b.location.start_line > 1:
            base.location = b.location
        elif b.location.start_line == 1 and a.location.start_line > 1:
            base.location = a.location

    base.confidence = max(base.confidence, other.confidence)
    base.taint_reachable = base.taint_reachable or other.taint_reachable
    base.sensitive_asset = base.sensitive_asset or other.sensitive_asset
    base.auth_context = base.auth_context or other.auth_context
    base.impact_class = base.impact_class or other.impact_class
    if not base.evidence_chain and other.evidence_chain or other.evidence_chain and len(other.evidence_chain) < len(base.evidence_chain):
        base.evidence_chain = list(other.evidence_chain)

    # Merge unique evidence lines without duplicates
    ev_lines = []
    seen_lines = set()
    for ev_line in (base.evidence or "").splitlines() + (other.evidence or "").splitlines():
        l_str = ev_line.strip()
        if l_str and l_str not in seen_lines:
            seen_lines.add(l_str)
            ev_lines.append(ev_line)
    base.evidence = "\n".join(ev_lines)[:800]

    for src in other.sources:
        if src not in base.sources:
            base.sources.append(src)
    return base



def _extract_cve_or_ghsa(text: str) -> set[str]:
    """Extract all CVE-YYYY-NNNN or GHSA-xxxx-xxxx tokens."""
    matches = set(re.findall(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", text, re.IGNORECASE))
    return {m.upper() for m in matches}


def _prefer_dep(a: Finding, b: Finding) -> Finding:
    """Merge two dependency findings that reference the same vulnerability."""
    base, other = (a, b) if a.severity.rank >= b.severity.rank else (b, a)
    base.confidence = max(base.confidence, other.confidence)
    for src in other.sources:
        if src not in base.sources:
            base.sources.append(src)

    # Union aliases
    combined_aliases = list(dict.fromkeys(base.aliases + other.aliases))
    base.aliases = combined_aliases

    # Merge affected instances cleanly without unrelated string noise
    instances = set(base.affected_instances)
    instances.update(other.affected_instances)
    if base.package_name:
        if base.package_version and base.package_version != "?":
            instances.add(f"{base.package_name}@{base.package_version}")
        if other.package_version and other.package_version != "?":
            instances.add(f"{other.package_name}@{other.package_version}")
    base.affected_instances = sorted(list(instances))

    # Prefer more specific fix snippet
    if not base.fix_snippet and other.fix_snippet:
        base.fix_snippet = other.fix_snippet

    # If CWE is generic on base but specific on other, copy it
    if (not base.cwe or base.cwe in ("CWE-0", "CWE-1395")) and other.cwe and other.cwe not in ("CWE-0", "CWE-1395"):
        base.cwe = other.cwe

    return base


def _norm_file(f: str) -> str:
    s = (f or "").replace("\\", "/").strip().lower()
    while s.startswith("./"):
        s = s[2:]
    return s


def _same_file(f1: str, f2: str) -> bool:
    n1 = _norm_file(f1)
    n2 = _norm_file(f2)
    if n1 == n2:
        return True
    return n1.endswith("/" + n2) or n2.endswith("/" + n1)


def _correlate_code(findings: list[Finding]) -> list[Finding]:
    """Correlate code, secret, config, and license findings."""
    merged: list[Finding] = []

    sorted_findings = sorted(
        findings,
        key=lambda x: (
            x.location.file.replace("\\", "/").lower() if x.location else "",
            x.location.start_line if x.location else 0,
            -x.severity.rank,
            x.rule_id,
            x.title,
        ),
    )

    for f in sorted_findings:
        matched = False
        f_fam = _family(f.cwe)

        # Pass 1: Exact matches (Dockerfile secrets, same line duplicate, or exact rule collision within 2 lines)
        for idx, m in enumerate(merged):
            same_file = _same_file(f.location.file if f.location else "", m.location.file if m.location else "")
            line_diff = abs((f.location.start_line if f.location else 0) - (m.location.start_line if m.location else 0))
            m_fam = _family(m.cwe)

            # Dockerfile secrets special merge: Trivy at line 1 and vibe at line 4/5
            is_dockerfile = "dockerfile" in (f.location.file.lower() if f.location else "")
            both_secrets = (f.category == "secret" or f_fam == "secrets" or "secret" in f.rule_id.lower()) and \
                           (m.category == "secret" or m_fam == "secrets" or "secret" in m.rule_id.lower())
            if same_file and is_dockerfile and both_secrets:
                merged[idx] = _prefer_code(m, f)
                matched = True
                break

            # 1. Merge duplicates at the exact same line if same rule, same CWE family, or both secrets
            if same_file and line_diff == 0 and (f.rule_id == m.rule_id or f_fam == m_fam or both_secrets):
                merged[idx] = _prefer_code(m, f)
                matched = True
                break

            # 2. Exact rule collision at same line or within +/- 2 lines
            if same_file and line_diff <= 2 and f.rule_id == m.rule_id:
                merged[idx] = _prefer_code(m, f)
                matched = True
                break

        # Pass 2: Loose matches (Equivalent CWE class within +/- 2 lines)
        if not matched:
            for idx, m in enumerate(merged):
                same_file = _same_file(f.location.file if f.location else "", m.location.file if m.location else "")
                line_diff = abs((f.location.start_line if f.location else 0) - (m.location.start_line if m.location else 0))
                m_fam = _family(m.cwe)

                if same_file and line_diff <= 2:
                    if f_fam == m_fam and f_fam not in ("", "CWE-0", "unknown"):
                        merged[idx] = _prefer_code(m, f)
                        matched = True
                        break
                    # Both injection or both secrets or both code execution (eval / exec)
                    if f_fam == m_fam and (
                        ("eval" in f.rule_id.lower() and "eval" in m.rule_id.lower())
                        or ("exec" in f.rule_id.lower() and "exec" in m.rule_id.lower())
                    ):
                        merged[idx] = _prefer_code(m, f)
                        matched = True
                        break

        if not matched:
            merged.append(f)

    return merged



def _correlate_dependencies(findings: list[Finding]) -> list[Finding]:
    """Correlate dependency findings by package and shared vulnerability identifier."""
    if not findings:
        return []

    # Prepare findings with normalized tokens
    for f in findings:
        if not f.aliases:
            tokens = _extract_cve_or_ghsa(f.rule_id) | _extract_cve_or_ghsa(f.title)
            f.aliases = sorted(list(tokens)) if tokens else [f.rule_id.split(".", 1)[-1]]
        if not f.affected_instances and f.package_name and f.package_version and f.package_version != "?":
            f.affected_instances = [f"{f.package_name}@{f.package_version}"]

    merged: list[Finding] = []
    sorted_deps = sorted(
        findings,
        key=lambda x: (
            (x.ecosystem or "").lower(),
            (x.package_name or "").lower(),
            (x.package_version or "").lower(),
            x.rule_id,
            x.location.file.replace("\\", "/").lower() if x.location else "",
            x.location.start_line if x.location else 0,
        ),
    )
    for f in sorted_deps:
        matched = False
        f_pkg = (f.package_name or "").lower().strip()
        f_eco = (f.ecosystem or "").lower().strip()
        f_aliases = {a.upper() for a in f.aliases}

        for idx, m in enumerate(merged):
            m_pkg = (m.package_name or "").lower().strip()
            m_eco = (m.ecosystem or "").lower().strip()
            m_aliases = {a.upper() for a in m.aliases}

            # Check if same package in same ecosystem
            if f_pkg and m_pkg and f_pkg == m_pkg and (not f_eco or not m_eco or f_eco == m_eco):
                # Check for shared CVE/GHSA alias or identical rule_id
                shared_aliases = f_aliases & m_aliases
                if shared_aliases or (f.rule_id == m.rule_id and f.rule_id != "trivy.UNKNOWN"):
                    merged[idx] = _prefer_dep(m, f)
                    matched = True
                    break

        if not matched:
            merged.append(f)

    return merged


def correlate(findings: list[Finding]) -> list[Finding]:
    """Merge findings that point at the same underlying issue."""
    dep_findings: list[Finding] = []
    code_findings: list[Finding] = []

    for f in findings:
        if f.category == "dependency" or (f.package_name and f.category not in ("code", "secret", "config", "license")):
            dep_findings.append(f)
        else:
            code_findings.append(f)

    merged_code = _correlate_code(code_findings)
    merged_dep = _correlate_dependencies(dep_findings)
    return merged_code + merged_dep
