"""Dependency finding grouping and FixAction calculation.

Groups dozens of CVE rows for the same package into actionable, prioritized
FixAction items with minimal target versions and breaking-change indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding

try:
    from packaging.version import parse as parse_pkg_version

    def _parse_v(v: str) -> tuple[int, ...]:
        clean = re.sub(r"^[vV]", "", v.strip())
        try:
            pv = parse_pkg_version(clean)
            if hasattr(pv, "release") and pv.release:
                return pv.release
        except Exception:
            pass
        nums = re.findall(r"\d+", clean)
        return tuple(int(x) for x in nums) if nums else (0,)

except Exception:
    def _parse_v(v: str) -> tuple[int, ...]:
        clean = re.sub(r"^[vV]", "", v.strip())
        nums = re.findall(r"\d+", clean)
        return tuple(int(x) for x in nums) if nums else (0,)


_REACHABILITY_RANKS = {
    "CALLED": 5,
    "IMPORTED": 4,
    "TRANSITIVE_OF_RUNTIME": 3,
    "TRANSITIVE_OF_IMPORTED": 3,  # legacy
    "UNKNOWN": 2,
    "TOOLCHAIN": 1,
    "BUILD_TOOL": 1,  # legacy
    "NOT_IMPORTED": 0,
}

_EXPOSURE_RANKS = {
    "RUNTIME_SERVER": 6,
    "RUNTIME_BUNDLE": 6,
    "UNKNOWN": 3,
    "TOOLCHAIN_BUILD": 2,
    "TOOLCHAIN_DEVSERVER": 1,
    "TEST": 1,
}


@dataclass
class FixAction:
    action_id: str
    ecosystem: str
    package_name: str
    installed_version: str
    target_version: str
    cves_resolved: list[str] = field(default_factory=list)
    cves_unresolved: list[str] = field(default_factory=list)
    is_major_bump: bool = False
    scope: str = "prod"
    reachability: str = "UNKNOWN"
    exposure_class: str = "UNKNOWN"
    evidence_chain: list[str] = field(default_factory=list)
    max_score: float = 0.0
    kev_count: int = 0
    max_epss: float | None = None
    epss_measured: bool = False
    findings: list[Finding] = field(default_factory=list)
    manifest_file: str = ""

    @property
    def package(self) -> str:
        return self.package_name

    def summary(self) -> str:
        resolved_cnt = len(self.cves_resolved)
        bump_warn = " [MAJOR BUMP: may be breaking]" if self.is_major_bump else ""
        epss = f"{self.max_epss:.2f}" if self.epss_measured and self.max_epss is not None else "not measured"
        kev = "KEV" if self.kev_count else "no KEV"
        return (
            f"Upgrade {self.package_name} {self.installed_version} -> {self.target_version} "
            f"(resolves {resolved_cnt} CVEs, exposure: {self.exposure_class}, "
            f"reachability: {self.reachability}, max EPSS: {epss}, {kev}){bump_warn}"
        )

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "ecosystem": self.ecosystem,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "target_version": self.target_version,
            "cves_resolved": list(self.cves_resolved),
            "cves_unresolved": list(self.cves_unresolved),
            "is_major_bump": self.is_major_bump,
            "scope": self.scope,
            "reachability": self.reachability,
            "exposure_class": self.exposure_class,
            "evidence_chain": list(self.evidence_chain),
            "max_score": self.max_score,
            "kev_count": self.kev_count,
            "max_epss": self.max_epss,
            "epss_measured": self.epss_measured,
            "manifest_file": self.manifest_file,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FixAction:
        return cls(
            action_id=d.get("action_id", ""),
            ecosystem=d.get("ecosystem", ""),
            package_name=d.get("package_name", d.get("package", "")),
            installed_version=d.get("installed_version", ""),
            target_version=d.get("target_version", ""),
            cves_resolved=d.get("cves_resolved", []) or [],
            cves_unresolved=d.get("cves_unresolved", []) or [],
            is_major_bump=bool(d.get("is_major_bump", False)),
            scope=d.get("scope", "prod"),
            reachability=d.get("reachability", "UNKNOWN"),
            exposure_class=d.get("exposure_class", "UNKNOWN"),
            evidence_chain=list(d.get("evidence_chain") or []),
            max_score=float(d.get("max_score", 0.0) or 0.0),
            kev_count=int(d.get("kev_count", 0) or 0),
            max_epss=float(d["max_epss"]) if d.get("max_epss") is not None else None,
            epss_measured=bool(d.get("epss_measured", False)),
            manifest_file=d.get("manifest_file", ""),
        )


def _extract_fix_versions(finding: Finding) -> list[str]:
    """Extract candidate fix versions from finding metadata or text."""
    versions: list[str] = []
    text = f"{finding.fix_snippet or ''} {finding.evidence or ''} {finding.title or ''}"

    # Match fixed in / upgrade to patterns
    matches = re.findall(
        r"(?:fixed in|upgrade.*?to (?:version)?|to)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-zA-Z0-9_\-\.]*)?)",
        text,
        re.I,
    )
    for m in matches:
        m_clean = m.strip().rstrip(".,;)")
        if re.match(r"^\d+\.\d+", m_clean) and m_clean not in versions:
            versions.append(m_clean)

    return versions


def _pick_minimal_target(
    installed: str,
    finding_fixed_map: dict[str, list[str]],
) -> tuple[str, list[str], list[str], bool]:
    """Compute minimal target version that resolves max CVEs.

    Returns: (target_version, resolved_cves, unresolved_cves, is_major_bump)
    """
    inst_v = _parse_v(installed)
    inst_major = inst_v[0] if inst_v else 0

    all_cves = list(finding_fixed_map.keys())
    resolved: list[str] = []
    unresolved: list[str] = []

    # Collect candidate versions
    candidates: set[str] = set()
    for fix_list in finding_fixed_map.values():
        for fv in fix_list:
            candidates.add(fv)

    if not candidates:
        return ("no fix available", [], all_cves, False)

    sorted_candidates = sorted(list(candidates), key=lambda x: _parse_v(x))

    # Try to find a version in the same major that satisfies the max fixed version
    # Each CVE is resolved if target_version >= min(fix_list for that CVE)
    def cves_fixed_by(cand: str) -> list[str]:
        cand_v = _parse_v(cand)
        res = []
        for cve, fix_list in finding_fixed_map.items():
            if not fix_list:
                continue
            if any(cand_v >= _parse_v(fv) for fv in fix_list):
                res.append(cve)
        return res

    best_target = sorted_candidates[-1]
    best_resolved = cves_fixed_by(best_target)

    # Check if there is a version in the same major that resolves just as many
    same_major_candidates = [
        c for c in sorted_candidates if _parse_v(c) and _parse_v(c)[0] == inst_major
    ]
    for sm in same_major_candidates:
        sm_resolved = cves_fixed_by(sm)
        if len(sm_resolved) == len(best_resolved) and len(sm_resolved) > 0:
            best_target = sm
            best_resolved = sm_resolved
            break

    target_v = _parse_v(best_target)
    is_major = bool(target_v and inst_v and target_v[0] > inst_major)

    resolved = best_resolved
    unresolved = [c for c in all_cves if c not in resolved]

    return (best_target, resolved, unresolved, is_major)


def build_fix_actions(findings: list[Finding]) -> list[FixAction]:
    """Group dependency findings into ordered FixAction plans."""
    groups: dict[tuple[str, str, str, str], list[Finding]] = {}

    for f in findings:
        if f.category != "dependency":
            continue
        eco = (f.ecosystem or "npm").lower().strip()
        pkg = (f.package_name or "unknown").lower().strip()
        ver = (f.package_version or "?").strip()
        lockfile = (f.location.file or "").replace("\\", "/") if f.location else ""
        key = (eco, pkg, ver, lockfile)
        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    actions: list[FixAction] = []
    for (eco, pkg, ver, _lockfile), group in groups.items():
        finding_fixed: dict[str, list[str]] = {}
        for f in group:
            cve_id = f.aliases[0] if f.aliases else f.rule_id
            finding_fixed[cve_id] = _extract_fix_versions(f)

        target, resolved, unresolved, is_major = _pick_minimal_target(ver, finding_fixed)
        if target == "no fix available" and not resolved:
            continue


        # Aggregate properties
        scopes = [f.scope for f in group if f.scope]
        if "prod" in scopes:
            scope = "prod"
        elif "optional" in scopes:
            scope = "optional"
        else:
            scope = "dev" if "dev" in scopes else "prod"

        reach_list = [f.reachability for f in group if f.reachability]
        best_reach = max(reach_list, key=lambda r: _REACHABILITY_RANKS.get(r, 0)) if reach_list else "UNKNOWN"

        max_score = max((f.risk_score for f in group), default=0.0)
        kev_count = sum(1 for f in group if f.in_cisa_kev)
        epss_values = [f.epss_score for f in group if f.epss_score is not None]
        max_epss = max(epss_values) if epss_values else None

        exposures = [f.exposure_class for f in group if f.exposure_class]
        exposure_class = (
            max(exposures, key=lambda e: _EXPOSURE_RANKS.get(e, 0)) if exposures else "UNKNOWN"
        )
        chains = [f.exposure_chain for f in group if f.exposure_chain]
        evidence_chain = min(chains, key=len) if chains else []

        # Select primary manifest file from findings
        manifests = [f.location.file for f in group if f.location.file]
        primary_manifest = manifests[0] if manifests else ""

        act_id = f"fix-{eco}-{pkg}-{ver}"
        action = FixAction(
            action_id=act_id,
            ecosystem=eco,
            package_name=pkg,
            installed_version=ver,
            target_version=target,
            cves_resolved=resolved,
            cves_unresolved=unresolved,
            is_major_bump=is_major,
            scope=scope,
            reachability=best_reach,
            exposure_class=exposure_class,
            evidence_chain=evidence_chain,
            max_score=max_score,
            kev_count=kev_count,
            max_epss=max_epss,
            epss_measured=bool(epss_values),
            findings=group,
            manifest_file=primary_manifest,
        )

        for f in group:
            f.fix_action_id = act_id

        actions.append(action)

    # Sort actions by max_score descending, then kev_count desc, then reachability rank desc, then package_name
    actions.sort(
        key=lambda a: (
            -a.max_score,
            -a.kev_count,
            -_EXPOSURE_RANKS.get(a.exposure_class, 0),
            -_REACHABILITY_RANKS.get(a.reachability, 0),
            a.package_name,
        )
    )
    return actions
