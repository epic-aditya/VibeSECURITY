"""Stage 6 — Risk Prioritization (Scoring v2).

Static-analysis-only scoring. Deterministic and reproducible.

Formula 1: Code, Secret, Config, License findings
    score = 4·severity_rank + 2·confidence + 1.5·taint + auth + sensitive

    severity_rank : CRITICAL=4 … INFO=0
    confidence    : 0.0–1.0
    taint         : 1.0 if user input reaches sink, else 0
    auth          : public route 0.5 · authenticated 0.1 · unknown 0
    sensitive     : 1.0 if credentials/PII/auth token/payment data involved

Formula 2: Dependency findings (Scoring v2.1, exposure-adjusted)
    score = (4·S + 2·X + 1.5·R + K) · D

    S : severity rank (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0)
    X : EPSS exploit probability 0.0–1.0 (default 0.3 when unknown)
    R : reachability (CALLED 1.0, IMPORTED 0.7, TRANSITIVE_OF_RUNTIME 0.4,
        UNKNOWN 0.4, TOOLCHAIN 0.1, NOT_IMPORTED 0.0)
    K : CISA KEV bonus (2.0 if in KEV catalog, else 0.0)
    D : exposure multiplier (RUNTIME_SERVER 1.0, RUNTIME_BUNDLE 1.0,
        UNKNOWN 0.7, TOOLCHAIN_BUILD 0.35, TOOLCHAIN_DEVSERVER 0.25, TEST 0.2)

Buckets: >=16 CRITICAL · >=12 HIGH · >=8 MEDIUM · >=4 LOW · else INFO
"""

from __future__ import annotations

from typing import Any

from .models import Finding, Severity

# Code scoring weights
_W_SEVERITY = 4.0
_W_CONFIDENCE = 2.0
_W_TAINT = 1.5
_W_SENSITIVE = 1.0
_AUTH_RISK = {"public": 0.5, "unauthenticated": 0.5, "authenticated": 0.1}

# Dependency scoring constants
_REACHABILITY_WEIGHTS = {
    "CALLED": 1.0,
    "IMPORTED": 0.7,
    "TRANSITIVE_OF_RUNTIME": 0.4,
    "TRANSITIVE_OF_IMPORTED": 0.4,  # legacy history compatibility
    "UNKNOWN": 0.4,
    "TOOLCHAIN": 0.1,
    "BUILD_TOOL": 0.2,  # legacy history compatibility
    "NOT_IMPORTED": 0.0,
}

_EXPOSURE_MULTIPLIERS = {
    "RUNTIME_SERVER": 1.0,
    "RUNTIME_BUNDLE": 1.0,
    "UNKNOWN": 0.7,
    "TOOLCHAIN_BUILD": 0.35,
    "TOOLCHAIN_DEVSERVER": 0.25,
    "TEST": 0.2,
}

_SCOPE_MULTIPLIERS = {
    "prod": 1.0,
    "optional": 0.6,
    "dev": 0.35,
}

_DEFAULT_EPSS_UNKNOWN = 0.3
_KEV_BONUS = 2.0

MAX_SCORE = 22.0

_THRESHOLDS = [
    (16.0, Severity.CRITICAL),
    (12.0, Severity.HIGH),
    (8.0, Severity.MEDIUM),
    (4.0, Severity.LOW),
]


def score_finding(finding: Finding) -> Finding:
    """Attach risk_score and risk_bucket in place; returns the same finding."""
    score = _score_dependency(finding) if finding.category == "dependency" else _score_code(finding)

    finding.risk_score = round(score, 2)
    finding.risk_bucket = _bucket(score)
    return finding


def _score_code(finding: Finding) -> float:
    base = (
        _W_SEVERITY * finding.severity.rank
        + _W_CONFIDENCE * finding.confidence
        + (_W_TAINT if finding.taint_reachable else 0.0)
        + _AUTH_RISK.get((finding.auth_context or "").lower(), 0.0)
        + (_W_SENSITIVE if finding.sensitive_asset else 0.0)
    )
    if finding.exposure_class:
        d = _EXPOSURE_MULTIPLIERS.get(finding.exposure_class.upper(), 1.0)
        return base * d
    return base


def is_actionable(f: Finding) -> bool:
    """Actionable excludes INFO and test/fixture/script findings."""
    if f.risk_bucket == Severity.INFO or f.severity == Severity.INFO:
        return False
    exp = (f.exposure_class or "").upper()
    if exp in ("TEST", "TOOLCHAIN_BUILD", "TOOLCHAIN_DEVSERVER") or exp.startswith("TOOLCHAIN"):
        return False
    fpath = (f.location.file if f.location else "").replace("\\", "/").lower()
    parts = fpath.split("/")
    if any(p in ("tests", "test", "fixtures", "scripts", "__tests__", "spec", "specs") for p in parts):
        return False
    return True


def calculate_risk_posture(
    findings: list[Finding],
    asm: Any = None,
    coverage: Any = None,
) -> tuple[str, dict[str, Any]]:
    """Establish a single authoritative result model for risk posture.

    Guarantees severity counts, maximum score, attack paths, public routes,
    and coverage status agree across Dashboard, PDF, Markdown, SARIF, and CLI.
    """
    crit_findings = [f for f in findings if f.risk_bucket == Severity.CRITICAL]
    high_findings = [f for f in findings if f.risk_bucket == Severity.HIGH]
    med_findings = [f for f in findings if f.risk_bucket == Severity.MEDIUM]
    low_findings = [f for f in findings if f.risk_bucket == Severity.LOW]
    info_findings = [f for f in findings if f.risk_bucket == Severity.INFO]

    max_score = max((f.risk_score for f in findings), default=0.0)
    cov_status = getattr(coverage, "status", "COMPLETE") if coverage else "COMPLETE"
    cov_reason = getattr(coverage, "reason", "") if coverage else ""
    attack_paths = getattr(asm, "attack_paths", []) if asm else []

    posture_data_raw = getattr(asm, "posture", None)
    if posture_data_raw and hasattr(posture_data_raw, "public_routes"):
        public_routes = posture_data_raw.public_routes
        public_state_changing = posture_data_raw.public_state_changing_routes
    else:
        eps = getattr(asm, "entry_points", []) if asm else []
        public_routes = len([e for e in eps if getattr(e, "auth_state", "") == "PUBLIC"])
        public_state_changing = len([e for e in eps if getattr(e, "method", "").upper() in ("POST", "PUT", "PATCH", "DELETE") and getattr(e, "auth_state", "") == "PUBLIC"])

    actionable_list = [f for f in findings if is_actionable(f)]
    actionable_findings = len(actionable_list)
    deprioritized_findings = len(findings) - actionable_findings
    dep_cves_cnt = sum(1 for f in findings if not is_actionable(f) and f.category == "dependency")
    test_toolchain_cnt = sum(1 for f in findings if not is_actionable(f) and f.category != "dependency")

    if dep_cves_cnt > 0 and test_toolchain_cnt > 0:
        dep_summary = f"{dep_cves_cnt} dependency CVE(s) and {test_toolchain_cnt} test/toolchain finding(s) are deprioritized"
    elif dep_cves_cnt > 0:
        dep_summary = f"{dep_cves_cnt} dependency CVE(s) are build-toolchain-only and deprioritized"
    elif test_toolchain_cnt > 0:
        dep_summary = f"{test_toolchain_cnt} test/toolchain finding(s) are deprioritized"
    else:
        dep_summary = "0 test/toolchain findings are deprioritized"

    crit_paths = [
        p for p in attack_paths
        if getattr(p, "auth_state", "PUBLIC") == "PUBLIC"
        and getattr(p, "sink_class", "") in ("code_execution", "sql_injection", "command_execution", "llm_prompt_injection")
    ]
    high_paths = [p for p in attack_paths if p not in crit_paths and getattr(p, "auth_state", "PUBLIC") == "PUBLIC"]

    state_str = f", {public_state_changing} public state-changing routes" if public_state_changing > 0 else ""
    kev_cnt = sum(1 for f in findings if getattr(f, "in_cisa_kev", False))
    kev_str = f", {kev_cnt} in CISA KEV" if kev_cnt > 0 else ""

    top_finding = None
    if actionable_list:
        top_finding = max(actionable_list, key=lambda f: f.risk_score)
    elif findings:
        top_finding = max(findings, key=lambda f: f.risk_score)

    boundary_name = "Application trust boundary"
    if top_finding:
        rule_lower = top_finding.rule_id.lower()
        title_lower = top_finding.title.lower()
        if top_finding.taint_reachable or top_finding.auth_context == "public" or (crit_paths and any(getattr(p, "sink_class", "") in rule_lower for p in crit_paths)):
            boundary_name = "Internet to application boundary"
        elif any(k in rule_lower or k in title_lower for k in ("sql", "datastore", "mongo", "database", "orm")):
            boundary_name = "Application to datastore boundary"
        elif any(k in rule_lower or k in title_lower for k in ("ssrf", "external", "webhook", "http")):
            boundary_name = "Application to external network boundary"
        elif top_finding.auth_context == "authenticated":
            boundary_name = "Authenticated user boundary"
        elif top_finding.location and any(t in top_finding.location.file.lower() for t in ("test", "fixture", "spec")):
            boundary_name = "Test environment boundary"
        elif asm and getattr(asm, "trust_boundaries", None):
            boundary_name = asm.trust_boundaries[0].name

    top_desc = f"top finding: '{top_finding.title}' at {boundary_name}" if top_finding else "no active findings"

    if cov_status == "INCOMPLETE":
        if crit_findings:
            posture_stmt = (
                f"High risk (incomplete coverage): {len(crit_findings)} critical finding(s) detected "
                f"({top_desc}, highest score {max_score:.1f}{state_str}), but analysis coverage is INCOMPLETE ({cov_reason or 'partial analysis'})."
            )
        elif high_findings:
            posture_stmt = (
                f"Elevated risk (incomplete coverage): {len(high_findings)} high-severity finding(s) detected "
                f"({top_desc}, highest score {max_score:.1f}{state_str}), but analysis coverage is INCOMPLETE ({cov_reason or 'partial analysis'})."
            )
        elif len(findings) == 0:
            posture_stmt = f"UNDETERMINED: Zero findings recorded, but analysis coverage is INCOMPLETE ({cov_reason or 'Web framework detected but 0 entry points discovered'}). Cannot guarantee safety."
        else:
            posture_stmt = f"Undetermined risk (incomplete coverage): {len(findings)} finding(s) detected ({top_desc}), analysis coverage INCOMPLETE ({cov_reason or 'partial analysis'})."
    else:
        if crit_paths:
            top_sinks = sorted(list(set(getattr(p, "sink_class", "").replace("_", " ") for p in crit_paths)))
            top_sinks_str = ", ".join(top_sinks[:3]) or "critical sinks"
            posture_stmt = (
                f"High risk: {len(crit_paths)} unauthenticated attack path(s) reach critical sinks "
                f"({top_sinks_str}{state_str}{kev_str}); "
                f"{len(crit_findings)} critical finding(s) ({top_desc}, highest score {max_score:.1f}); "
                f"{dep_summary}."
            )
        elif high_paths:
            top = high_paths[0]
            posture_stmt = (
                f"Moderate risk: {len(high_paths)} reachable path(s) identified "
                f"({getattr(top, 'method', '')} {getattr(top, 'route', '')} -> {getattr(top, 'sink_class', '').replace('_', ' ')}{state_str}, {top_desc}); "
                f"{dep_summary}."
            )
        elif crit_findings:
            posture_stmt = (
                f"High risk: {len(crit_findings)} critical finding(s) detected without proven unauthenticated attack path "
                f"({top_desc}, highest score {max_score:.1f}{state_str}{kev_str}); "
                f"{dep_summary}."
            )
        elif high_findings:
            posture_stmt = (
                f"Elevated risk: {len(high_findings)} high-severity finding(s) detected "
                f"({top_desc}, highest score {max_score:.1f}{state_str}{kev_str}); "
                f"{dep_summary}."
            )
        elif med_findings or actionable_findings > 0:
            posture_stmt = (
                f"Low-to-moderate risk: {actionable_findings} actionable finding(s) "
                f"({top_desc}, highest score {max_score:.1f}{state_str}); "
                f"{dep_summary}."
            )
        elif findings:
            posture_stmt = (
                f"Low risk: {len(findings)} low/info finding(s) ({top_desc}, highest score {max_score:.1f}); "
                f"{dep_summary}."
            )
        else:
            posture_stmt = "Strong security posture: No actionable attack paths or vulnerabilities detected across complete analysis coverage."

    details = {
        "risk_posture_statement": posture_stmt,
        "actionable_findings": actionable_findings,
        "deprioritized_findings": deprioritized_findings,
        "deprioritized_dependency_cves": dep_cves_cnt,
        "deprioritized_test_toolchain": test_toolchain_cnt,
        "top_finding_title": top_finding.title if top_finding else "",
        "top_finding_boundary": boundary_name if top_finding else "",
        "critical_count": len(crit_findings),
        "high_count": len(high_findings),
        "medium_count": len(med_findings),
        "low_count": len(low_findings),
        "info_count": len(info_findings),
        "max_score": max_score,
        "reachable_attack_paths": len(crit_paths) + len(high_paths),
        "unauthenticated_critical_paths": len(crit_paths),
        "public_routes": public_routes,
        "public_state_changing_routes": public_state_changing,
        "cisa_kev_count": kev_cnt,
    }
    return posture_stmt, details


def _score_dependency(finding: Finding) -> float:
    s = float(finding.severity.rank)
    x = finding.epss_score if finding.epss_score is not None else _DEFAULT_EPSS_UNKNOWN
    r = _REACHABILITY_WEIGHTS.get((finding.reachability or "UNKNOWN").upper(), 0.4)
    k = _KEV_BONUS if finding.in_cisa_kev else 0.0
    if finding.exposure_class:
        d = _EXPOSURE_MULTIPLIERS.get(finding.exposure_class.upper(), 0.7)
    elif (finding.reachability or "").upper() in ("TOOLCHAIN", "BUILD_TOOL"):
        d = _EXPOSURE_MULTIPLIERS["TOOLCHAIN_BUILD"]
    else:
        d = _SCOPE_MULTIPLIERS.get((finding.scope or "prod").lower(), 1.0)

    base = (4.0 * s) + (2.0 * x) + (1.5 * r) + k
    return base * d


def _bucket(score: float) -> Severity:
    for threshold, bucket in _THRESHOLDS:
        if score >= threshold:
            return bucket
    return Severity.INFO


def score_all(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        score_finding(f)
    # Sort deterministically: risk_score desc, then rule_id, then file, then line, then title
    return sorted(
        findings,
        key=lambda f: (
            -f.risk_score,
            f.rule_id,
            f.location.file.replace("\\", "/").lower() if f.location else "",
            f.location.start_line if f.location else 0,
            f.title,
            f.evidence or "",
        ),
    )
