"""Stage 6 — Risk Prioritization (Scoring v3 - 0–10 Multiplicative Model).

Deterministic, transparent, static-analysis-only risk scoring.
All scores are bounded in [0.0, 10.0] with CVSS-aligned severity thresholds.

Formula 1: Code, Secret, Config, and License findings:
    Score = min(10.0, base · Conf · T · A · D · S_asset)

    base    : CVSS base score (0.0-10.0) if present, else mapped from raw severity:
              CRITICAL=9.5, HIGH=7.5, MEDIUM=5.0, LOW=2.0, INFO=0.0
    Conf    : Scanner confidence factor = 0.6 + 0.4 · confidence (range: 0.6-1.0)
    T       : Taint / reachability factor:
              1.0 for proven taint flow or non-sink findings (secrets/config/license)
              0.75 for unconfirmed/static code sinks without proven user input flow
    A       : Authentication context factor:
              1.0 for public / unauthenticated endpoints
              0.9 for unknown / internal functions
              0.75 for authenticated endpoints
    D       : Exposure multiplier:
              RUNTIME_SERVER=1.0, RUNTIME_BUNDLE=1.0, UNKNOWN=0.7,
              TOOLCHAIN_BUILD=0.35, TOOLCHAIN_DEVSERVER=0.25, TEST=0.2
    S_asset : Sensitive asset multiplier: 1.15 if credentials/PII/tokens, else 1.0

Formula 2: Dependency findings (Exposure- & Reachability-adjusted):
    Score = min(10.0, base · R · D · (1 + 0.3·EPSS) + KEV_bonus)

    base      : CVSS base score if present, else mapped from raw severity
    R         : Reachability factor:
                CALLED=1.0, IMPORTED=0.75, UNKNOWN=0.5,
                TRANSITIVE_OF_RUNTIME=0.4, TOOLCHAIN=0.25, NOT_IMPORTED=0.15
                (Note: NOT_IMPORTED is demoted to LOW or below, never hidden,
                because dynamic imports or CLI entry points can defeat static checks)
    D         : Exposure multiplier (same as Formula 1)
    EPSS      : Exploit Prediction Scoring System probability (0.0-1.0).
                When unmeasured/offline, term is dropped (multiplier=1.0, labeled "not measured").
    KEV_bonus : CISA Known Exploited Vulnerability bonus (3.0 · D if listed, else 0.0).
                Findings that are CALLED in RUNTIME and in CISA KEV are guaranteed >= 7.0 (HIGH).

Severity Buckets (CVSS-aligned):
    >= 9.0 : CRITICAL
    >= 7.0 : HIGH
    >= 4.0 : MEDIUM
    >  0.0 : LOW
    == 0.0 : INFO
"""

from __future__ import annotations

from typing import Any

from .models import Finding, Severity

# =============================================================================
# SCORING CONFIGURATION (Single Source of Truth)
# =============================================================================

MAX_SCORE: float = 10.0

# Severity base score mapping (when CVSS score is unavailable)
SEVERITY_BASE_SCORES: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

# CVSS-aligned bucket thresholds: (minimum_score, Severity)
THRESHOLDS: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.001, Severity.LOW),
]

# Code scoring factors
CONFIDENCE_MIN: float = 0.6
CONFIDENCE_WEIGHT: float = 0.4

TAINT_FACTORS: dict[str, float] = {
    "REACHABLE": 1.0,
    "NOT_REACHABLE": 0.75,
    "NOT_APPLICABLE": 1.0,
}

AUTH_FACTORS: dict[str, float] = {
    "public": 1.0,
    "unauthenticated": 1.0,
    "unknown": 0.9,
    "authenticated": 0.75,
}

SENSITIVE_ASSET_MULTIPLIER: float = 1.15

# Dependency reachability factors (R)
REACHABILITY_FACTORS: dict[str, float] = {
    "CALLED": 1.0,
    "IMPORTED": 0.75,
    "UNKNOWN": 0.5,
    "TRANSITIVE_OF_RUNTIME": 0.4,
    "TRANSITIVE_OF_IMPORTED": 0.4,
    "TOOLCHAIN": 0.25,
    "BUILD_TOOL": 0.25,
    "NOT_IMPORTED": 0.15,
}

# Exposure multipliers (D)
EXPOSURE_MULTIPLIERS: dict[str, float] = {
    "RUNTIME_SERVER": 1.0,
    "RUNTIME_BUNDLE": 1.0,
    "UNKNOWN": 0.7,
    "TOOLCHAIN_BUILD": 0.35,
    "TOOLCHAIN_DEVSERVER": 0.25,
    "TEST": 0.2,
}

# Scope fallback multipliers (when exposure_class is absent)
SCOPE_MULTIPLIERS: dict[str, float] = {
    "prod": 1.0,
    "optional": 0.6,
    "dev": 0.35,
}

EPSS_FACTOR: float = 0.3
KEV_BONUS: float = 3.0

# Aliases for backward compatibility
_THRESHOLDS = THRESHOLDS
_EXPOSURE_MULTIPLIERS = EXPOSURE_MULTIPLIERS
_REACHABILITY_WEIGHTS = REACHABILITY_FACTORS
_SCOPE_MULTIPLIERS = SCOPE_MULTIPLIERS
_KEV_BONUS = KEV_BONUS

# Human-readable formula strings for documentation and reporting
SCORING_FORMULA_CODE = "Score = min(10.0, base · Conf · T · A · D · S_asset)"
SCORING_FORMULA_DEPENDENCY = "Score = min(10.0, base · R · D · (1 + 0.3·EPSS) + KEV_bonus)"


def get_base_score(finding: Finding) -> float:
    """Extract CVSS base score or map from raw severity."""
    if finding.cvss_score is not None:
        return min(10.0, max(0.0, float(finding.cvss_score)))
    return SEVERITY_BASE_SCORES.get(finding.severity, 0.0)


def score_finding(finding: Finding) -> Finding:
    """Attach risk_score (0.0-10.0) and risk_bucket in place; returns the finding."""
    score = _score_dependency(finding) if finding.category == "dependency" else _score_code(finding)
    finding.risk_score = round(min(10.0, max(0.0, score)), 2)
    finding.risk_bucket = _bucket(finding.risk_score)
    return finding


def _score_code(finding: Finding) -> float:
    base = get_base_score(finding)
    if base <= 0.0:
        return 0.0

    # Confidence factor (0.6 - 1.0)
    c_raw = finding.confidence if finding.confidence is not None else 0.8
    conf = CONFIDENCE_MIN + (CONFIDENCE_WEIGHT * max(0.0, min(1.0, c_raw)))

    # Taint factor (1.0 or 0.75)
    if finding.category in ("secret", "config", "license"):
        t = TAINT_FACTORS["NOT_APPLICABLE"]
    elif finding.taint_reachable:
        t = TAINT_FACTORS["REACHABLE"]
    else:
        t = TAINT_FACTORS["NOT_REACHABLE"]

    # Authentication factor (0.75 - 1.0)
    auth_ctx = (finding.auth_context or "").lower().strip()
    a = AUTH_FACTORS.get(auth_ctx, AUTH_FACTORS["unknown"])

    # Exposure factor (0.2 - 1.0)
    if finding.exposure_class:
        d = EXPOSURE_MULTIPLIERS.get(finding.exposure_class.upper(), 1.0)
    else:
        fpath = (finding.location.file if finding.location else "").replace("\\", "/").lower()
        parts = fpath.split("/")
        if any(p in ("tests", "test", "fixtures", "__tests__", "spec", "specs") for p in parts):
            d = EXPOSURE_MULTIPLIERS["TEST"]
        elif any(p in ("scripts",) for p in parts):
            d = EXPOSURE_MULTIPLIERS["TOOLCHAIN_BUILD"]
        else:
            d = 1.0

    # Sensitive asset factor (1.15 or 1.0)
    s_asset = SENSITIVE_ASSET_MULTIPLIER if finding.sensitive_asset else 1.0

    if finding.category == "secret" and d <= EXPOSURE_MULTIPLIERS["TEST"] and not finding.remediation:
        finding.remediation = "Verify whether this test credential is live in production or restricted to test environment."

    return base * conf * t * a * d * s_asset


def _score_dependency(finding: Finding) -> float:
    base = get_base_score(finding)
    if base <= 0.0 and not finding.in_cisa_kev:
        return 0.0

    r = REACHABILITY_FACTORS.get((finding.reachability or "UNKNOWN").upper(), 0.5)

    if finding.exposure_class:
        d = EXPOSURE_MULTIPLIERS.get(finding.exposure_class.upper(), 0.7)
    elif (finding.reachability or "").upper() in ("TOOLCHAIN", "BUILD_TOOL"):
        d = EXPOSURE_MULTIPLIERS["TOOLCHAIN_BUILD"]
    else:
        d = SCOPE_MULTIPLIERS.get((finding.scope or "prod").lower(), 1.0)

    # EPSS term: when unmeasured or offline, term is dropped (multiplier 1.0)
    if finding.epss_score is not None:
        epss_term = 1.0 + (EPSS_FACTOR * max(0.0, min(1.0, finding.epss_score)))
    else:
        epss_term = 1.0

    # KEV bonus scaled by exposure
    kev_bonus = (KEV_BONUS * d) if finding.in_cisa_kev else 0.0

    raw_score = (base * r * d * epss_term) + kev_bonus

    # Invariant: KEV-listed and CALLED in runtime is never below HIGH (>= 7.0)
    if finding.in_cisa_kev and r >= 1.0 and d >= 1.0:
        raw_score = max(raw_score, 7.0)

    return raw_score


def _bucket(score: float) -> Severity:
    for threshold, bucket in THRESHOLDS:
        if score >= threshold:
            return bucket
    return Severity.INFO


def is_actionable(f: Finding) -> bool:
    """Actionable excludes INFO and non-secret test/fixture/build-tool findings."""
    if f.risk_bucket == Severity.INFO or f.severity == Severity.INFO:
        return False
    # Secrets in test or script paths must remain actionable for manual credential verification
    if f.category == "secret":
        return True
    exp = (f.exposure_class or "").upper()
    if exp in ("TEST", "TOOLCHAIN_BUILD", "TOOLCHAIN_DEVSERVER") or exp.startswith("TOOLCHAIN"):
        return False
    fpath = (f.location.file if f.location else "").replace("\\", "/").lower()
    parts = fpath.split("/")
    return not any(p in ("tests", "test", "fixtures", "scripts", "__tests__", "spec", "specs") for p in parts)


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


def score_all(findings: list[Finding]) -> list[Finding]:
    """Score all findings in place and sort deterministically."""
    for f in findings:
        score_finding(f)
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
