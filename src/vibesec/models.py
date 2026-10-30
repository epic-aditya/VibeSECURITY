"""Common finding schema shared by every scanner (plan Section 3, Stage 4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class SourceTool(StrEnum):
    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    TRIVY = "trivy"
    VIBE_RULE = "vibe-rule"
    PIP_AUDIT = "pip-audit"
    NPM_AUDIT = "npm-audit"
    BANDIT = "bandit"
    SUPPLY_CHAIN = "supply-chain"


class ToolState(StrEnum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


@dataclass
class ToolStatus:
    name: str
    version: str | None = None
    state: ToolState | str = ToolState.OK
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        val = self.state.value if hasattr(self.state, "value") else str(self.state)
        return {
            "name": self.name,
            "version": self.version or "",
            "state": val,
            "reason": self.reason,
        }


@dataclass
class Location:
    file: str
    start_line: int
    end_line: int | None = None

    def __post_init__(self) -> None:
        if self.end_line is None:
            self.end_line = self.start_line
        if self.start_line < 1:
            self.start_line = 1
        if self.end_line < self.start_line:
            self.end_line = self.start_line

    def overlaps(self, other: Location, slack: int = 3) -> bool:
        """True when two locations in the same file touch or nearly touch."""
        if self.file.replace("\\", "/").lower() != other.file.replace("\\", "/").lower():
            return False
        return not (self.end_line + slack < other.start_line or other.end_line + slack < self.start_line)


@dataclass
class Finding:
    """One normalized, already-scored security finding.

    The LLM explanation layer only ever receives a finalized
    Finding and may only attach `explanation` / `remediation` text — never
    change severity, existence, or score.
    """

    rule_id: str
    title: str
    cwe: str
    severity: Severity
    confidence: float  # 0.0 - 1.0, from rule reliability
    location: Location
    evidence: str
    sources: list[SourceTool] = field(default_factory=list)
    # Category taxonomy: code | secret | dependency | license | supply_chain | config
    category: str = "code"

    # Dependency intelligence attributes
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None  # npm, pypi
    aliases: list[str] = field(default_factory=list)  # CVE-..., GHSA-...
    affected_instances: list[dict] = field(default_factory=list)

    # Reachability & exposure (v3)
    reachability: str | None = None  # CALLED | IMPORTED | TRANSITIVE_OF_RUNTIME | TOOLCHAIN | NOT_IMPORTED | UNKNOWN
    reachability_evidence: list[str] = field(default_factory=list)
    exposure_class: str | None = None  # RUNTIME_SERVER | RUNTIME_BUNDLE | TOOLCHAIN_* | TEST | UNKNOWN
    exposure_chain: list[str] = field(default_factory=list)
    scope: str | None = None  # prod | dev | optional
    epss_score: float | None = None  # 0.0 - 1.0
    in_cisa_kev: bool = False
    fix_action_id: str | None = None

    # Scoring inputs, all measurable from static analysis only
    taint_reachable: bool = False
    impact_class: str | None = None  # command_execution | sql_injection | ssrf | ...
    evidence_chain: list[str] = field(default_factory=list)  # static source -> sink steps
    auth_context: str | None = None  # e.g. "authenticated route", "public route", None
    sensitive_asset: str | None = None  # e.g. "credentials", "PII", "auth token"
    risk_score: float = 0.0
    risk_bucket: Severity = Severity.INFO
    explanation: str | None = None
    remediation: str | None = None
    # OWASP mapping (populated by pipeline after scoring)
    owasp_categories: list[str] = field(default_factory=list)
    # Fix suggestion
    fix_snippet: str | None = None
    # Suppression state
    suppressed: bool = False
    suppression_reason: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        d["risk_bucket"] = self.risk_bucket.value if hasattr(self.risk_bucket, "value") else str(self.risk_bucket)
        d["sources"] = [s.value if hasattr(s, "value") else str(s) for s in self.sources]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        loc = d.get("location") or {}
        if isinstance(loc, dict):
            location = Location(
                file=loc.get("file", ""),
                start_line=int(loc.get("start_line", 1)),
                end_line=int(loc.get("end_line", loc.get("start_line", 1))),
            )
        elif isinstance(loc, Location):
            location = loc
        else:
            location = Location(file="unknown", start_line=1, end_line=1)

        sources = [
            SourceTool(s) if isinstance(s, str) and s in {st.value for st in SourceTool} else s
            for s in d.get("sources", [])
        ]
        sev = d.get("severity", "INFO")
        severity = Severity(sev) if isinstance(sev, str) and sev in {s.value for s in Severity} else Severity.INFO
        rb = d.get("risk_bucket", "INFO")
        risk_bucket = Severity(rb) if isinstance(rb, str) and rb in {s.value for s in Severity} else Severity.INFO

        return cls(
            rule_id=d.get("rule_id", ""),
            title=d.get("title", ""),
            cwe=d.get("cwe", "CWE-0"),
            severity=severity,
            confidence=float(d.get("confidence", 0.0)),
            location=location,
            evidence=d.get("evidence", ""),
            sources=sources,
            category=d.get("category", "code"),
            package_name=d.get("package_name"),
            package_version=d.get("package_version"),
            ecosystem=d.get("ecosystem"),
            aliases=list(d.get("aliases") or []),
            affected_instances=list(d.get("affected_instances") or []),
            reachability=d.get("reachability"),
            reachability_evidence=list(d.get("reachability_evidence") or []),
            exposure_class=d.get("exposure_class"),
            exposure_chain=list(d.get("exposure_chain") or []),
            scope=d.get("scope"),
            epss_score=float(d["epss_score"]) if d.get("epss_score") is not None else None,
            in_cisa_kev=bool(d.get("in_cisa_kev", False)),
            fix_action_id=d.get("fix_action_id"),
            taint_reachable=bool(d.get("taint_reachable", False)),
            impact_class=d.get("impact_class"),
            evidence_chain=list(d.get("evidence_chain") or []),
            auth_context=d.get("auth_context"),
            sensitive_asset=d.get("sensitive_asset"),
            risk_score=float(d.get("risk_score", 0.0)),
            risk_bucket=risk_bucket,
            explanation=d.get("explanation"),
            remediation=d.get("remediation"),
            owasp_categories=list(d.get("owasp_categories") or []),
            fix_snippet=d.get("fix_snippet"),
            suppressed=bool(d.get("suppressed", False)),
            suppression_reason=d.get("suppression_reason"),
        )

    @property
    def key(self) -> tuple[str, str]:
        """Stable identity used for dedup before correlation."""
        if self.category == "dependency" and self.package_name:
            cve_alias = sorted(self.aliases)[0] if self.aliases else self.rule_id
            return (self.package_name, cve_alias)
        return (self.location.file.replace("\\", "/"), self.rule_id)


@dataclass
class LicenseFinding:
    package_name: str
    license_name: str
    status: str = "REVIEW"  # REVIEW | VIOLATION
    severity: Severity = Severity.INFO
    scope: str = "prod"
    exposure_class: str = "UNKNOWN"
    file: str = ""
    line: int = 1
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "license_name": self.license_name,
            "status": self.status,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "scope": self.scope,
            "exposure_class": self.exposure_class,
            "file": self.file,
            "line": self.line,
            "notes": self.notes,
        }


@dataclass
class AnalysisCoverage:
    status: str = "INCOMPLETE"  # "COMPLETE" | "INCOMPLETE"
    languages: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    entry_points_count: int = 0
    taint_analysis: str = "ACTIVE"
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "languages": dict(self.languages),
            "frameworks": list(self.frameworks),
            "entry_points_count": self.entry_points_count,
            "taint_analysis": self.taint_analysis,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict) -> AnalysisCoverage:
        return cls(
            status=d.get("status", "INCOMPLETE"),
            languages=dict(d.get("languages", {})),
            frameworks=list(d.get("frameworks", [])),
            entry_points_count=int(d.get("entry_points_count", 0)),
            taint_analysis=d.get("taint_analysis", "ACTIVE"),
            reason=d.get("reason", ""),
        )

