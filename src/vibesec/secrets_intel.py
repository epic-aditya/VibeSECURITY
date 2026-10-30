"""Secrets intelligence module — enhanced secret analysis beyond raw Gitleaks output.

Classifies secret types, provides redacted previews, rotation guidance,
and computes a "secret sprawl" metric (unique secrets × duplicate leaks).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .models import Finding

# Secret type classification by prefix/pattern
_SECRET_TYPES: list[tuple[str, re.Pattern, str, str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL", "Rotate in AWS IAM console immediately. Deactivate the old key."),
    ("AWS Secret Key", re.compile(r"(?:aws_secret|AWS_SECRET)[^=]*=\s*['\"]?[A-Za-z0-9/+=]{40}"), "CRITICAL", "Rotate via AWS IAM. Update all services using this key."),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), "HIGH", "Regenerate at https://platform.openai.com/api-keys. Revoke old key."),
    ("GitHub Token", re.compile(r"gh[ps]_[A-Za-z0-9]{36,}"), "HIGH", "Revoke at GitHub Settings → Developer settings → Personal access tokens."),
    ("GitHub OAuth", re.compile(r"gho_[A-Za-z0-9]{36}"), "HIGH", "Revoke the OAuth app token at GitHub Settings."),
    ("Slack Token", re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "HIGH", "Regenerate at Slack API → OAuth & Permissions."),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH", "Restrict or delete at Google Cloud Console → APIs & Services → Credentials."),
    ("Stripe Key", re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"), "CRITICAL", "Roll the key at Stripe Dashboard → Developers → API keys."),
    ("Twilio Key", re.compile(r"SK[0-9a-fA-F]{32}"), "HIGH", "Rotate at Twilio Console → Settings → API Keys."),
    ("JWT Secret", re.compile(r"(?:JWT_SECRET|jwt_secret|SECRET_KEY)\s*=\s*['\"][^'\"]{8,}['\"]"), "HIGH", "Generate a new cryptographically random secret (≥256 bits). Invalidate existing tokens."),
    ("Database URL", re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@"), "CRITICAL", "Change the database password. Update connection strings in all services."),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "CRITICAL", "Generate a new key pair. Replace in all deployments. Revoke associated certificates."),
    ("Generic Password", re.compile(r"(?:password|passwd|pass)\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE), "MEDIUM", "Use environment variables or a secret manager (e.g., HashiCorp Vault, AWS Secrets Manager)."),
    ("Generic API Key", re.compile(r"(?:api[_-]?key|apikey)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), "HIGH", "Rotate the API key with the provider. Store in environment variables."),
    ("Generic Token", re.compile(r"(?:token|auth_token|access_token)\s*=\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), "MEDIUM", "Rotate the token. Use a secret manager for storage."),
]


@dataclass
class SecretInfo:
    """Enriched secret intelligence for a single finding."""
    secret_type: str = "Unknown"
    redacted_preview: str = ""
    rotation_guidance: str = ""
    severity_by_type: str = "MEDIUM"
    in_git_history: bool = False


@dataclass
class SecretIntelligence:
    """Summary of all secrets found in the scan."""
    total_secrets: int = 0
    unique_secret_types: int = 0
    secret_type_counts: dict[str, int] = field(default_factory=dict)
    sprawl_metric: float = 0.0  # unique_types * total_occurrences (higher = worse)
    enriched_findings: list[tuple[Finding, SecretInfo]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_secrets": self.total_secrets,
            "unique_secret_types": self.unique_secret_types,
            "secret_type_counts": self.secret_type_counts,
            "sprawl_metric": round(self.sprawl_metric, 2),
        }


def _redact(evidence: str) -> str:
    """Create a redacted preview of a secret value."""
    if not evidence:
        return "(no evidence)"
    # Try to find the actual secret value
    for pattern in [
        re.compile(r"""[=:]\s*['"]([^'"]{4,})['"]"""),
        re.compile(r"""((?:sk-|AKIA|ghp_|gho_|xox[baprs]-|AIza|pk_|sk_)[A-Za-z0-9\-_/+=]+)"""),
    ]:
        m = pattern.search(evidence)
        if m:
            val = m.group(1)
            if len(val) <= 6:
                return val[0] + "****" + val[-1]
            return val[:4] + "****" + val[-4:]

    # Fallback: redact the whole evidence
    if len(evidence) > 12:
        return evidence[:6] + "****" + evidence[-4:]
    return evidence[:3] + "****"


def classify_secret(evidence: str) -> SecretInfo:
    """Classify a secret by its evidence string."""
    info = SecretInfo()

    for type_name, pattern, severity, guidance in _SECRET_TYPES:
        if pattern.search(evidence):
            info.secret_type = type_name
            info.severity_by_type = severity
            info.rotation_guidance = guidance
            break

    info.redacted_preview = _redact(evidence)
    return info


def analyze_secrets(findings: list[Finding]) -> SecretIntelligence:
    """Analyze all secret-related findings and produce intelligence summary."""
    intel = SecretIntelligence()

    secret_findings = [
        f for f in findings
        if f.sensitive_asset == "credentials"
        or f.cwe in {"CWE-798", "CWE-321", "CWE-259"}
        or "secret" in f.rule_id.lower()
        or "credential" in f.rule_id.lower()
        or "gitleaks" in f.rule_id.lower()
    ]

    intel.total_secrets = len(secret_findings)
    type_counts: dict[str, int] = {}

    for f in secret_findings:
        info = classify_secret(f.evidence)
        type_counts[info.secret_type] = type_counts.get(info.secret_type, 0) + 1
        intel.enriched_findings.append((f, info))

    intel.secret_type_counts = type_counts
    intel.unique_secret_types = len(type_counts)
    intel.sprawl_metric = intel.unique_secret_types * intel.total_secrets

    return intel
