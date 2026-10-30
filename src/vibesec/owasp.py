"""CWE → OWASP Top 10 (2021) and ASVS mapping.

Used by the report and dashboard to show which OWASP categories are affected.
The mapping is intentionally conservative — only well-established CWE–category
links are included.
"""

from __future__ import annotations

# OWASP Top 10 2021 categories
OWASP_TOP10: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# CWE → OWASP Top 10 2021 category ID(s)
CWE_TO_OWASP: dict[str, list[str]] = {
    # A01 — Broken Access Control
    "CWE-22": ["A01"],     # path traversal
    "CWE-23": ["A01"],
    "CWE-35": ["A01"],
    "CWE-59": ["A01"],
    "CWE-200": ["A01"],
    "CWE-201": ["A01"],
    "CWE-219": ["A01"],
    "CWE-264": ["A01"],
    "CWE-275": ["A01"],
    "CWE-276": ["A01"],
    "CWE-284": ["A01"],
    "CWE-285": ["A01"],
    "CWE-352": ["A01"],
    "CWE-359": ["A01"],
    "CWE-377": ["A01"],
    "CWE-402": ["A01"],
    "CWE-425": ["A01"],
    "CWE-441": ["A01"],
    "CWE-497": ["A01"],
    "CWE-538": ["A01"],
    "CWE-540": ["A01"],
    "CWE-548": ["A01"],
    "CWE-552": ["A01"],
    "CWE-566": ["A01"],
    "CWE-601": ["A01"],
    "CWE-639": ["A01"],
    "CWE-651": ["A01"],
    "CWE-668": ["A01"],
    "CWE-706": ["A01"],
    "CWE-862": ["A01"],
    "CWE-863": ["A01"],
    "CWE-913": ["A01"],
    "CWE-922": ["A01"],
    "CWE-942": ["A01", "A05"],

    # A02 — Cryptographic Failures
    "CWE-256": ["A02"],
    "CWE-261": ["A02"],
    "CWE-296": ["A02"],
    "CWE-310": ["A02"],
    "CWE-312": ["A02"],
    "CWE-319": ["A02"],
    "CWE-321": ["A02"],
    "CWE-322": ["A02"],
    "CWE-323": ["A02"],
    "CWE-324": ["A02"],
    "CWE-325": ["A02"],
    "CWE-326": ["A02"],
    "CWE-327": ["A02"],
    "CWE-328": ["A02"],
    "CWE-329": ["A02"],
    "CWE-330": ["A02"],
    "CWE-331": ["A02"],
    "CWE-335": ["A02"],
    "CWE-336": ["A02"],
    "CWE-337": ["A02"],
    "CWE-338": ["A02"],
    "CWE-340": ["A02"],
    "CWE-347": ["A02"],
    "CWE-720": ["A02"],
    "CWE-757": ["A02"],
    "CWE-759": ["A02"],
    "CWE-760": ["A02"],
    "CWE-780": ["A02"],
    "CWE-798": ["A02", "A07"],
    "CWE-916": ["A02"],

    # A03 — Injection
    "CWE-20": ["A03"],
    "CWE-74": ["A03"],
    "CWE-75": ["A03"],
    "CWE-77": ["A03"],
    "CWE-78": ["A03"],
    "CWE-79": ["A03"],
    "CWE-80": ["A03"],
    "CWE-83": ["A03"],
    "CWE-87": ["A03"],
    "CWE-88": ["A03"],
    "CWE-89": ["A03"],
    "CWE-90": ["A03"],
    "CWE-91": ["A03"],
    "CWE-93": ["A03"],
    "CWE-94": ["A03"],
    "CWE-95": ["A03"],
    "CWE-96": ["A03"],
    "CWE-97": ["A03"],
    "CWE-98": ["A03"],
    "CWE-99": ["A03"],
    "CWE-113": ["A03"],
    "CWE-116": ["A03"],
    "CWE-138": ["A03"],
    "CWE-184": ["A03"],
    "CWE-470": ["A03"],
    "CWE-471": ["A03"],
    "CWE-564": ["A03"],
    "CWE-610": ["A03"],
    "CWE-643": ["A03"],
    "CWE-644": ["A03"],
    "CWE-652": ["A03"],
    "CWE-917": ["A03"],

    # A04 — Insecure Design
    "CWE-209": ["A04"],
    "CWE-501": ["A04"],
    "CWE-522": ["A04"],
    "CWE-602": ["A04"],
    "CWE-770": ["A04"],
    "CWE-841": ["A04"],
    "CWE-927": ["A04"],

    # A05 — Security Misconfiguration
    "CWE-2": ["A05"],
    "CWE-11": ["A05"],
    "CWE-13": ["A05"],
    "CWE-15": ["A05"],
    "CWE-16": ["A05"],
    "CWE-260": ["A05"],
    "CWE-315": ["A05"],
    "CWE-520": ["A05"],
    "CWE-526": ["A05"],
    "CWE-537": ["A05"],
    "CWE-541": ["A05"],
    "CWE-547": ["A05"],
    "CWE-611": ["A05"],
    "CWE-614": ["A05"],
    "CWE-756": ["A05"],
    "CWE-776": ["A05"],
    "CWE-489": ["A05"],
    "CWE-1327": ["A05"],

    # A06 — Vulnerable and Outdated Components
    "CWE-937": ["A06"],
    "CWE-1035": ["A06"],
    "CWE-1104": ["A06"],
    "CWE-1395": ["A06"],
    "CWE-1333": ["A03"],

    # A07 — Identification and Authentication Failures
    "CWE-255": ["A07"],
    "CWE-259": ["A07"],
    "CWE-287": ["A07"],
    "CWE-288": ["A07"],
    "CWE-290": ["A07"],
    "CWE-294": ["A07"],
    "CWE-295": ["A07"],
    "CWE-297": ["A07"],
    "CWE-300": ["A07"],
    "CWE-302": ["A07"],
    "CWE-304": ["A07"],
    "CWE-306": ["A07"],
    "CWE-307": ["A07"],
    "CWE-346": ["A07"],
    "CWE-384": ["A07"],
    "CWE-521": ["A07"],
    "CWE-613": ["A07"],
    "CWE-620": ["A07"],
    "CWE-640": ["A07"],

    # A08 — Software and Data Integrity Failures
    "CWE-345": ["A08"],
    "CWE-353": ["A08"],
    "CWE-426": ["A08"],
    "CWE-494": ["A08"],
    "CWE-502": ["A08"],
    "CWE-565": ["A08"],
    "CWE-784": ["A08"],
    "CWE-829": ["A08"],
    "CWE-830": ["A08"],
    "CWE-915": ["A08"],

    # A10 — SSRF
    "CWE-918": ["A10"],
}


def cwe_to_owasp(cwe: str) -> list[str]:
    """Return OWASP Top 10 2021 category IDs for a CWE."""
    key = cwe.upper().strip()
    return CWE_TO_OWASP.get(key, [])


def owasp_label(cat_id: str) -> str:
    """Full label for an OWASP category ID, e.g. 'A03: Injection'."""
    name = OWASP_TOP10.get(cat_id, "Unknown")
    return f"{cat_id}: {name}"


def owasp_summary(findings: list) -> dict[str, dict]:
    """Build an OWASP Top 10 summary from a list of scored findings.

    Returns {category_id: {"label": str, "count": int, "max_severity": str, "findings": [...]}}
    """
    from .models import Severity

    summary: dict[str, dict] = {}
    for f in findings:
        cats = cwe_to_owasp(f.cwe)
        for cat in cats:
            if cat not in summary:
                summary[cat] = {
                    "label": owasp_label(cat),
                    "count": 0,
                    "max_severity": Severity.INFO.value,
                    "findings": [],
                }
            entry = summary[cat]
            entry["count"] += 1
            entry["findings"].append(f)
            if f.risk_bucket.rank > Severity(entry["max_severity"]).rank:
                entry["max_severity"] = f.risk_bucket.value

    return dict(sorted(summary.items()))
