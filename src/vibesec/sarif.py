"""SARIF 2.1.0 export with codeFlows for attack paths.

Produces a Static Analysis Results Interchange Format (SARIF) file from
VibeSec findings and AttackPaths, enabling integration with GitHub Code Scanning
and displaying step-by-step code flows in GitHub Advanced Security.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import Finding
from .owasp import cwe_to_owasp, owasp_label

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _normalize_sarif_uri(file_path: str) -> str:
    """Normalize file path to a relative POSIX URI without host drive letters or temp paths."""
    if not file_path:
        return "unknown"
    norm = file_path.replace("\\", "/").strip()
    if ":" in norm:
        # Strip drive letters e.g. C:/ or D:/
        norm = norm.split(":", 1)[1]
    norm = norm.lstrip("/")
    while norm.startswith("./"):
        norm = norm[2:]
    # Remove leading temp directory segments if leaked from extraction
    parts = norm.split("/")
    for idx, part in enumerate(parts):
        if part.startswith("vibesec_") or part.startswith("tmp") or part == "dest":
            norm = "/".join(parts[idx + 1 :])
            break
    norm = norm.lstrip("/")
    return norm or "unknown"


def _build_rule(finding: Finding) -> dict:
    owasp_cats = cwe_to_owasp(finding.cwe)
    tags = [finding.cwe]
    tags.extend(owasp_label(c) for c in owasp_cats)
    sec_score = min(10.0, max(0.0, finding.risk_score or 0.0))

    rule = {
        "id": finding.rule_id,
        "name": finding.rule_id.replace(".", "_"),
        "shortDescription": {"text": finding.title[:256]},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe.split('-')[-1]}.html"
        if "-" in finding.cwe
        else "https://cwe.mitre.org/",
        "properties": {
            "tags": tags,
            "security-severity": f"{sec_score:.1f}",
        },
    }
    if finding.explanation:
        rule["fullDescription"] = {"text": finding.explanation[:1024]}
    return rule


def _build_path_rule(path: Any) -> dict:
    cwe = getattr(path, "cwe", "CWE-0") or "CWE-0"
    owasp_cats = cwe_to_owasp(cwe)
    tags = [cwe]
    tags.extend(owasp_label(c) for c in owasp_cats)
    sink_cls = getattr(path, "sink_class", "taint_path")
    rule_id = f"vibe.path.{sink_cls}"
    score = min(10.0, max(0.0, getattr(path, "score", 8.0)))

    return {
        "id": rule_id,
        "name": f"attack_path_{sink_cls}",
        "shortDescription": {"text": f"Reachable attack path reaching {sink_cls}"},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[-1]}.html" if "-" in cwe else "https://cwe.mitre.org/",
        "properties": {
            "tags": tags,
            "security-severity": f"{score:.1f}",
        },
    }


def _build_result(finding: Finding) -> dict:
    bucket_val = finding.risk_bucket.value if hasattr(finding.risk_bucket, "value") else str(finding.risk_bucket or "INFO")
    raw_loc = finding.location.file if finding.location else "unknown"
    norm_file = _normalize_sarif_uri(raw_loc)
    start_line = max(1, finding.location.start_line) if finding.location else 1
    end_line = max(start_line, finding.location.end_line) if finding.location and finding.location.end_line else start_line
    sources_list = [s.value if hasattr(s, "value") else str(s) for s in finding.sources]
    sec_score = min(10.0, max(0.0, finding.risk_score or 0.0))

    props: dict[str, Any] = {
        "risk_score": sec_score,
        "security-severity": f"{sec_score:.1f}",
        "risk_bucket": bucket_val,
        "confidence": finding.confidence or 0.0,
        "cwe": finding.cwe or "CWE-0",
        "category": finding.category,
        "sources": sources_list,
        "taint_reachable": bool(finding.taint_reachable),
        "reachability": finding.reachability,
        "exposure_class": finding.exposure_class,
        "scope": finding.scope,
        "epss_score": finding.epss_score,
        "in_cisa_kev": bool(finding.in_cisa_kev),
    }
    if finding.remediation and not finding.fix_snippet:
        props["remediation"] = finding.remediation[:512]

    # Deterministic partial fingerprint for GitHub Code Scanning alert tracking
    fp_hash = hashlib.sha256(
        f"{finding.rule_id}:{norm_file}:{start_line}:{finding.evidence or ''}".encode()
    ).hexdigest()

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(bucket_val, "warning"),
        "message": {"text": finding.title or ""},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": norm_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": start_line,
                        "endLine": end_line,
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": fp_hash[:32],
        },
        "properties": props,
    }

    if finding.evidence:
        result["fingerprints"] = {
            "evidence/v1": finding.evidence[:200],
        }
    if finding.remediation and finding.fix_snippet:
        result["fixes"] = [
            {
                "description": {"text": finding.remediation[:512]},
                "artifactChanges": [
                    {
                        "artifactLocation": {
                            "uri": norm_file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "replacements": [
                            {
                                "deletedRegion": {"startLine": start_line, "endLine": end_line},
                                "insertedContent": {"text": finding.fix_snippet},
                            }
                        ],
                    }
                ],
            }
        ]
    return result


def _build_path_result(path: Any) -> dict:
    steps = getattr(path, "steps", []) or []
    sink_cls = getattr(path, "sink_class", "path")
    rule_id = f"vibe.path.{sink_cls}"
    score = min(10.0, max(0.0, getattr(path, "score", 0.0)))
    level = "error" if score >= 7.0 else ("warning" if score >= 4.0 else "note")

    target_file = steps[-1].file if steps else "unknown"
    norm_target = _normalize_sarif_uri(target_file)
    target_line = steps[-1].line if steps else 1

    thread_flow_locs = []
    for step in steps:
        step_uri = _normalize_sarif_uri(getattr(step, "file", ""))
        thread_flow_locs.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": step_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(1, getattr(step, "line", 1))},
                },
                "message": {"text": f"[{getattr(step, 'operation', 'step')}] {getattr(step, 'code', '')[:100]}"},
            }
        })

    path_hash = hashlib.sha256(
        f"{rule_id}:{norm_target}:{target_line}:{getattr(path, 'id', '')}".encode()
    ).hexdigest()

    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f"[{path.id}] {path.title}: {path.explanation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": norm_target,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": target_line, "endLine": target_line},
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash": path_hash[:32],
        },
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": thread_flow_locs,
                    }
                ]
            }
        ],
        "properties": {
            "path_id": getattr(path, "id", ""),
            "sink_class": sink_cls,
            "auth_state": getattr(path, "auth_state", "UNKNOWN"),
            "score": score,
            "security-severity": f"{score:.1f}",
            "cwe": getattr(path, "cwe", "CWE-0"),
            "poc_curl": getattr(path, "poc_curl", ""),
        },
    }


def export_sarif(
    findings: list[Finding],
    out_path: str | Path,
    tool_name: str = "VibeSec",
    tool_version: str = "3.0.0",
    attack_paths: list[Any] | None = None,
) -> Path:
    """Write findings and attack paths with codeFlows to a SARIF 2.1.0 JSON file."""
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = _build_rule(f)
        results.append(_build_result(f))

    for p in (attack_paths or []):
        r_id = f"vibe.path.{getattr(p, 'sink_class', 'taint_path')}"
        if r_id not in rules_seen:
            rules_seen[r_id] = _build_path_rule(p)
        results.append(_build_path_result(p))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/vibesec/vibesec",
                        "rules": list(rules_seen.values()),
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": "file:///"
                    }
                },
                "results": results,
            }
        ],
    }

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return out
