"""Multi-format report exports — HTML, CSV, Markdown, JSON.

Overhauled in Phase 6:
1. Executive summary with one-sentence risk posture and counts by category.
2. Top 5 actions from FixActions plus top code findings.
3. Partitioned sections: Code & Config, Secrets, Dependency Fix Plan (grouped),
   Supply-chain (slopsquatting), License review.
4. Compact reachability summary (unimported CVEs, dev-only CVEs).
5. Scan metadata (target, date, tool versions, rule pack v2.0, offline/online).
6. Appendix with transparent scoring formulas. No repeated "also affected" lines.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .grouping import FixAction
from .models import Finding, Severity


def _risk_posture_sentence(findings: list[Finding]) -> str:
    crit = sum(1 for f in findings if f.risk_bucket.value == "CRITICAL")
    high = sum(1 for f in findings if f.risk_bucket.value == "HIGH")
    med = sum(1 for f in findings if f.risk_bucket.value == "MEDIUM")
    if crit > 0:
        return f"CRITICAL RISK: {crit} critical vulnerability item(s) require immediate remediation before release."
    if high > 0:
        return f"ELEVATED RISK: {high} high-severity issue(s) detected across active codebase and dependencies."
    if med > 0:
        return "MODERATE RISK: Scheduled remediation and dependency maintenance recommended."
    return "STRONG SECURITY POSTURE: No high or critical severity vulnerabilities detected."


def _compute_category_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"code": 0, "secret": 0, "dependency": 0, "config": 0, "supply_chain": 0, "license": 0}
    for f in findings:
        cat = f.category if f.category in counts else "code"
        counts[cat] += 1
    return counts


def export_json(
    findings: list[Finding],
    profile: dict,
    out_path: str | Path,
    target_name: str | None = None,
    fix_actions: list[FixAction] | None = None,
    metadata: dict[str, Any] | None = None,
    asm: dict[str, Any] | None = None,
    offline: bool | None = None,
) -> Path:
    """Export findings, fix actions, ASM, attack paths, and metadata as JSON."""
    meta = dict(metadata or {})
    if offline is not None:
        meta["offline"] = offline
    asm_dict = asm.to_dict() if asm is not None and hasattr(asm, "to_dict") else (asm or {})
    data = {
        "schema_version": "v3",
        "vibesec_version": "3.0.0",
        "rule_pack_version": "3.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "metadata": meta,
        "risk_posture": _risk_posture_sentence(findings),
        "category_counts": _compute_category_counts(findings),
        "profile": profile or {},
        "finding_count": len(findings),
        "asm": asm_dict,
        "attack_paths": asm_dict.get("attack_paths", []),
        "posture": asm_dict.get("posture", {}),
        "fix_actions": [
            {
                "action_id": a.action_id,
                "package_name": a.package_name,
                "installed_version": a.installed_version,
                "target_version": a.target_version,
                "cves_resolved": a.cves_resolved,
                "is_major_bump": a.is_major_bump,
                "scope": a.scope,
                "reachability": a.reachability,
                "exposure_class": a.exposure_class,
                "evidence_chain": list(a.evidence_chain),
                "max_score": a.max_score,
                "max_epss": a.max_epss,
                "epss_measured": a.epss_measured,
                "kev_count": a.kev_count,
                "summary": a.summary(),
            }
            for a in (fix_actions or [])
        ],
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(data, indent=2, default=lambda o: o.to_dict() if hasattr(o, "to_dict") else str(o)),
        encoding="utf-8",
    )
    return out


def export_markdown(
    findings: list[Finding],
    profile: dict,
    target_name: str,
    out_path: str | Path,
    fix_actions: list[FixAction] | None = None,
    metadata: dict[str, Any] | None = None,
    asm: dict[str, Any] | None = None,
    offline: bool | None = None,
    suppressed_findings: list[Finding] | None = None,
) -> Path:
    """Export comprehensive Markdown report with ASM, attack paths, and audit ledger."""
    meta = dict(metadata or {})
    if offline is not None:
        meta["offline"] = offline

    asm_dict = asm.to_dict() if asm is not None and hasattr(asm, "to_dict") else (asm or {})
    posture_data = asm_dict.get("posture", {}) or {}
    paths = asm_dict.get("attack_paths", []) or []
    entry_points = asm_dict.get("entry_points", []) or []

    lines: list[str] = []
    lines.append(f"# VibeSec Security Assessment — {target_name}\n")

    # 1. Executive Summary
    lines.append("## 1. Executive Summary\n")
    from .prioritizer import calculate_risk_posture, is_actionable
    posture, p_details = calculate_risk_posture(findings, asm=asm_dict, coverage=meta.get("coverage"))
    lines.append(f"**Risk Posture:** {posture}\n")

    crit_cnt = sum(1 for f in findings if f.risk_bucket == Severity.CRITICAL)
    high_cnt = sum(1 for f in findings if f.risk_bucket == Severity.HIGH)
    med_cnt = sum(1 for f in findings if f.risk_bucket == Severity.MEDIUM)
    low_cnt = sum(1 for f in findings if f.risk_bucket == Severity.LOW)
    info_cnt = sum(1 for f in findings if f.risk_bucket == Severity.INFO)
    max_score = max((f.risk_score for f in findings), default=0.0)

    supp_cnt = len(suppressed_findings) if suppressed_findings is not None else posture_data.get('suppressed_findings', 0)
    lines.append(
        f"- **Total findings:** {len(findings)} "
        f"| **Actionable findings:** {p_details.get('actionable_findings', len(findings))} "
        f"| **Deprioritized:** {p_details.get('deprioritized_findings', 0)} "
        f"({p_details.get('deprioritized_dependency_cves', 0)} dependency CVE(s), {p_details.get('deprioritized_test_toolchain', 0)} test/toolchain finding(s)) "
        f"| **Findings Removed by Filters / Suppressed:** {supp_cnt}"
    )
    lines.append(
        f"- **Severity Breakdown:** Critical: {crit_cnt} | High: {high_cnt} | Medium: {med_cnt} | Low: {low_cnt} | Info: {info_cnt} | Highest Risk Score: {max_score:.1f}"
    )
    lines.append(
        f"- **Reachable attack paths:** {p_details.get('reachable_attack_paths', len(paths))} "
        f"| **Unauthenticated critical paths:** {p_details.get('unauthenticated_critical_paths', 0)} "
        f"| **Public routes:** {p_details.get('public_routes', 0)} "
        f"| **Public state-changing routes:** {p_details.get('public_state_changing_routes', 0)}"
    )
    if p_details.get("cisa_kev_count", 0) > 0:
        lines.append(f"- **CISA KEV Vulnerabilities:** {p_details.get('cisa_kev_count')}")
    lines.append(
        f"- **Runtime packages with findings:** {posture_data.get('runtime_packages_with_findings', 0)} "
        f"| **Toolchain packages with findings:** {posture_data.get('toolchain_packages_with_findings', 0)}"
    )
    lines.append("")

    # Collapsed non-actionable findings summary (Item 7)
    non_actionable = [f for f in findings if not is_actionable(f)]
    if non_actionable:
        lines.append("### Collapsed Non-Actionable Findings (Test / Toolchain / Info Summary)\n")
        lines.append("| Folder | Rule ID | Count | Classification |")
        lines.append("| :--- | :--- | :--- | :--- |")
        summary_groups: dict[tuple[str, str], list[Finding]] = {}
        for f in non_actionable:
            f_folder = "/".join((f.location.file if f.location else "").replace("\\", "/").split("/")[:-1]) or "."
            summary_groups.setdefault((f_folder, f.rule_id), []).append(f)
        for (f_folder, f_rule), g_list in sorted(summary_groups.items()):
            reasons = set(f.exposure_class or ("INFO" if f.risk_bucket == Severity.INFO else "NON_RUNTIME") for f in g_list)
            lines.append(f"| `{f_folder}` | `{f_rule}` | {len(g_list)} | {', '.join(sorted(reasons))} |")
        lines.append("\n")

    # Analysis Coverage (I-24)
    cov = meta.get("coverage")
    if cov:
        cov_dict = cov.to_dict() if hasattr(cov, "to_dict") else (cov if isinstance(cov, dict) else {})
        lines.append("### Analysis Coverage\n")
        lines.append(f"- **Coverage Status:** `{cov_dict.get('status', 'COMPLETE')}`")
        if cov_dict.get("reason"):
            lines.append(f"- **Coverage Detail:** {cov_dict.get('reason')}")
        langs = cov_dict.get("languages", {})
        if langs:
            langs_str = ", ".join(f"{k} ({v} files)" for k, v in sorted(langs.items()))
            lines.append(f"- **Languages Detected:** {langs_str}")
        fws = cov_dict.get("frameworks", [])
        if fws:
            lines.append(f"- **Frameworks:** {', '.join(fws)}")
        lines.append(f"- **Entry Points Discovered:** {cov_dict.get('entry_points_count', len(entry_points))}")
        lines.append(f"- **Taint Analysis:** {cov_dict.get('taint_analysis', 'ACTIVE')}\n")

    # Scanner Tool Status (I-05)
    tool_statuses = meta.get("tool_statuses")
    if tool_statuses:
        lines.append("### Scanner Tool Status\n")
        lines.append("| Tool | State | Version | Details |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for ts in tool_statuses:
            ts_state = ts.state.value if hasattr(ts.state, "value") else str(getattr(ts, "state", "OK"))
            lines.append(f"| `{getattr(ts, 'name', '')}` | **{ts_state}** | {getattr(ts, 'version', '')} | {getattr(ts, 'reason', '') or 'OK'} |")
        lines.append("\n")

    cat_counts = _compute_category_counts(findings)
    lines.append("| Category | Findings Count |")
    lines.append("| :--- | :--- |")
    for cat, cnt in cat_counts.items():
        lines.append(f"| **{cat.replace('_', ' ').capitalize()}** | {cnt} |")
    lines.append("\n")

    # 2. Top Priority Remediation Actions
    lines.append("## 2. Top Remediation Actions\n")
    if paths:
        lines.append("### Reachable Attack Paths:\n")
        for idx, path in enumerate(paths[:5], start=1):
            lines.append(
                f"{idx}. **[{path.get('severity')}]** {path.get('title')} "
                f"(path score {path.get('score')}, confidence {path.get('confidence')})"
            )
        lines.append("\n")
    if fix_actions:
        lines.append("### Recommended Dependency Upgrades (Grouped):\n")
        for idx, act in enumerate(fix_actions[:5], start=1):
            lines.append(f"{idx}. {act.summary()}")
        lines.append("\n")

    top_code = [f for f in findings if f.category in ("code", "secret", "config") and f.risk_score >= 12.0][:5]
    if top_code:
        lines.append("### Urgent Code & Config Fixes:\n")
        for idx, f in enumerate(top_code, start=1):
            lines.append(f"{idx}. **[{f.risk_bucket.value}]** `{f.location.file}:{f.location.start_line}` — {f.title} (Score: {f.risk_score})")
        lines.append("\n")

    # 3. Application Security Model: Attack Surface & Paths
    lines.append("## 3. Attack Surface & Attack Paths\n")
    if profile.get("frameworks"):
        lines.append(f"- **Frameworks (static detection):** {', '.join(profile['frameworks'])}")
    lines.append(f"- **Discovered entry points:** {len(entry_points)}")
    if not entry_points:
        app_type_str = str(profile.get("app_type", "library")).upper()
        lines.append(f"- **Application type:** `{app_type_str}`")
        lines.append(f"\nNo HTTP entry points discovered (Application type: `{app_type_str}`).\n")
    if posture_data:
        lines.append(f"- **Public entry points:** {posture_data.get('public_routes', 0)}")
        lines.append(f"- **Public state-changing routes:** {posture_data.get('public_state_changing_routes', 0)}")
        lines.append(f"- **Secrets in client bundle (file-level evidence):** {posture_data.get('secrets_in_client_bundle', 0)}")
    if entry_points:
        lines.append("\n| Method | Path | File | Auth | Accepts Input |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for ep in entry_points[:25]:
            lines.append(
                f"| `{ep.get('method')}` | `{ep.get('path')}` | `{ep.get('file')}:{ep.get('line')}` "
                f"| {ep.get('auth')} | {ep.get('accepts_input')} |"
            )
        if len(entry_points) > 25:
            lines.append(f"\n*Showing 25 of {len(entry_points)} entry points; full list in JSON.*")
    lines.append("")
    if paths:
        lines.append("### Source-to-Sink Paths\n")
        for path in paths[:10]:
            lines.append(f"#### [{path.get('severity')}] {path.get('title')}")
            lines.append(
                f"- **Score:** {path.get('score')} (10 × impact {path.get('impact_class')} × "
                f"exposure {path.get('exposure')} × confidence {path.get('confidence')})"
            )
            lines.append(f"- **Location:** `{path.get('location')}` | **CWE:** `{path.get('cwe')}`")
            chain = path.get("evidence_chain") or []
            if chain:
                lines.append("- **Evidence chain (static):**")
                for step in chain:
                    lines.append(f"  - `{step}`")
            lines.append("")
    else:
        lines.append("No source-to-sink attack paths were proven by static taint analysis.\n")

    # 4. Code & Configuration Findings (Actionable Only)
    lines.append("## 4. Code & Configuration Findings\n")
    actionable_code = [f for f in findings if f.category in ("code", "config") and is_actionable(f)]
    non_actionable_code = [f for f in findings if f.category in ("code", "config") and not is_actionable(f)]
    if not actionable_code:
        lines.append("No active actionable code or configuration vulnerabilities detected.\n")
    else:
        for f in actionable_code:
            lines.append(f"### [{f.risk_bucket.value}] {f.title}")
            lines.append(f"- **Rule ID:** `{f.rule_id}` | **CWE:** `{f.cwe}` | **Risk Score:** {f.risk_score}")
            lines.append(f"- **Location:** `{f.location.file}:{f.location.start_line}`")
            if f.evidence:
                lines.append(f"```text\n{f.evidence.strip()}\n```")
            if f.remediation or f.fix_snippet:
                lines.append(f"**Suggested Fix:** {f.remediation or f.fix_snippet}\n")

    if non_actionable_code:
        lines.append(f"### Collapsed Non-Actionable Findings ({len(non_actionable_code)} in test/toolchain/INFO)\n")
        lines.append("| Folder | Rule ID | Count | Classification |")
        lines.append("| :--- | :--- | :--- | :--- |")
        code_groups: dict[tuple[str, str], list[Finding]] = {}
        for f in non_actionable_code:
            f_folder = "/".join((f.location.file if f.location else "").replace("\\", "/").split("/")[:-1]) or "."
            code_groups.setdefault((f_folder, f.rule_id), []).append(f)
        for (f_folder, f_rule), g_list in sorted(code_groups.items()):
            reasons = set(f.exposure_class or ("INFO" if f.risk_bucket == Severity.INFO else "NON_RUNTIME") for f in g_list)
            lines.append(f"| `{f_folder}` | `{f_rule}` | {len(g_list)} | {', '.join(sorted(reasons))} |")
        lines.append("\n")

    # 5. Secrets & Credentials (Actionable Only)
    lines.append("## 5. Exposed Secrets & Credentials\n")
    actionable_secrets = [f for f in findings if f.category == "secret" and is_actionable(f)]
    deprioritized_secrets = [f for f in findings if f.category == "secret" and not is_actionable(f)]
    if not actionable_secrets:
        lines.append("No exposed credentials or hardcoded keys identified in production code.\n")
    else:
        for f in actionable_secrets:
            lines.append(f"- **[{f.risk_bucket.value}]** `{f.location.file}:{f.location.start_line}`: {f.title}")
        lines.append("")

    if deprioritized_secrets:
        lines.append(f"### Collapsed Non-Actionable Secrets ({len(deprioritized_secrets)} in test/example files)\n")
        lines.append("| Folder | Secret Type | Count | Classification |")
        lines.append("| :--- | :--- | :--- | :--- |")
        sec_groups: dict[tuple[str, str], int] = {}
        for f in deprioritized_secrets:
            folder = "/".join((f.location.file if f.location else "").replace("\\", "/").split("/")[:-1]) or "."
            sec_groups[(folder, f.title)] = sec_groups.get((folder, f.title), 0) + 1
        for (folder, title), count in sorted(sec_groups.items()):
            lines.append(f"| `{folder}` | `{title}` | {count} | TEST_ENVIRONMENT |")
        lines.append("\n")

    # 6. Dependency Findings & Fix Plan (SCA Intelligence)
    lines.append("\n## 6. Dependency Fix Plan (SCA Intelligence)\n")
    dep_findings = [f for f in findings if f.category == "dependency"]
    actionable_deps = [f for f in dep_findings if is_actionable(f)]
    deprioritized_deps = [f for f in dep_findings if not is_actionable(f)]

    fix_map = {}
    if fix_actions:
        for act in fix_actions:
            fix_map[act.package_name] = act.target_version

    if not actionable_deps:
        lines.append("No actionable third-party dependency vulnerabilities detected.\n")
    else:
        lines.append("| Package | Version | Fix | Exposure | Reachability |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in actionable_deps:
            pkg_name = f.package_name or (f.title.split()[0] if f.title else "unknown")
            pkg_ver = f.package_version or "unknown"
            fix_ver = fix_map.get(pkg_name, "None available")
            exposure = f.exposure_class or "RUNTIME_SERVER"
            reach = f.reachability or "CALLED"
            lines.append(f"| `{pkg_name}` | `{pkg_ver}` | `{fix_ver}` | `{exposure}` | `{reach}` |")
        lines.append("\n")

    if deprioritized_deps:
        lines.append("### Deprioritized Dependencies (Test / Toolchain / Unimported)\n")
        lines.append("| Package | Version | Fix | Exposure | Reachability |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in deprioritized_deps:
            pkg_name = f.package_name or (f.title.split()[0] if f.title else "unknown")
            pkg_ver = f.package_version or "unknown"
            fix_ver = fix_map.get(pkg_name, "None available")
            exposure = f.exposure_class or "TOOLCHAIN_BUILD"
            reach = f.reachability or "NOT_IMPORTED"
            lines.append(f"| `{pkg_name}` | `{pkg_ver}` | `{fix_ver}` | `{exposure}` | `{reach}` |")
        lines.append("\n")

    # 6. Supply Chain & Hallucination Risks
    lines.append("## 7. Supply-Chain & Package Hallucination Intelligence\n")
    supply = [f for f in findings if f.category == "supply_chain"]
    if not supply:
        if meta.get("offline"):
            lines.append("No hallucinated/typosquatted packages flagged in offline checks; registry verification not measured.\n")
        else:
            lines.append("No hallucinated or typosquatted packages flagged by registry checks.\n")
    else:
        for f in supply:
            lines.append(f"- **[{f.risk_bucket.value}]** `{f.package_name}` ({f.ecosystem}): {f.title}")
            lines.append(f"  *Evidence:* {f.evidence}\n")

    # 7. License Review (I-11)
    lines.append("## 8. License Compliance Review\n")
    licenses = [f for f in findings if f.category == "license"]
    violations = [f for f in licenses if "violation" in f.title.lower()]
    reviews = [f for f in licenses if "review" in f.title.lower()]
    pkg_count = meta.get("license_packages_checked", len(licenses))
    lines.append(f"License policy: {pkg_count} total packages checked, {len(violations)} violations, {len(reviews)} review items.\n")
    if licenses:
        for f in licenses:
            lines.append(f"- **[{f.risk_bucket.value}]** `{f.package_name}`: {f.title} — {f.evidence}")

    # 8. Compact Reachability & Exposure Summary
    lines.append("\n## 9. Reachability & Exposure Summary\n")
    dep_findings = [f for f in findings if f.category == "dependency"]
    unimported = sum(1 for f in dep_findings if f.reachability == "NOT_IMPORTED")
    called = sum(1 for f in dep_findings if f.reachability == "CALLED")
    imported = sum(1 for f in dep_findings if f.reachability == "IMPORTED")
    transitive = sum(1 for f in dep_findings if f.reachability == "TRANSITIVE_OF_RUNTIME")
    toolchain = sum(1 for f in dep_findings if f.reachability == "TOOLCHAIN")
    server = sum(1 for f in dep_findings if f.exposure_class == "RUNTIME_SERVER")
    bundle = sum(1 for f in dep_findings if f.exposure_class == "RUNTIME_BUNDLE")
    lines.append(f"- **Total Dependency Findings:** {len(dep_findings)}")
    lines.append(f"- **Called / Imported / Transitive-of-runtime:** {called} / {imported} / {transitive}")
    lines.append(f"- **Toolchain-only (discounted):** {toolchain}")
    lines.append(f"- **Never imported (deprioritized):** {unimported}")
    lines.append(f"- **Exposure split — runtime server / runtime bundle:** {server} / {bundle}\n")

    # 9. Scan Metadata
    lines.append("## 10. Scan Metadata\n")
    lines.append(f"- **Target:** `{target_name}`")
    lines.append(f"- **Date:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("- **Rule Pack:** `VibeSec Rules v3.0.0`")
    lines.append(f"- **Trivy Vulnerability DB Date:** `{meta.get('trivy_db_date', '2026-10-29')}`")
    lines.append(f"- **NPM Advisory Database Date:** `{meta.get('npm_advisory_date', '2026-10-29')}`")
    lines.append(f"- **Execution Mode:** {'Offline (neutral signals; EPSS not measured)' if meta.get('offline') else 'Online (EPSS + CISA KEV when available)'}\n")

    # 10. Audit Ledger: Findings Removed by Filters
    if suppressed_findings:
        lines.append("## 10. Audit Ledger: Findings Removed by Filters\n")
        lines.append(f"**Total Findings Filtered / Suppressed:** {len(suppressed_findings)}\n")
        lines.append("| File | Line | Rule ID | Category | Suppression Reason |")
        lines.append("|---|---|---|---|---|")
        for sf in suppressed_findings[:50]:
            loc_f = sf.location.file if sf.location else "unknown"
            loc_l = sf.location.start_line if sf.location else 1
            reason = sf.suppression_reason or "Non-executable or placeholder"
            lines.append(f"| `{loc_f}` | `{loc_l}` | `{sf.rule_id}` | `{sf.category}` | {reason} |")
        lines.append("")

    # 11. Appendix: Scoring Formulas
    lines.append("## 11. Appendix: Transparent Scoring Formulas\n")
    lines.append("**Code Findings (0–10 Scale):** `Score = min(10.0, base · Conf · T · A · D · S_asset)`\n")
    lines.append("- $base$: CVSS base score (0.0-10.0) if present, else mapped from raw severity (CRITICAL 9.5, HIGH 7.5, MEDIUM 5.0, LOW 2.0, INFO 0.0)")
    lines.append("- $Conf$: Confidence factor = $0.6 + 0.4 \\times confidence$ (range 0.6–1.0)")
    lines.append("- $T$: Taint factor (1.0 for reachable flow or non-sink rules; 0.75 for unconfirmed code sinks)")
    lines.append("- $A$: Authentication context factor (1.0 public/unauth, 0.9 unknown, 0.75 authenticated)")
    lines.append("- $D$: Exposure multiplier (RUNTIME 1.0, UNKNOWN 0.7, TOOLCHAIN_BUILD 0.35, TOOLCHAIN_DEVSERVER 0.25, TEST 0.2)")
    lines.append("- $S_{asset}$: Sensitive asset multiplier (1.15 if credentials/tokens/PII, else 1.0)\n")
    lines.append("**Dependency Findings (0–10 Scale):** `Score = min(10.0, base · R · D · (1 + 0.3·EPSS) + KEV_bonus)`\n")
    lines.append("- $base$: CVSS base score or severity map")
    lines.append("- $R$: Reachability factor (CALLED 1.0, IMPORTED 0.75, UNKNOWN 0.5, TRANSITIVE 0.4, TOOLCHAIN 0.25, NOT_IMPORTED 0.15 [demoted, never hidden])")
    lines.append("- $D$: Exposure multiplier (RUNTIME 1.0, UNKNOWN 0.7, TOOLCHAIN_BUILD 0.35, TEST 0.2)")
    lines.append("- $EPSS$: Exploit probability (0.0-1.0; term dropped [multiplier 1.0] when unmeasured or offline)")
    lines.append("- $KEV_{bonus}$: CISA KEV exploit bonus ($3.0 \\times D$ if actively exploited; CALLED in RUNTIME is guaranteed $\\ge 7.0$)\n")
    lines.append("**Attack Path Score (0–10 Scale):** `PathScore = 10 · Impact · Exposure · Confidence`\n")
    lines.append("- Impact: command/code execution 1.0, SQL 0.9, SSRF/path traversal 0.7, XSS 0.5; Exposure: public 1.0, unknown 0.8, authenticated 0.5\n")
    lines.append("**Severity Buckets:** CRITICAL $\\ge 9.0$ · HIGH $\\ge 7.0$ · MEDIUM $\\ge 4.0$ · LOW $> 0.0$ · INFO $== 0.0$\n")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")
    return out

