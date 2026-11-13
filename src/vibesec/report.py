"""Stage 8 — PDF security report (fpdf2) (v3).

Report structure:
1. Executive summary: one-sentence risk posture (exposure-adjusted) + finding counts.
2. Attack Paths: top 5 reachable paths with steps, sinks, PoC curl templates, and fixes.
3. Application attack surface map: routes, auth states, parameter validations.
4. Code, config & secret findings: real 3-line source context.
5. Dependency Fix Plan: grouped minimal target versions, exposure classes, EPSS, KEV,
   evidence chains, plus deprioritized toolchain appendix.
6. Supply-chain & license compliance.
7. Scan metadata and transparent scoring formulas appendix.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF

from .grouping import FixAction
from .models import Finding, Severity

_SEVERITY_COLORS = {
    "CRITICAL": (180, 20, 20),
    "HIGH": (200, 90, 0),
    "MEDIUM": (160, 130, 0),
    "LOW": (0, 102, 153),
    "INFO": (100, 100, 100),
}


def _t(text: str | None) -> str:
    """Latin-1 safe text for built-in PDF fonts."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    replacements = {
        "—": "-", "–": "-", "·": "*", "•": "*",
        "“": '"', "”": '"', "‘": "'", "’": "'",
        "…": "...", "→": "->", "←": "<-", "≥": ">=", "≤": "<=",
        "✓": "[OK]", "✗": "[X]", "✔": "[OK]", "❌": "[X]",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("helvetica", "B", 9)
        self.set_text_color(130, 130, 130)
        self.set_x(self.l_margin)
        self.cell(self.epw, 7, "VibeSec Application Security Assessment Report", align="R", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("helvetica", "", 8)
        self.set_text_color(130, 130, 130)
        self.set_x(self.l_margin)
        self.cell(self.epw, 10, f"Page {self.page_no()}", align="C", new_x="LMARGIN", new_y="NEXT")

    def write_line(self, text: str, h: float = 4.8) -> None:
        self.set_x(self.l_margin)
        self.multi_cell(self.epw, h, _t(text), new_x="LMARGIN", new_y="NEXT")


def _section(pdf: ReportPDF, title: str) -> None:
    pdf.ln(3)
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(25, 25, 25)
    pdf.set_x(pdf.l_margin)
    pdf.cell(pdf.epw, 7, _t(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(200, 200, 200)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(2)


def _body(pdf: ReportPDF, text: str, size: int = 9) -> None:
    pdf.set_font("helvetica", "", size)
    pdf.set_text_color(45, 45, 45)
    pdf.write_line(text, h=4.6)


def build_report(
    target_name: str,
    profile: dict,
    findings: list[Finding],
    out_path: str | Path,
    fix_actions: list[FixAction] | None = None,
    metadata: dict[str, Any] | None = None,
    asm: Any | None = None,
    offline: bool | None = None,
    suppressed_findings: list[Finding] | None = None,
) -> Path:
    meta = dict(metadata or {})
    if offline is not None:
        meta["offline"] = offline

    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Title block
    pdf.set_font("helvetica", "B", 18)
    pdf.set_text_color(20, 20, 20)
    pdf.set_x(pdf.l_margin)
    pdf.cell(pdf.epw, 10, "VibeSec Application Security Assessment", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(80, 80, 80)
    pdf.set_x(pdf.l_margin)
    pdf.cell(pdf.epw, 6, _t(f"Target: {target_name} | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    asm_dict = asm.to_dict() if asm is not None and hasattr(asm, "to_dict") else (asm or {})
    attack_paths = asm_dict.get("attack_paths", []) or []
    entry_points = asm_dict.get("entry_points", []) or []

    # 1. Executive Summary & Exposure-Adjusted Risk Posture
    _section(pdf, "1. Executive Summary & Risk Posture")
    from .prioritizer import calculate_risk_posture, is_actionable
    posture_stmt, p_details = calculate_risk_posture(findings, asm=asm_dict, coverage=meta.get("coverage"))
    _body(pdf, f"Risk Posture: {posture_stmt}", size=10)
    pdf.ln(1)

    dep_findings = [f for f in findings if f.category == "dependency"]
    runtime_cves = sum(
        1 for f in dep_findings
        if (f.exposure_class or "").startswith("RUNTIME") and f.reachability != "NOT_IMPORTED"
    )
    deprioritized_cves = sum(
        1 for f in dep_findings
        if (f.exposure_class or "").startswith("TOOLCHAIN")
        or f.exposure_class == "TEST"
        or f.reachability == "NOT_IMPORTED"
    )
    code_cnt = sum(1 for f in findings if f.category == "code")
    config_cnt = sum(1 for f in findings if f.category == "config")
    secret_cnt = sum(1 for f in findings if f.category == "secret")
    license_review_cnt = sum(1 for f in findings if f.category == "license")

    crit_cnt = sum(1 for f in findings if f.risk_bucket == Severity.CRITICAL)
    high_cnt = sum(1 for f in findings if f.risk_bucket == Severity.HIGH)
    med_cnt = sum(1 for f in findings if f.risk_bucket == Severity.MEDIUM)
    low_cnt = sum(1 for f in findings if f.risk_bucket == Severity.LOW)
    info_cnt = sum(1 for f in findings if f.risk_bucket == Severity.INFO)
    max_score = max((f.risk_score for f in findings), default=0.0)

    supp_cnt = len(suppressed_findings) if suppressed_findings is not None else 0
    _body(pdf, f"Actionable: {p_details.get('actionable_findings', len(findings))} | Deprioritized: {p_details.get('deprioritized_findings', 0)} ({p_details.get('deprioritized_dependency_cves', 0)} dependency CVE(s), {p_details.get('deprioritized_test_toolchain', 0)} test/toolchain finding(s)) | Filtered: {supp_cnt}")
    _body(pdf, f"Severity Breakdown: Critical: {crit_cnt} | High: {high_cnt} | Medium: {med_cnt} | Low: {low_cnt} | Info: {info_cnt} | Highest Score: {max_score:.1f}")
    _body(pdf, f"Attack Paths: {p_details.get('reachable_attack_paths', len(attack_paths))} reachable | Unauthenticated Critical Paths: {p_details.get('unauthenticated_critical_paths', 0)}")
    if p_details.get("cisa_kev_count", 0) > 0:
        _body(pdf, f"CISA KEV Catalog Matches: {p_details.get('cisa_kev_count')}")

    _body(pdf, (
        f"Findings Summary: {len(findings)} total | Attack Paths: {len(attack_paths)} | "
        f"Code: {code_cnt} | Config: {config_cnt} | Secrets: {secret_cnt} | "
        f"Actionable Runtime CVEs: {runtime_cves} | Deprioritized CVEs: {deprioritized_cves} | "
        f"License Review: {license_review_cnt} | Fix Actions: {len(fix_actions or [])}"
    ))
    cov = meta.get("coverage")
    if cov:
        cov_dict = cov.to_dict() if hasattr(cov, "to_dict") else (cov if isinstance(cov, dict) else {})
        _body(pdf, f"Analysis Coverage: {cov_dict.get('status', 'COMPLETE')} | Discovered Routes: {cov_dict.get('entry_points_count', len(entry_points))} | Taint Engine: {cov_dict.get('taint_analysis', 'ACTIVE')}")
        if cov_dict.get("reason"):
            _body(pdf, f"  * Note: {cov_dict.get('reason')}")

    tool_statuses = meta.get("tool_statuses")
    if tool_statuses:
        st_parts = []
        for ts in tool_statuses:
            ts_state = ts.state.value if hasattr(ts.state, "value") else str(getattr(ts, "state", "OK"))
            st_parts.append(f"{getattr(ts, 'name', '')}: {ts_state}")
        _body(pdf, f"Scanner Status: {' | '.join(st_parts)}")
    pdf.ln(2)

    # 2. Attack Paths (The Core Intelligence)
    _section(pdf, "2. Attack Paths (Inter-procedural Taint Flows)")
    if not attack_paths:
        _body(pdf, "No source-to-sink attack paths were proven by static taint analysis.")
    else:
        for idx, p in enumerate(attack_paths[:5], start=1):
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(180, 20, 20)
            pdf.write_line(f"Path #{idx} [{p.get('sink_class', 'vulnerability').replace('_', ' ').upper()}] (Score: {p.get('score', 0):.1f})")
            _body(pdf, f"Entrypoint: {p.get('method')} {p.get('route')} | Auth: {p.get('auth_state')} | CWE: {p.get('cwe')}")
            _body(pdf, f"Source: {p.get('source')} -> Sink: {p.get('sink')}")

            steps = p.get("steps", [])
            if steps:
                _body(pdf, "Flow Trace:")
                for s in steps:
                    _body(pdf, f"  * [{s.get('operation')}] {s.get('file')}:{s.get('line')} -> {s.get('code', '')[:80]}")

            if p.get("poc_curl"):
                _body(pdf, "Verification PoC (Template only - never executed):")
                _body(pdf, f"  {p.get('poc_curl')}")
                _body(pdf, f"Expected Response Marker: {p.get('poc_expected_response')}")

            if p.get("fix_recommendation"):
                _body(pdf, f"Recommended Fix: {p.get('fix_recommendation')}")
            pdf.ln(2)

    # 3. Application Attack Surface & Route Profile
    _section(pdf, "3. Application Attack Surface Map")
    if profile.get("frameworks") or asm_dict.get("frameworks"):
        fws = asm_dict.get("frameworks") or profile.get("frameworks", [])
        _body(pdf, f"Frameworks Detected: {', '.join(fws)} | Total Routes: {len(entry_points)}")
    if not entry_points:
        app_type_str = str(profile.get("app_type", "library")).upper()
        _body(pdf, f"No HTTP entry points discovered (Application type: {app_type_str}).")
    else:
        for ep in entry_points[:15]:
            params_str = ", ".join(f"{param.get('name')}:{param.get('validation')}" for param in ep.get("parameters", []))
            _body(pdf, f"* [{ep.get('method')}] {ep.get('path')} | Auth: {ep.get('auth_state')} | Validations: {params_str or 'none'}")
        if len(entry_points) > 15:
            _body(pdf, f"* ... ({len(entry_points) - 15} more routes detailed in JSON/SARIF export)")
    pdf.ln(2)

    # 4. Code & Configuration Findings
    _section(pdf, "4. Code, Secret & Configuration Findings")
    actionable_code_secrets = [f for f in findings if f.category in ("code", "config", "secret") and is_actionable(f)]
    non_actionable_code_secrets = [f for f in findings if f.category in ("code", "config", "secret") and not is_actionable(f)]
    if not actionable_code_secrets:
        _body(pdf, "No active actionable code, secret, or configuration findings detected.")
    else:
        for f in actionable_code_secrets[:15]:
            color = _SEVERITY_COLORS.get(f.risk_bucket.value, (100, 100, 100))
            pdf.set_text_color(*color)
            pdf.set_font("helvetica", "B", 9)
            pdf.write_line(f"[{f.risk_bucket.value}] {f.title} (Score: {f.risk_score:.1f})")
            _body(pdf, f"Location: {f.location.file}:{f.location.start_line} | CWE: {f.cwe} | Category: {f.category}")
            if f.evidence:
                _body(pdf, f"Evidence Context:\n{f.evidence[:300]}")
            if f.remediation or f.fix_snippet:
                _body(pdf, f"Fix: {f.remediation or f.fix_snippet}")
            pdf.ln(1)

    if non_actionable_code_secrets:
        _body(pdf, f"Collapsed Non-Actionable Findings ({len(non_actionable_code_secrets)} in test/toolchain/INFO):", size=9)
        summary_groups: dict[tuple[str, str], int] = {}
        for f in non_actionable_code_secrets:
            f_folder = "/".join((f.location.file if f.location else "").replace("\\", "/").split("/")[:-1]) or "."
            summary_groups[(f_folder, f.rule_id)] = summary_groups.get((f_folder, f.rule_id), 0) + 1
        for (f_folder, f_rule), cnt in sorted(summary_groups.items())[:10]:
            _body(pdf, f"  * [{f_folder}] {f_rule}: {cnt} finding(s)", size=8)

    # 5. Dependency Fix Plan (Actionable vs Deprioritized)
    _section(pdf, "5. Dependency Fix Plan (SCA Intelligence)")
    if not fix_actions:
        _body(pdf, "All dependencies up to date.")
    else:
        actionable_actions = [a for a in fix_actions if (a.exposure_class or "").startswith("RUNTIME") or a.reachability in ("CALLED", "IMPORTED", "TRANSITIVE_OF_RUNTIME")]
        deprioritized_actions = [a for a in fix_actions if a not in actionable_actions]
        total_actions = len(fix_actions)

        top_act = min(10, len(actionable_actions))
        _body(pdf, f"Actionable Production Upgrades (showing top {top_act} of {len(actionable_actions)} actionable actions):", size=9)
        for act in actionable_actions[:top_act]:
            bump_warn = " [MAJOR BUMP: may be breaking]" if act.is_major_bump else ""
            epss_str = f"{act.max_epss:.2f}" if act.epss_measured and act.max_epss is not None else "not measured"
            kev_str = "[CISA KEV]" if act.kev_count > 0 else "no KEV"
            chain_str = f" | Chain: {' > '.join(act.evidence_chain)}" if act.evidence_chain else ""
            _body(pdf, (
                f"* {act.package_name} ({act.installed_version} -> {act.target_version}) | Exposure: {act.exposure_class} | "
                f"Reachability: {act.reachability} | EPSS: {epss_str} | {kev_str} | Resolves {len(act.cves_resolved)} CVEs{chain_str}{bump_warn}"
            ))

        if deprioritized_actions:
            exp_counts: dict[str, int] = {}
            for a in deprioritized_actions:
                exp = a.exposure_class or "UNKNOWN"
                exp_counts[exp] = exp_counts.get(exp, 0) + 1
            counts_str = ", ".join(f"{k}: {v}" for k, v in sorted(exp_counts.items()))

            pdf.ln(1)
            _body(pdf, f"Deprioritized Upgrades ({len(deprioritized_actions)} packages across [{counts_str}], showing top 5):", size=9)
            for act in deprioritized_actions[:5]:
                bump_warn = " [MAJOR BUMP: may be breaking]" if act.is_major_bump else ""
                chain_str = f" ({' > '.join(act.evidence_chain)})" if act.evidence_chain else ""
                _body(pdf, f"  - {act.package_name} ({act.installed_version} -> {act.target_version}) [{act.exposure_class}]{chain_str}{bump_warn}")

        if total_actions > (top_act + 5):
            _body(pdf, f"Showing top {top_act + min(5, len(deprioritized_actions))} of {total_actions} fix actions (remaining actions listed in JSON/SARIF export).", size=8)
    pdf.ln(2)

    # 6. Supply Chain & License Compliance
    _section(pdf, "6. Supply-Chain & License Compliance")
    supply = [f for f in findings if f.category == "supply_chain"]
    licenses = [f for f in findings if f.category == "license"]
    if supply:
        _body(pdf, f"Supply Chain Findings ({len(supply)}):")
        for f in supply:
            _body(pdf, f"* [{f.risk_bucket.value}] {f.title} ({f.package_name})")
    else:
        _body(pdf, "Supply Chain: No hallucinated or typosquatted packages identified.")

    # One compact line summary for license policy plus review items
    meta_info = meta
    pkg_count = meta_info.get("license_packages_checked") or len(set(f.package_name for f in findings if f.package_name)) or len(findings)
    violations = [f for f in licenses if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    reviews = [f for f in licenses if f not in violations]
    review_desc = ", ".join(f"{f.package_name} {f.title}" for f in reviews[:3])
    if review_desc:
        lic_line = f"License policy: {pkg_count} total packages checked, {len(violations)} violations, {len(reviews)} review item(s) ({review_desc})."
    else:
        lic_line = f"License policy: {pkg_count} total packages checked, {len(violations)} violations, 0 review items."
    _body(pdf, lic_line)
    if reviews:
        for r in reviews:
            _body(pdf, f"  * Review item: {r.package_name} - {r.title} ({r.location.file}:{r.location.start_line})")
    pdf.ln(2)

    # 7. Metadata and Scoring Formulas Appendix
    _section(pdf, "7. Appendix: Transparent Scoring Formulas & Scan Metadata")
    _body(pdf, f"Scan Mode: {'Offline (Isolated fallback; EPSS not measured)' if meta.get('offline') else 'Online (EPSS + CISA KEV verified)'}")
    if meta.get("trivy_db_date"):
        _body(pdf, f"Trivy Vulnerability DB Date: {meta.get('trivy_db_date')}")
    if meta.get("npm_advisory_date"):
        _body(pdf, f"NPM Advisory Database Date: {meta.get('npm_advisory_date')}")
    _body(pdf, "Attack Path Formula: PathScore = 10 * Impact(sink) * Exposure(auth) * Confidence")
    _body(pdf, "  Impact: Command/Code 1.0, SQL 0.9, Deserialization 0.85, SSRF/Path 0.7, IDOR 0.75, LLM Prompt 0.6, XSS 0.5")
    _body(pdf, "  Exposure: PUBLIC 1.0, UNKNOWN 0.8, AUTHENTICATED 0.5")
    _body(pdf, "Code Finding Formula: Score = min(10.0, base * Conf * T * A * D * S_asset)")
    _body(pdf, "  base: CVSS score or severity map (CRIT 9.5, HIGH 7.5, MED 5.0, LOW 2.0); Conf: 0.6 + 0.4*conf")
    _body(pdf, "  T: Taint (1.0 reachable, 0.75 unconfirmed); A: Auth (public 1.0, auth 0.75); S_asset: 1.15/1.0")
    _body(pdf, "Dependency Formula: Score = min(10.0, base * R * D * (1 + 0.3*EPSS) + KEV_bonus)")
    _body(pdf, "  base: CVSS score or severity map; R: Reachability (CALLED 1.0, IMPORTED 0.75, NOT_IMPORTED 0.15)")
    _body(pdf, "  D: Exposure (RUNTIME 1.0, UNKNOWN 0.7, TOOLCHAIN 0.35, TEST 0.2); KEV_bonus: 3.0*D")
    _body(pdf, "Severity Buckets: CRITICAL >= 9.0, HIGH >= 7.0, MEDIUM >= 4.0, LOW > 0.0, INFO == 0.0")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out))
    return out
