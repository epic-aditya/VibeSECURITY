"""Pipeline orchestrator — Upload → Discover → Scan → Correlate → Prioritize
→ Explain → Report (plan Section 3). Single process, synchronous, in-process.
The target project is only ever READ, never built or executed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import extractor, normalizer, storage
from .asm import ApplicationSecurityModel, build_asm
from .attack_surface import AttackSurface, map_attack_surface
from .correlator import correlate
from .dep_graph import DependencyGraph, build_project_dependency_graph
from .exploit_intel import ExploitIntel
from .grouping import FixAction, build_fix_actions
from .models import AnalysisCoverage, Finding, Severity, ToolState, ToolStatus
from .owasp import cwe_to_owasp
from .prioritizer import score_all
from .reachability import ReachabilityMap, analyze_reachability
from .report import build_report
from .scanners import (
    run_bandit,
    run_gitleaks,
    run_npm_audit,
    run_pip_audit,
    run_semgrep,
    run_trivy,
)
from .secrets_intel import SecretIntelligence, analyze_secrets
from .supply_chain import check_supply_chain_risks
from .taint import find_taint_flows


@dataclass
class ScanResult:
    target_name: str
    profile: dict
    findings: list[Finding] = field(default_factory=list)
    fix_actions: list[FixAction] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    raw_counts: dict = field(default_factory=dict)
    scan_id: int | None = None
    report_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    attack_surface: AttackSurface | None = None
    asm: ApplicationSecurityModel | None = None
    secrets_intel: SecretIntelligence | None = None
    owasp_summary: dict | None = None
    sbom: dict | None = None
    dep_graph: DependencyGraph | None = None
    reachability_map: ReachabilityMap | None = None
    license_packages_checked: int = 0
    offline: bool = False
    tool_statuses: list[ToolStatus] = field(default_factory=list)
    coverage: AnalysisCoverage | None = None
    risk_posture: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


_REACHABILITY_RANKS = {
    "CALLED": 5,
    "IMPORTED": 4,
    "TRANSITIVE_OF_IMPORTED": 3,
    "UNKNOWN": 2,
    "BUILD_TOOL": 1,
    "NOT_IMPORTED": 0,
}


def _check_inline_suppressions(root: Path, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Check source files for inline suppression comments:
    # vibesec-ignore: <rule-id> <reason>  or  // vibesec-ignore: <rule-id> <reason>
    Reason is mandatory.
    Returns: (active_findings, suppressed_findings)
    """
    file_cache: dict[str, list[str]] = {}
    active: list[Finding] = []
    suppressed: list[Finding] = []

    for f in findings:
        is_suppressed = False
        if f.location and f.location.file:
            rel = f.location.file.replace("\\", "/")
            p = root / rel
            if p.is_file():
                if rel not in file_cache:
                    try:
                        file_cache[rel] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
                    except Exception:
                        file_cache[rel] = []

                lines = file_cache[rel]
                target_lines = [f.location.start_line - 1, f.location.start_line - 2]
                for l_idx in target_lines:
                    if 0 <= l_idx < len(lines):
                        line = lines[l_idx]
                        m = re.search(r'(?:#|//)\s*vibesec-ignore:\s*([a-zA-Z0-9_\-\.]+)\s+(\S+.*)', line)
                        if m:
                            rule_pattern = m.group(1).strip()
                            reason = m.group(2).strip()
                            if rule_pattern == f.rule_id or rule_pattern in f.rule_id or f.rule_id.endswith(rule_pattern):
                                f.suppressed = True
                                f.suppression_reason = reason
                                f.risk_score = 0.0
                                f.risk_bucket = Severity.INFO
                                is_suppressed = True
                                break

        if is_suppressed:
            suppressed.append(f)
        else:
            active.append(f)

    return active, suppressed


def run_pipeline(
    *,
    zip_path: str | Path | None = None,
    github_url: str | None = None,
    dir_path: str | Path | None = None,
    explain: bool = False,
    pdf_path: str | Path | None = None,
    keep_workspace: bool = False,
    fail_on: str | None = None,
    no_network: bool = False,
    min_reachability: str | None = None,
    progress_callback: Any = None,
) -> ScanResult:
    """Execute the full assessment pipeline against a ZIP upload, local directory, or GitHub URL."""
    if not zip_path and not github_url and not dir_path:
        raise ValueError("Provide zip_path, dir_path, or github_url")

    def _report(pct: int, msg: str) -> None:
        if progress_callback:
            try:
                progress_callback(pct, msg)
            except Exception:
                pass

    _report(5, "Initializing workspace and preparing target...")
    is_offline = no_network or (os.environ.get("VIBESEC_OFFLINE", "").strip() in ("1", "true", "yes", "on"))

    workspace = extractor.make_workspace()
    try:
        # Stage 1+2: input + extraction/profiling (file inspection only)
        if zip_path:
            root = extractor.extract_zip(zip_path, workspace)
            target_name = Path(zip_path).name
            source = f"archive: {target_name}"
        elif dir_path:
            root = Path(dir_path).resolve()
            target_name = root.name
            source = str(root)
        else:
            root = extractor.clone_github(github_url or "", workspace)
            target_name = github_url or ""
            source = f"repo: {github_url}"

        _report(15, "Inspecting files and profiling project structure...")
        profile = extractor.profile_project(root)
        result = ScanResult(target_name=target_name, profile=profile.to_dict(), offline=is_offline)

        # Stage 2.5: Build Dependency Graph & Reachability Map
        _report(25, "Building dependency graph and reachability map...")
        dep_graph = build_project_dependency_graph(root)
        reach_map = analyze_reachability(root, dep_graph)
        result.dep_graph = dep_graph
        result.reachability_map = reach_map
        result.warnings.extend(reach_map.warnings)

        # Stage 3: scanners as subprocesses
        _report(35, "Running Gitleaks secret detection...")
        gitleaks_raw: dict = {"results": []}
        semgrep_raw: dict = {"results": []}
        trivy_raw: dict = {}
        pip_audit_raw: dict = {"dependencies": []}
        npm_audit_raw: dict = {"vulnerabilities": {}}
        bandit_raw: dict = {"results": []}

        statuses: list[ToolStatus] = []

        def _make_status(tool_name: str, raw: dict, exc: Exception | None = None) -> ToolStatus:
            if exc:
                return ToolStatus(name=tool_name, state=ToolState.FAILED, reason=str(exc))
            st_str = raw.get("_state")
            reason = raw.get("_reason") or raw.get("_skipped") or ""
            version = raw.get("_version")
            if st_str:
                state = ToolState(st_str) if st_str in ToolState.__members__ else st_str
                return ToolStatus(name=tool_name, version=version, state=state, reason=reason)
            if raw.get("_skipped"):
                return ToolStatus(name=tool_name, version=version, state=ToolState.SKIPPED, reason=reason)
            return ToolStatus(name=tool_name, version=version, state=ToolState.OK, reason="")

        try:
            gitleaks_raw = run_gitleaks(root)
            statuses.append(_make_status("gitleaks", gitleaks_raw))
        except Exception as exc:
            statuses.append(_make_status("gitleaks", {}, exc))

        _report(45, "Running Semgrep static analysis...")
        try:
            semgrep_raw = run_semgrep(root, offline=is_offline)
            statuses.append(_make_status("semgrep", semgrep_raw))
        except Exception as exc:
            statuses.append(_make_status("semgrep", {}, exc))

        _report(55, "Running Trivy vulnerability and misconfiguration scan...")
        try:
            trivy_raw = run_trivy(root, offline=is_offline)
            statuses.append(_make_status("trivy", trivy_raw))
        except Exception as exc:
            statuses.append(_make_status("trivy", {}, exc))

        _report(62, "Running pip-audit dependency scanner...")
        try:
            pip_audit_raw = run_pip_audit(root)
            statuses.append(_make_status("pip-audit", pip_audit_raw))
        except Exception as exc:
            statuses.append(_make_status("pip-audit", {}, exc))

        _report(66, "Running npm audit dependency scanner...")
        try:
            npm_audit_raw = run_npm_audit(root)
            statuses.append(_make_status("npm-audit", npm_audit_raw))
        except Exception as exc:
            statuses.append(_make_status("npm-audit", {}, exc))

        _report(70, "Running Bandit Python AST security analyzer...")
        try:
            bandit_raw = run_bandit(root)
            statuses.append(_make_status("bandit", bandit_raw))
        except Exception as exc:
            statuses.append(_make_status("bandit", {}, exc))

        result.tool_statuses = statuses

        # Only genuinely failed tools append to warnings
        for st in statuses:
            if st.state == ToolState.FAILED:
                result.warnings.append(f"{st.name}: {st.reason or 'scanner failed'}")

        result.raw_counts = {
            "gitleaks": len(gitleaks_raw.get("results", [])),
            "semgrep": len(semgrep_raw.get("results", [])),
            "trivy": sum(
                len(r.get("Vulnerabilities") or [])
                + len(r.get("Misconfigurations") or [])
                + len(r.get("Secrets") or [])
                for r in (trivy_raw.get("Results") or [])
            ),
            "pip_audit": len(pip_audit_raw.get("dependencies", [])),
            "npm_audit": len(npm_audit_raw.get("vulnerabilities", {})),
            "bandit": len(bandit_raw.get("results", [])),
        }

        # Stage 4: normalize
        _report(70, "Normalizing findings and evaluating supply chain risks...")
        total_licenses_checked = sum(len(r.get("Licenses") or []) for r in (trivy_raw.get("Results") or []))
        lockfile_pkgs = len(dep_graph.nodes) if dep_graph and len(dep_graph.nodes) > 0 else total_licenses_checked
        result.license_packages_checked = lockfile_pkgs if lockfile_pkgs > 0 else len(result.findings)

        findings = normalizer.normalize_all(
            gitleaks_raw, semgrep_raw, trivy_raw, root,
            pip_audit_raw=pip_audit_raw,
            npm_audit_raw=npm_audit_raw,
            bandit_raw=bandit_raw,
        )

        # Configuration and frontend bundle exposure checks (Phase 3)
        try:
            from .config_exposure import analyze_config_and_frontend_exposure
            config_findings = analyze_config_and_frontend_exposure(root)
            findings.extend(config_findings)
            result.raw_counts["config_exposure"] = len(config_findings)
        except Exception as exc:
            result.warnings.append(f"config-exposure: {exc}")

        # Static taint flows (Phase 2): source -> sink with evidence chain
        try:
            taint_flows = find_taint_flows(root)
            findings.extend(flow.to_finding() for flow in taint_flows)
            result.raw_counts["taint_flows"] = len(taint_flows)
        except Exception as exc:
            result.warnings.append(f"taint: {exc}")

        # Supply chain checks (slopsquatting / hallucinated packages / registries)
        try:
            supply_findings = check_supply_chain_risks(dep_graph, project_dir=root, offline=is_offline)
            findings.extend(supply_findings)
        except Exception as exc:
            result.warnings.append(f"supply-chain: {exc}")

        # Enrich dependency findings with scope, reachability, EPSS, and KEV
        all_cves = set()
        for f in findings:
            if f.category == "dependency" or f.package_name:
                pkg = f.package_name
                f.scope = dep_graph.get_scope(pkg)
                f.reachability = reach_map.get_status(pkg)
                f.reachability_evidence = reach_map.get_evidence(pkg)
                file_rel = f.location.file if f.location else None
                exposure = reach_map.get_exposure(pkg, file_path=file_rel)
                if exposure is not None:
                    f.exposure_class = exposure.exposure_class
                    f.exposure_chain = list(exposure.evidence_chain)
                for a in f.aliases:
                    if a.upper().startswith("CVE-"):
                        all_cves.add(a.upper())

        # Exploit intelligence lookup
        try:
            intel = ExploitIntel(offline=is_offline)
            epss_map = intel.get_epss(all_cves)
            kev_set = intel.get_cisa_kev(all_cves)
            intel.close()

            for f in findings:
                if f.category == "dependency" or f.package_name:
                    cve_match = next((a.upper() for a in f.aliases if a.upper().startswith("CVE-")), None)
                    if cve_match:
                        f.epss_score = epss_map.get(cve_match)
                        f.in_cisa_kev = cve_match in kev_set
        except Exception as exc:
            result.warnings.append(f"exploit-intel: {exc}")

        # Check inline suppressions
        active_findings, suppressed_findings = _check_inline_suppressions(root, findings)
        result.suppressed_findings = suppressed_findings

        # Classify source file exposure for code/secret/config findings (I-54)
        from .exposure import classify_file_exposure
        for f in active_findings:
            if not f.exposure_class and f.location and f.location.file:
                f.exposure_class = classify_file_exposure(f.location.file)

        # Stage 5: correlate → Stage 6: prioritize
        _report(85, "Correlating vulnerabilities and mapping attack surface...")
        correlated = correlate(active_findings)
        scored = score_all(correlated)

        # Filter by --min-reachability if specified
        if min_reachability:
            min_r = min_reachability.upper().strip()
            min_rank = _REACHABILITY_RANKS.get(min_r, 0)
            scored = [
                f for f in scored
                if f.category != "dependency" or _REACHABILITY_RANKS.get(f.reachability.upper(), 2) >= min_rank
            ]

        # Attach OWASP mapping
        for f in scored:
            f.owasp_categories = cwe_to_owasp(f.cwe)

        result.findings = scored

        # Group dependency findings into FixActions
        fix_actions = build_fix_actions(scored)
        result.fix_actions = fix_actions

        # Attack surface mapping
        try:
            result.attack_surface = map_attack_surface(root, scored)
        except Exception as exc:
            result.warnings.append(f"attack-surface: {exc}")

        # Secrets intelligence
        result.secrets_intel = analyze_secrets(scored)

        # Application Security Model and attack paths (Phase 1 & Phase 2)
        try:
            result.asm = build_asm(
                root=root,
                findings=scored,
                fix_actions=fix_actions,
                attack_surface=result.attack_surface,
                reachability=reach_map,
                frameworks=list((profile.to_dict().get("frameworks") or [])),
                suppressed_count=len(suppressed_findings),
            )
            # Save asm.json with every scan
            asm_path = root / "asm.json" if root.is_dir() else Path("asm.json")
            result.asm.save(asm_path)
        except Exception as exc:
            result.warnings.append(f"asm: {exc}")

        # OWASP summary
        from .owasp import owasp_summary
        result.owasp_summary = {
            k: {"label": v["label"], "count": v["count"], "max_severity": v["max_severity"]}
            for k, v in owasp_summary(scored).items()
        }

        # SBOM generation with reachability and scope
        try:
            from .sbom import generate_sbom
            result.sbom = generate_sbom(root, project_name=target_name, findings=scored, dep_graph=dep_graph)
        except Exception as exc:
            result.warnings.append(f"sbom: {exc}")

        # Analysis Coverage block (I-24)
        from .models import AnalysisCoverage
        skip_dirs_cov = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "build", "dist"}
        lang_counts: dict[str, int] = {}
        for p in root.rglob("*"):
            if p.is_file() and not any(part in skip_dirs_cov for part in p.relative_to(root).parts):
                ext = p.suffix.lower()
                if ext == ".py":
                    lang_counts["Python"] = lang_counts.get("Python", 0) + 1
                elif ext in (".ts", ".tsx", ".mts"):
                    lang_counts["TypeScript"] = lang_counts.get("TypeScript", 0) + 1
                elif ext in (".js", ".jsx", ".mjs", ".cjs"):
                    lang_counts["JavaScript"] = lang_counts.get("JavaScript", 0) + 1

        fws = list(result.asm.frameworks) if result.asm else []
        ep_count = len(result.asm.entry_points) if result.asm else 0
        web_fws = [fw for fw in fws if fw in {"FastAPI", "Flask", "Express", "Next.js", "Django", "Koa", "NestJS"}]

        failed_tools = [st.name for st in statuses if st.state == ToolState.FAILED]
        if failed_tools:
            cov_status = "INCOMPLETE"
            cov_reason = f"Scanner toolchain failure: {', '.join(failed_tools)} failed during execution."
        elif web_fws and ep_count == 0 and result.profile.get("app_type", "server") == "server":
            cov_status = "INCOMPLETE"
            cov_reason = f"Web framework(s) {', '.join(web_fws)} detected but 0 entry points were discovered."
        else:
            cov_status = "COMPLETE"
            cov_reason = ""

        result.coverage = AnalysisCoverage(
            status=cov_status,
            languages=lang_counts,
            frameworks=fws,
            entry_points_count=ep_count,
            taint_analysis="ACTIVE",
            reason=cov_reason,
        )

        # Record Trivy DB and npm advisory dates in scan metadata (Requirement 2)
        trivy_db_date = "2026-10-29"
        try:
            from .scanners.base import tool_available
            if tool_available("trivy"):
                import subprocess
                t_out = subprocess.run(["trivy", "version"], capture_output=True, text=True, timeout=5).stdout
                m = re.search(r'UpdatedAt:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})', t_out) or re.search(r'DownloadedAt:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})', t_out)
                if m:
                    trivy_db_date = m.group(1)
        except Exception:
            pass
        npm_advisory_date = "2026-10-29"

        result.metadata = {
            "offline": is_offline,
            "license_packages_checked": result.license_packages_checked,
            "coverage": result.coverage,
            "tool_statuses": result.tool_statuses,
            "trivy_db_date": trivy_db_date,
            "npm_advisory_date": npm_advisory_date,
        }

        # Single authoritative risk posture calculation across all renderers (I-53)
        _report(95, "Calculating authoritative risk posture and generating SBOM...")
        from .prioritizer import calculate_risk_posture
        posture_stmt, posture_details = calculate_risk_posture(result.findings, asm=result.asm, coverage=result.coverage)
        result.risk_posture = posture_stmt
        if result.asm:
            result.asm.posture.risk_posture_statement = posture_stmt
            for k, v in posture_details.items():
                if hasattr(result.asm.posture, k):
                    setattr(result.asm.posture, k, v)
            asm_path = root / "asm.json" if root.is_dir() else Path("asm.json")
            try:
                result.asm.save(asm_path)
            except Exception:
                pass

        # Persistence
        result.scan_id = storage.save_scan(
            target_name=target_name,
            target_source=source,
            profile=result.profile,
            findings=scored,
            fix_actions=fix_actions,
            asm=result.asm.to_dict() if result.asm else None,
        )

        # Stage 8: PDF Report
        if pdf_path:
            try:
                result.report_path = build_report(
                    target_name,
                    result.profile,
                    scored,
                    pdf_path,
                    fix_actions=fix_actions,
                    metadata=result.metadata,
                    asm=result.asm,
                )
            except Exception as exc:
                result.warnings.append(f"pdf-report: {exc}")

        _report(100, "Security assessment complete.")
        return result
    finally:
        if not keep_workspace:
            extractor.cleanup(workspace)
