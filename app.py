"""VibeSec — Automated Security Assessment Platform for AI-Generated Applications.

Implements the full Upload -> Discover -> Scan -> Correlate -> Prioritize -> Report
pipeline with multi-scanner orchestration, attack-surface mapping, reachability analysis,
CycloneDX SBOM generation, and empirical evaluation benchmarks.

UI Technical Standards:
- Clean technical palette with purposeful contrast (dark steel/slate).
- Monospace styling for code, locations, and metric values.
- Exactly 5 tabs: Scan, Attack Surface & Paths, Dependencies, Reports, Benchmark.
- Tool Status and Coverage banner prominently displayed.
- Deterministic, honest terminology with zero emojis.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

# Streamlit Community Cloud runs the app from the repository root, where the
# package under src/ is not on sys.path. Add it so `import vibesec` resolves.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from vibesec import pipeline, storage
from vibesec.exports import export_markdown
from vibesec.grouping import build_fix_actions
from vibesec.models import Finding
from vibesec.report import build_report
from vibesec.sarif import export_sarif


def render_path_graphviz(path: Any) -> str:
    lines = [
        'digraph AttackPath {',
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="sans-serif", fontsize=10, margin="0.2,0.1"];',
        '  edge [fontname="sans-serif", fontsize=9, color="#8b949e"];',
    ]
    method = getattr(path, "method", "")
    route = getattr(path, "route", "")
    ep_name = f"{method} {route}".strip() or getattr(path, "entry_point_id", "PUBLIC Entrypoint")
    ep_name = str(ep_name).replace('"', '\\"')
    auth = getattr(path, "auth_state", "PUBLIC")
    auth_color = "#fee2e2" if auth == "PUBLIC" else "#dcfce7"
    lines.append(f'  entry [label="{ep_name}\\n[{auth}]", fillcolor="{auth_color}", fontcolor="#1f2937"];')
    prev = "entry"
    for idx, step in enumerate(getattr(path, "steps", [])):
        nid = f"step_{idx}"
        f_raw = getattr(step, "file", "") if hasattr(step, "file") else (step.get("file", "") if isinstance(step, dict) else "")
        f = f_raw.replace("\\", "/").split("/")[-1]
        line_no = getattr(step, "line", 1) if hasattr(step, "line") else (step.get("line", 1) if isinstance(step, dict) else 1)
        code_raw = getattr(step, "code", "") if hasattr(step, "code") else (step.get("code", "") if isinstance(step, dict) else "")
        code = str(code_raw)[:40].replace('"', '\\"').replace('\n', ' ')
        lines.append(f'  {nid} [label="{f}:{line_no}\\n{code}", fillcolor="#e0f2fe", fontcolor="#1e3a8a"];')
        lines.append(f'  {prev} -> {nid};')
        prev = nid
    sc = getattr(path, "sink_class", "Sink").replace('"', '\\"')
    cwe = getattr(path, "cwe", "").replace('"', '\\"')
    lines.append(f'  sink [label="Sink: {sc}\\n{cwe}", fillcolor="#fecaca", fontcolor="#991b1b", shape=octagon];')
    lines.append(f'  {prev} -> sink;')
    lines.append('}')
    return "\n".join(lines)


def render_app_map_graphviz(asm: Any) -> str:
    lines = [
        'digraph ApplicationMap {',
        '  rankdir=TB;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="sans-serif", fontsize=10, margin="0.2,0.1"];',
        '  edge [fontname="sans-serif", fontsize=9, color="#8b949e"];',
        '  subgraph cluster_routes {',
        '    label = "Entrypoints (Routes)"; style=dashed; color="#8b949e"; fontname="sans-serif";',
    ]
    eps = getattr(asm, "entry_points", [])
    if not eps:
        lines.append('    no_routes [label="No routes detected", fillcolor="#f3f4f6", fontcolor="#374151"];')
    else:
        for idx, ep in enumerate(eps[:12]):
            auth = getattr(ep, "auth_state", "PUBLIC")
            color = "#dcfce7" if auth == "AUTHENTICATED" else "#fee2e2" if auth == "PUBLIC" else "#fef3c7"
            lbl = f"{ep.method} {ep.path}\\n[{auth}]".replace('"', '\\"')
            lines.append(f'    route_{idx} [label="{lbl}", fillcolor="{color}", fontcolor="#1f2937"];')
    lines.append('  }')
    if getattr(asm, "data_access_sites", []):
        lines.append('  subgraph cluster_db {')
        lines.append('    label = "Data Stores"; style=dashed; color="#8b949e"; fontname="sans-serif";')
        for idx, da in enumerate(asm.data_access_sites[:4]):
            f = da.file.split("/")[-1].split("\\")[-1]
            lbl = f"{da.kind}\\n{f}:{da.line}".replace('"', '\\"')
            lines.append(f'    db_{idx} [label="{lbl}", fillcolor="#fef3c7", fontcolor="#92400e", shape=cylinder];')
        lines.append('  }')
        if eps:
            lines.append('  route_0 -> db_0 [label="accesses", style=dashed];')
    if getattr(asm, "external_calls", []):
        lines.append('  subgraph cluster_ext {')
        lines.append('    label = "External Services & APIs"; style=dashed; color="#8b949e"; fontname="sans-serif";')
        for idx, ex in enumerate(asm.external_calls[:4]):
            f = ex.file.split("/")[-1].split("\\")[-1]
            lbl = f"{ex.kind}\\n{ex.target or f}".replace('"', '\\"')
            lines.append(f'    ext_{idx} [label="{lbl}", fillcolor="#e0e7ff", fontcolor="#3730a3"];')
        lines.append('  }')
        if eps:
            lines.append('  route_0 -> ext_0 [label="invokes", style=dashed];')
    lines.append('}')
    return "\n".join(lines)


st.set_page_config(
    page_title="VibeSec - Application Security Assessment",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
:root {
    --text-primary: var(--text-color, #1f2328);
    --bg-surface: var(--secondary-background-color, #f6f8fa);
    --border-subtle: rgba(128, 128, 128, 0.25);
    --border-strong: rgba(128, 128, 128, 0.45);
    --text-muted: rgba(128, 128, 128, 0.9);
}

@media (prefers-color-scheme: dark) {
    :root {
        --text-primary: #e6edf3;
        --bg-surface: #161b22;
        --border-subtle: #30363d;
        --border-strong: #8b949e;
        --text-muted: #8b949e;
    }
}

body, [data-testid="stAppViewContainer"] {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: var(--text-color, var(--text-primary));
}

code, pre, .mono-data {
    font-family: "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace !important;
}

h1, h2, h3, h4, h5 {
    font-weight: 600 !important;
    letter-spacing: -0.02em;
    color: var(--text-color, var(--text-primary)) !important;
}

div[data-testid="stExpander"] {
    border: 1px solid var(--border-subtle) !important;
    border-radius: 4px !important;
    background: var(--secondary-background-color, var(--bg-surface)) !important;
    margin-bottom: 8px;
}

div[data-testid="stMetricValue"] {
    font-family: "JetBrains Mono", monospace !important;
    font-size: 1.8rem !important;
    font-weight: 700 !important;
    color: var(--text-color, var(--text-primary)) !important;
}

div[data-testid="stMetricLabel"] {
    font-size: 0.75rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em;
    color: var(--text-muted) !important;
}

button[kind="primary"] {
    background-color: #238636 !important;
    color: #ffffff !important;
    border: 1px solid #2ea043 !important;
    border-radius: 4px !important;
    font-weight: 600 !important;
}

button[data-baseweb="tab"] {
    color: var(--text-muted) !important;
    font-weight: 500 !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--text-color, var(--text-primary)) !important;
    border-bottom: 2px solid #58a6ff !important;
    font-weight: 600 !important;
}

/* Hide Streamlit Community Cloud hosting chrome (creator avatar, Cloud badge,
   and the top toolbar with Fork/GitHub/menu). These elements belong to the
   hosting platform, not the app; selectors are unsupported and may change. */
div[class*="_profileContainer_"],
a[class*="_viewerBadge_"],
[data-testid="stToolbar"] {
    display: none !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_tmpdir" not in st.session_state:
    st.session_state.last_tmpdir = None

# --- Sidebar ---
with st.sidebar:
    st.markdown("### VibeSec Assessment")
    st.caption("Static Application Security Testing for AI-Generated Software")
    st.divider()

    input_mode = st.radio(
        "Target Source",
        ["Local Path", "ZIP Archive", "Public GitHub Repository"],
        label_visibility="collapsed",
    )
    local_path = None
    zip_file = None
    github_url = None

    if input_mode == "Local Path":
        local_path = st.text_input(
            "Local Directory Path",
            value="",
            placeholder="/path/to/project",
            help="Path to repository or extracted application directory",
        )
    elif input_mode == "ZIP Archive":
        zip_file = st.file_uploader(
            "Upload application archive (.zip)",
            type=["zip"],
            help="Zip archive containing source code",
        )
    else:
        github_url = st.text_input(
            "GitHub repository URL",
            placeholder="https://github.com/org/repo",
        )

    offline_mode = st.checkbox(
        "Offline mode (--no-network)",
        value=False,
        help="Disable external network queries; neutral signals used for EPSS/KEV",
    )

    run_scan_btn = st.button("Execute Security Scan", type="primary")

    st.divider()
    st.markdown("**Toolchain Status**")
    st.markdown(
        "- SAST: Semgrep (custom + audit) + Bandit\n"
        "- Secrets: Gitleaks\n"
        "- SCA: Trivy + pip-audit + npm audit\n"
        "- Policy: CycloneDX SBOM + License Evaluation"
    )

# --- Execute Scan ---
if run_scan_btn:
    # Reclaim the previous run's workspace so temporary files stay bounded.
    previous_tmpdir = st.session_state.get("last_tmpdir")
    if previous_tmpdir:
        shutil.rmtree(previous_tmpdir, ignore_errors=True)
    tmpdir = Path(tempfile.mkdtemp(prefix="vibesec-run-"))
    st.session_state.last_tmpdir = str(tmpdir)
    prog_holder = st.empty()
    prog_bar = prog_holder.progress(0, text="Initializing security assessment pipeline...")

    def update_progress(pct: int, msg: str) -> None:
        prog_bar.progress(pct, text=f"[{pct}%] {msg}")

    try:
        pdf_out = tmpdir / "vibesec-security-report.pdf"
        if input_mode == "Local Path" and local_path:
            p = Path(local_path)
            if not p.exists():
                st.error(f"Path does not exist: {local_path}")
            else:
                res = pipeline.run_pipeline(
                    dir_path=p,
                    no_network=offline_mode,
                    pdf_path=pdf_out,
                    progress_callback=update_progress,
                )
                st.session_state.last_result = res
        elif input_mode == "ZIP Archive" and zip_file is not None:
            # Use only the basename: uploaded file names must not control paths.
            zip_path = tmpdir / Path(zip_file.name or "upload.zip").name
            zip_path.write_bytes(zip_file.getbuffer())
            res = pipeline.run_pipeline(
                zip_path=zip_path,
                no_network=offline_mode,
                pdf_path=pdf_out,
                progress_callback=update_progress,
            )
            st.session_state.last_result = res
        elif input_mode == "Public GitHub Repository" and github_url:
            res = pipeline.run_pipeline(
                github_url=github_url,
                no_network=offline_mode,
                pdf_path=pdf_out,
                progress_callback=update_progress,
            )
            st.session_state.last_result = res
        else:
            st.error("Please provide a valid scan target.")

        prog_holder.empty()
        if st.session_state.last_result:
            st.success(f"Scan #{st.session_state.last_result.scan_id} completed: {len(st.session_state.last_result.findings)} findings identified.")
    except Exception as exc:
        prog_holder.empty()
        st.error(f"Scan failed: {exc}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        st.session_state.last_tmpdir = None

result = st.session_state.last_result

# --- Main Workspace Header ---
st.markdown("## VibeSec: Security Assessment for AI-Generated Software")
st.caption("Deterministic multi-scanner static pipeline paired with empirical rule validation against labeled AI-generated samples.")

# Top Status & Coverage Banner
if result is not None:
    # 1. Coverage Banner
    cov = getattr(result, "coverage", None)
    if cov:
        status_color = "#3fb950" if cov.status == "COMPLETE" else "#d29922"
        files_count = sum(cov.languages.values()) if cov.languages else 0
        langs_str = ", ".join(f"{k}: {v}" for k, v in sorted(cov.languages.items())) if cov.languages else "none"
        fws_str = ", ".join(cov.frameworks) or "none"
        st.markdown(
            f"""
            <div style="border: 1px solid {status_color}; border-radius: 4px; padding: 10px 14px; margin-bottom: 12px; background: rgba(0,0,0,0.15);">
                <strong>Analysis Coverage: <span style="color: {status_color};">{cov.status}</span></strong> &mdash; 
                Parsed: {files_count} files ({langs_str}) | 
                Frameworks: {fws_str} | 
                Entry Points: {cov.entry_points_count} | 
                Taint Analysis: {cov.taint_analysis}
            </div>
            """,
            unsafe_allow_html=True,
        )
        if cov.status == "INCOMPLETE":
            st.warning(f"No findings from the analysis that completed; coverage INCOMPLETE: {cov.reason or 'Entry points or taint analysis incomplete.'}")

    # 2. Risk Posture Statement
    posture = getattr(result, "risk_posture", "")
    if not posture and getattr(result, "asm", None):
        if getattr(result.asm, "posture", None) and getattr(result.asm.posture, "risk_posture_statement", None):
            posture = result.asm.posture.risk_posture_statement
        elif getattr(result.asm, "risk_posture_statement", None):
            posture = result.asm.risk_posture_statement
    if not posture:
        from vibesec.prioritizer import calculate_risk_posture
        posture, _ = calculate_risk_posture(result.findings, asm=result.asm, coverage=result.coverage)
    if posture:
        st.info(f"**Risk Posture:** {posture}")

    # 3. Compact Tool Status Table
    if getattr(result, "tool_statuses", None):
        with st.expander("Toolchain Execution Status", expanded=False):
            ts_rows = []
            for ts in result.tool_statuses:
                st_val = ts.state.value if hasattr(ts.state, "value") else str(ts.state)
                ts_rows.append({
                    "Tool": ts.name,
                    "Version": ts.version or "-",
                    "Status": st_val,
                    "Reason": ts.reason,
                })
            st.dataframe(pd.DataFrame(ts_rows), hide_index=True)

st.divider()


def _render_history_section() -> None:
    st.markdown("#### Previous Scans in Local Storage (SQLite)")
    st.caption("Historical scan metadata and findings stored in `~/.vibesec/vibesec.db`.")
    past = storage.list_scans()
    if past:
        st.dataframe(pd.DataFrame(past), hide_index=True)
        col_h1, col_h2 = st.columns([3, 2])
        with col_h1:
            scan_to_load = st.selectbox("Select scan ID to inspect:", [s["id"] for s in past], key="load_scan_select")
            if st.button("Load Past Scan", key="btn_load_past_scan"):
                loaded = storage.load_scan(scan_to_load)
                if loaded:
                    loaded_findings = [Finding.from_dict(f) for f in loaded.get("findings", [])]
                    st.session_state.last_result = pipeline.ScanResult(
                        target_name=loaded.get("target_name", f"Scan #{scan_to_load}"),
                        profile=loaded.get("profile", {}),
                        findings=loaded_findings,
                        fix_actions=build_fix_actions(loaded_findings),
                        scan_id=loaded.get("id", scan_to_load),
                    )
                    st.rerun()
        with col_h2:
            st.write("")
            st.write("")
            if st.button("Clear Previous Scans", key="btn_init_clear_scans"):
                st.session_state["confirm_clear_history"] = True

        if st.session_state.get("confirm_clear_history", False):
            st.warning(
                f"**Confirm Deletion:** This will permanently delete all {len(past)} recorded scan(s) "
                f"and their associated findings from the local SQLite database (`~/.vibesec/vibesec.db`). "
                f"The scan result currently loaded in memory and any generated reports will NOT be deleted."
            )
            col_c1, col_c2, _ = st.columns([2, 2, 4])
            with col_c1:
                if st.button("Yes, Delete History", type="primary", key="btn_confirm_delete_history"):
                    try:
                        count = storage.clear_scans()
                        st.session_state["confirm_clear_history"] = False
                        st.success(f"Successfully deleted {count} scan record(s) from local storage.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to clear history: {exc}")
            with col_c2:
                if st.button("Cancel", key="btn_cancel_delete_history"):
                    st.session_state["confirm_clear_history"] = False
                    st.rerun()
    else:
        st.info("No previous scan history found in local storage (`~/.vibesec/vibesec.db`).")


# Production Tabs
tabs = st.tabs([
    "Scan",
    "Attack Surface & Paths",
    "Dependencies",
    "Reports",
])

# ==============================================================================
# TAB 1: SCAN
# ==============================================================================
with tabs[0]:
    if result is None:
        st.info("No active scan in session. Select a target in the sidebar to execute an assessment, or load a recorded scan below.")
        _render_history_section()
    else:
        # Severity metrics ledger
        buckets = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in result.findings:
            b = f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket or "INFO")
            buckets[b] = buckets.get(b, 0) + 1

        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Total Findings", len(result.findings))
        m2.metric("Critical", buckets["CRITICAL"])
        m3.metric("High", buckets["HIGH"])
        m4.metric("Medium", buckets["MEDIUM"])
        m5.metric("Low", buckets["LOW"])
        m6.metric("Info", buckets["INFO"])

        # Filters
        st.markdown("#### Findings Ledger")
        col_f1, col_f2, col_f3 = st.columns([2, 2, 4])
        with col_f1:
            sev_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        with col_f2:
            cat_filter = st.selectbox("Category", ["All", "code", "dependency", "secret", "config"])
        with col_f3:
            search_query = st.text_input("Search findings (rule, CWE, file)", "")

        filtered = result.findings
        if sev_filter != "All":
            filtered = [f for f in filtered if (f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)) == sev_filter]
        if cat_filter != "All":
            filtered = [f for f in filtered if f.category == cat_filter]
        if search_query:
            q = search_query.lower()
            filtered = [
                f for f in filtered
                if q in f.rule_id.lower() or q in f.cwe.lower() or q in f.title.lower() or (f.location and q in f.location.file.lower())
            ]

        st.caption(f"Showing {len(filtered)} of {len(result.findings)} finding(s)")

        if not filtered:
            if len(result.findings) == 0:
                cov = getattr(result, "coverage", None)
                if cov and cov.status == "COMPLETE":
                    st.success("No vulnerabilities detected across analyzed attack surface.")
                else:
                    st.info("No findings recorded for this analysis.")
            else:
                st.info("No findings match the current filter criteria.")
        else:
            from vibesec.prioritizer import is_actionable

            actionable_filtered = [f for f in filtered if is_actionable(f)]
            non_actionable_filtered = [f for f in filtered if not is_actionable(f)]

            for f in actionable_filtered:
                sev_val = f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)
                loc_str = f"{f.location.file}:{f.location.start_line}" if f.location else "global"
                header = f"[{sev_val}] {f.title} — {f.rule_id} ({loc_str})"

                with st.expander(header):
                    col_d1, col_d2, col_d3 = st.columns([3, 3, 2])
                    with col_d1:
                        st.markdown(f"**CWE:** {f.cwe}")
                        if f.owasp_categories:
                            st.markdown(f"**OWASP:** {', '.join(f.owasp_categories)}")
                        st.markdown(f"**Location:** `{loc_str}`")
                    with col_d2:
                        st.markdown(f"**Category:** `{f.category}`")
                        st.markdown(f"**Sources:** {', '.join(s.value if hasattr(s, 'value') else str(s) for s in f.sources)}")
                        if f.taint_reachable:
                            st.markdown("**Taint Reachable:** Yes (Flows from entrypoint to sink)")
                    with col_d3:
                        st.markdown(f"**Risk Score:** `{f.risk_score:.1f}`")
                        st.markdown(f"**Confidence:** `{f.confidence:.2f}`")

                    if f.evidence:
                        st.markdown("**Evidence Snippet:**")
                        st.code(f.evidence, language="text")

                    if f.remediation:
                        st.markdown(f"**Remediation:** {f.remediation}")

            if non_actionable_filtered:
                with st.expander(
                    f"Collapsed Non-Actionable Findings ({len(non_actionable_filtered)} items: test/fixture/script/INFO)",
                    expanded=(len(actionable_filtered) == 0),
                ):
                    st.caption("Non-actionable findings (test/fixture/script files or INFO severity) collapsed into a per-rule, per-folder summary.")
                    summary_groups = {}
                    for f in non_actionable_filtered:
                        f_folder = "/".join((f.location.file if f.location else "").replace("\\", "/").split("/")[:-1]) or "."
                        summary_groups.setdefault((f_folder, f.rule_id), []).append(f)
                    na_rows = []
                    for (f_folder, f_rule), g_list in sorted(summary_groups.items()):
                        reasons = set(f.exposure_class or ("INFO" if (f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)) == "INFO" else "NON_RUNTIME") for f in g_list)
                        na_rows.append({
                            "Folder": f_folder,
                            "Rule ID": f_rule,
                            "Count": len(g_list),
                            "Classification": ", ".join(sorted(reasons)),
                        })
                    st.dataframe(pd.DataFrame(na_rows), hide_index=True)
                    for f in non_actionable_filtered:
                        sev_val = f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)
                        loc_str = f"{f.location.file}:{f.location.start_line}" if f.location else "global"
                        st.caption(f"[{sev_val}] {f.title} — `{loc_str}` ({f.rule_id})")

        st.divider()
        with st.expander("Manage Stored Scan History (SQLite)", expanded=False):
            _render_history_section()


# ==============================================================================
# TAB 2: ATTACK SURFACE & PATHS
# ==============================================================================
with tabs[1]:
    if result is None:
        st.info("Execute or load a scan to inspect the Application Security Model and attack paths.")
    else:
        asm = getattr(result, "asm", None)
        if not asm:
            st.info("No application security model generated for this target.")
        else:
            st.markdown("#### Application Security Model (ASM)")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Routes", len(asm.entry_points))
            unauth_cnt = asm.posture.public_routes if getattr(asm, "posture", None) else len([e for e in asm.entry_points if e.auth_state == "PUBLIC"])
            c2.metric("Unauthenticated Routes", unauth_cnt)
            state_changing_cnt = asm.posture.public_state_changing_routes if getattr(asm, "posture", None) else len([e for e in asm.entry_points if e.method.upper() in ("POST", "PUT", "PATCH", "DELETE")])
            c3.metric("State-Changing Routes", state_changing_cnt)
            c4.metric("Attack Paths", len(asm.attack_paths))

            # Entrypoints Table
            if asm.entry_points:
                st.markdown("**Discovered Entrypoints & Auth State:**")
                ep_rows = []
                for ep in asm.entry_points:
                    param_names = [p.name if hasattr(p, "name") else (p.get("name") if isinstance(p, dict) else str(p)) for p in ep.parameters]
                    ep_rows.append({
                        "Method": ep.method,
                        "Path": ep.path,
                        "Auth State": ep.auth_state,
                        "Handler": f"{ep.handler} ({ep.file}:{ep.line})" if ep.handler else f"{ep.file}:{ep.line}",
                        "Parameters": ", ".join(param_names) or "-",
                    })
                st.dataframe(pd.DataFrame(ep_rows), hide_index=True)
            else:
                profile_obj = getattr(result, "profile", {}) or {}
                app_type_str = str(profile_obj.get("app_type", "library")).upper()
                st.info(f"No HTTP entry points discovered (Application type: {app_type_str}).")

            # Application Map Graph
            with st.expander("Application Map Graph", expanded=False):
                try:
                    dot_app = render_app_map_graphviz(asm)
                    st.graphviz_chart(dot_app)
                except Exception as e:
                    st.caption(f"Graph rendering unavailable: {e}")

            # Ranked Attack Paths
            st.markdown("#### Ranked Attack Paths")
            if not asm.attack_paths:
                st.info("No attack paths identified from entrypoints to critical sinks.")
            else:
                for idx, path in enumerate(asm.attack_paths, start=1):
                    p_header = f"Path {idx}: [{path.sink_class.upper()}] {path.method} {path.route} (Auth: {path.auth_state}, Score: {path.score:.1f})"
                    with st.expander(p_header, expanded=(idx <= 3)):
                        pc1, pc2 = st.columns([1, 1])
                        with pc1:
                            st.markdown(f"**Entrypoint:** `{path.method} {path.route}`")
                            st.markdown(f"**Authentication:** `{path.auth_state}`")
                            st.markdown(f"**Sink Class:** `{path.sink_class}`")
                            st.markdown(f"**Confidence:** `{path.confidence:.2f}`")
                            st.markdown(f"**Calculated Score:** `{path.score:.1f}`")

                        with pc2:
                            st.markdown("**Flow Steps:**")
                            for s_idx, s in enumerate(path.steps, start=1):
                                s_f = getattr(s, "file", "") if hasattr(s, "file") else (s.get("file", "") if isinstance(s, dict) else "")
                                s_l = getattr(s, "line", 1) if hasattr(s, "line") else (s.get("line", 1) if isinstance(s, dict) else 1)
                                s_c = getattr(s, "code", "") if hasattr(s, "code") else (s.get("code", "") if isinstance(s, dict) else "")
                                st.markdown(f"`{s_idx}.` `{s_f}:{s_l}`: {str(s_c)[:60]}")

                        if path.poc_curl:
                            st.markdown("**Verification Proof of Concept (PoC):**")
                            st.code(path.poc_curl, language="bash")

                        try:
                            dot_path = render_path_graphviz(path)
                            st.graphviz_chart(dot_path)
                        except Exception:
                            pass


# ==============================================================================
# TAB 3: DEPENDENCIES
# ==============================================================================
with tabs[2]:
    if result is None:
        st.info("Execute or load a scan to inspect dependency intelligence and supply chain status.")
    else:
        st.markdown("#### Dependency Intelligence & Supply Chain")

        # License Policy Summary
        lic_checked = getattr(result, "license_packages_checked", None) or (getattr(result, "metadata", {}) or {}).get("license_packages_checked")
        lic_findings = [f for f in result.findings if f.category == "license"]
        if not lic_checked:
            lic_checked = len(set(f.package_name for f in result.findings if f.package_name)) or (len(getattr(result, "sbom", {}).get("components", [])) if getattr(result, "sbom", None) else 0) or len(lic_findings)
        lic_violations = [f for f in lic_findings if (f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)) in ("CRITICAL", "HIGH")]
        lic_reviews = [f for f in lic_findings if f not in lic_violations]
        st.info(f"**License Policy:** {lic_checked} total packages checked, {len(lic_violations)} violations, {len(lic_reviews)} review items.")

        # Actionable Fix Plan
        if result.fix_actions:
            st.markdown("#### Ordered Dependency Fix Plan")
            st.caption("Grouped by package and version; prioritized by runtime exposure and reachability.")
            action_rows = []
            for act in result.fix_actions:
                action_rows.append({
                    "Package": act.package_name,
                    "Current": act.installed_version,
                    "Advised Fix": act.target_version,
                    "Scope": act.exposure_class,
                    "Reachability": act.reachability,
                    "Lockfile": act.manifest_file,
                    "Breaking Change Warning": "MAJOR BUMP: may be breaking" if act.is_major_bump else "No",
                })
            st.dataframe(pd.DataFrame(action_rows), hide_index=True)

        # Supply chain findings
        supply_findings = [f for f in result.findings if f.category == "dependency"]
        if supply_findings:
            st.markdown(f"#### Vulnerable Dependencies ({len(supply_findings)})")
            dep_rows = []
            for sf in supply_findings:
                dep_rows.append({
                    "Advisory": sf.rule_id,
                    "Package": sf.title,
                    "Severity": sf.risk_bucket.value if hasattr(sf.risk_bucket, "value") else str(sf.risk_bucket),
                    "Score": sf.risk_score,
                    "Location": f"{sf.location.file}:{sf.location.start_line}" if sf.location else "-",
                })
            st.dataframe(pd.DataFrame(dep_rows), hide_index=True)

        # CycloneDX SBOM Preview
        if getattr(result, "sbom", None) and "components" in result.sbom:
            with st.expander(f"CycloneDX SBOM Components ({len(result.sbom['components'])})", expanded=False):
                comp_rows = []
                for c in result.sbom["components"][:50]:
                    comp_rows.append({
                        "Name": c.get("name"),
                        "Version": c.get("version"),
                        "Scope": c.get("scope", "required"),
                        "PURL": c.get("purl", "-"),
                    })
                st.dataframe(pd.DataFrame(comp_rows), hide_index=True)


# ==============================================================================
# TAB 4: REPORTS
# ==============================================================================
with tabs[3]:
    if result is None:
        st.info("Execute or load a scan to generate and export audit reports.")
    else:
        st.markdown("#### Export Security Audit Reports")
        st.caption("Generate verifiable PDF, Markdown, SARIF, and CycloneDX SBOM reports.")

        rep_col1, rep_col2, rep_col3, rep_col4 = st.columns(4)

        with tempfile.TemporaryDirectory(prefix="vibesec-export-") as exp_tmp:
            exp_dir = Path(exp_tmp)
            asm_dict = result.asm.to_dict() if result.asm else None
            cov_dict = result.coverage.to_dict() if result.coverage else None
            meta = dict(getattr(result, "metadata", {}) or {})
            meta.update({
                "offline": result.offline,
                "warnings": result.warnings,
                "coverage": cov_dict,
                "tool_statuses": result.tool_statuses,
            })

            # 1. PDF
            pdf_bytes = b""
            try:
                pdf_path = exp_dir / "vibesec-security-report.pdf"
                build_report(
                    result.target_name,
                    result.profile,
                    result.findings,
                    pdf_path,
                    fix_actions=result.fix_actions,
                    metadata=meta,
                    asm=asm_dict,
                    offline=result.offline,
                )
                if pdf_path.exists():
                    pdf_bytes = pdf_path.read_bytes()
            except Exception as e:
                st.error(f"PDF generation error: {e}")

            with rep_col1:
                st.markdown("**PDF Executive Report**")
                if pdf_bytes:
                    st.download_button(
                        "Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"{result.target_name}-security-report.pdf",
                        mime="application/pdf",
                    )

            # 2. Markdown
            md_text = ""
            try:
                md_path = exp_dir / "vibesec-report.md"
                export_markdown(
                    result.findings,
                    result.profile,
                    result.target_name,
                    md_path,
                    fix_actions=result.fix_actions,
                    metadata=meta,
                    asm=asm_dict,
                    offline=result.offline,
                )
                if md_path.exists():
                    md_text = md_path.read_text(encoding="utf-8")
            except Exception as e:
                st.error(f"Markdown generation error: {e}")

            with rep_col2:
                st.markdown("**Markdown Technical Report**")
                if md_text:
                    st.download_button(
                        "Download Markdown Report",
                        data=md_text,
                        file_name=f"{result.target_name}-report.md",
                        mime="text/markdown",
                    )

            # 3. SARIF
            sarif_text = ""
            try:
                sarif_path = exp_dir / "vibesec.sarif"
                export_sarif(
                    result.findings,
                    sarif_path,
                    attack_paths=result.asm.attack_paths if result.asm else None,
                )
                if sarif_path.exists():
                    sarif_text = sarif_path.read_text(encoding="utf-8")
            except Exception as e:
                st.error(f"SARIF export error: {e}")

            with rep_col3:
                st.markdown("**OASIS SARIF 2.1.0**")
                if sarif_text:
                    st.download_button(
                        "Download SARIF",
                        data=sarif_text,
                        file_name=f"{result.target_name}.sarif",
                        mime="application/json",
                    )

            # 4. SBOM
            sbom_text = json.dumps(result.sbom, indent=2) if getattr(result, "sbom", None) else ""
            with rep_col4:
                st.markdown("**CycloneDX 1.5 JSON SBOM**")
                if sbom_text:
                    st.download_button(
                        "Download SBOM",
                        data=sbom_text,
                        file_name=f"{result.target_name}-cyclonedx.json",
                        mime="application/json",
                    )

        if md_text:
            st.divider()
            st.markdown("#### Technical Report Preview")
            with st.expander("View Rendered Markdown Report", expanded=False):
                st.markdown(md_text)



