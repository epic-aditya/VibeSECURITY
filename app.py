"""VibeSec — Automated Security Assessment Platform for AI-Generated Applications.

Implements the full Upload -> Discover -> Scan -> Correlate -> Prioritize -> Report
pipeline with multi-scanner orchestration, attack-surface mapping, reachability analysis,
CycloneDX SBOM generation, and empirical evaluation benchmarks.

UI Design Standards:
- Exclusive light theme with pure white surfaces and subtle slate borders.
- Typography: Inter with JetBrains Mono for code, metrics, and locations.
- Exactly 4 primary dashboard sections: Scan, Attack Surface & Paths, Dependencies, Reports.
- Zero emojis and zero decorative icons across the application.
"""

from __future__ import annotations

import json
import os
import re
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

from vibesec import pipeline
from vibesec.exports import export_markdown
from vibesec.models import Finding
from vibesec.prioritizer import calculate_risk_posture, is_actionable
from vibesec.report import build_report
from vibesec.sarif import export_sarif


def render_path_graphviz(path: Any) -> str:
    lines = [
        'digraph AttackPath {',
        '  rankdir=LR;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="Inter, sans-serif", fontsize=10, margin="0.2,0.1", penwidth=1.0];',
        '  edge [fontname="Inter, sans-serif", fontsize=9, color="#94a3b8", penwidth=1.2];',
    ]
    method = getattr(path, "method", "")
    route = getattr(path, "route", "")
    ep_name = f"{method} {route}".strip() or getattr(path, "entry_point_id", "PUBLIC Entrypoint")
    ep_name = str(ep_name).replace('"', '\\"')
    auth = getattr(path, "auth_state", "PUBLIC")
    if auth == "PUBLIC":
        auth_fill = "#fef2f2"
        auth_stroke = "#fecaca"
        auth_text = "#991b1b"
    else:
        auth_fill = "#ecfdf5"
        auth_stroke = "#a7f3d0"
        auth_text = "#065f46"
    lines.append(f'  entry [label="{ep_name}\\n[{auth}]", fillcolor="{auth_fill}", color="{auth_stroke}", fontcolor="{auth_text}"];')
    prev = "entry"
    for idx, step in enumerate(getattr(path, "steps", [])):
        nid = f"step_{idx}"
        f_raw = getattr(step, "file", "") if hasattr(step, "file") else (step.get("file", "") if isinstance(step, dict) else "")
        f = f_raw.replace("\\", "/").split("/")[-1]
        line_no = getattr(step, "line", 1) if hasattr(step, "line") else (step.get("line", 1) if isinstance(step, dict) else 1)
        code_raw = getattr(step, "code", "") if hasattr(step, "code") else (step.get("code", "") if isinstance(step, dict) else "")
        code = str(code_raw)[:40].replace('"', '\\"').replace('\n', ' ')
        lines.append(f'  {nid} [label="{f}:{line_no}\\n{code}", fillcolor="#eff6ff", color="#bfdbfe", fontcolor="#1e40af"];')
        lines.append(f'  {prev} -> {nid};')
        prev = nid
    sc = getattr(path, "sink_class", "Sink").replace('"', '\\"')
    cwe = getattr(path, "cwe", "").replace('"', '\\"')
    lines.append(f'  sink [label="Sink: {sc}\\n{cwe}", fillcolor="#fee2e2", color="#fca5a5", fontcolor="#991b1b", shape=octagon];')
    lines.append(f'  {prev} -> sink;')
    lines.append('}')
    return "\n".join(lines)


def render_app_map_graphviz(asm: Any) -> str:
    lines = [
        'digraph ApplicationMap {',
        '  rankdir=TB;',
        '  bgcolor="transparent";',
        '  node [shape=box, style="rounded,filled", fontname="Inter, sans-serif", fontsize=10, margin="0.2,0.1", penwidth=1.0];',
        '  edge [fontname="Inter, sans-serif", fontsize=9, color="#94a3b8", penwidth=1.2];',
        '  subgraph cluster_routes {',
        '    label = "Entrypoints (Routes)"; style=dashed; color="#cbd5e1"; fontname="Inter, sans-serif";',
    ]
    eps = getattr(asm, "entry_points", [])
    if not eps:
        lines.append('    no_routes [label="No routes detected", fillcolor="#f8fafc", color="#e2e8f0", fontcolor="#475569"];')
    else:
        for idx, ep in enumerate(eps[:12]):
            auth = getattr(ep, "auth_state", "PUBLIC")
            if auth == "AUTHENTICATED":
                fill, stroke, text = "#ecfdf5", "#a7f3d0", "#065f46"
            elif auth == "PUBLIC":
                fill, stroke, text = "#fef2f2", "#fecaca", "#991b1b"
            else:
                fill, stroke, text = "#fffbeb", "#fde68a", "#92400e"
            lbl = f"{ep.method} {ep.path}\\n[{auth}]".replace('"', '\\"')
            lines.append(f'    route_{idx} [label="{lbl}", fillcolor="{fill}", color="{stroke}", fontcolor="{text}"];')
    lines.append('  }')
    if getattr(asm, "data_access_sites", []):
        lines.append('  subgraph cluster_db {')
        lines.append('    label = "Data Stores"; style=dashed; color="#cbd5e1"; fontname="Inter, sans-serif";')
        for idx, da in enumerate(asm.data_access_sites[:4]):
            f = da.file.split("/")[-1].split("\\")[-1]
            lbl = f"{da.kind}\\n{f}:{da.line}".replace('"', '\\"')
            lines.append(f'    db_{idx} [label="{lbl}", fillcolor="#fffbeb", color="#fde68a", fontcolor="#92400e", shape=cylinder];')
        lines.append('  }')
        if eps:
            lines.append('  route_0 -> db_0 [label="accesses", style=dashed];')
    if getattr(asm, "external_calls", []):
        lines.append('  subgraph cluster_ext {')
        lines.append('    label = "External Services & APIs"; style=dashed; color="#cbd5e1"; fontname="Inter, sans-serif";')
        for idx, ex in enumerate(asm.external_calls[:4]):
            f = ex.file.split("/")[-1].split("\\")[-1]
            lbl = f"{ex.kind}\\n{ex.target or f}".replace('"', '\\"')
            lines.append(f'    ext_{idx} [label="{lbl}", fillcolor="#e0e7ff", color="#c7d2fe", fontcolor="#3730a3"];')
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --background: #F8FAFC;
    --surface: #FFFFFF;
    --surface-secondary: #F1F5F9;
    --text-primary: #0F172A;
    --text-secondary: #475569;
    --text-muted: #64748B;
    --border: #E2E8F0;
    --border-subtle: #E2E8F0;
    --border-strong: #CBD5E1;
    --primary: #2563EB;
    --primary-hover: #1D4ED8;
    --success: #15803D;
    --warning: #B45309;
    --danger: #B91C1C;
    --info: #0369A1;
}

/* Force Light Theme Exclusively */
html, body, [data-testid="stAppViewContainer"], .stApp {
    background-color: #F8FAFC !important;
    color: #0F172A !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    -webkit-font-smoothing: antialiased;
}

/* Content Container Max Width and Spacing */
.main .block-container {
    max-width: 1280px !important;
    padding-top: 1.75rem !important;
    padding-bottom: 3rem !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #FFFFFF !important;
    border-right: 1px solid #E2E8F0 !important;
}

[data-testid="stSidebar"] .block-container {
    padding-top: 1.75rem !important;
    padding-bottom: 2rem !important;
}

[data-testid="stSidebar"] * {
    color: #0F172A;
}

[data-testid="stSidebar"] .stCaption,
[data-testid="stSidebar"] small {
    color: #64748B !important;
}

/* Typography */
h1, h2, h3, h4, h5, h6 {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    color: #0F172A !important;
    font-weight: 600 !important;
    letter-spacing: -0.02em !important;
}

p, span, label, div {
    color: #0F172A;
}

.stCaption, small {
    color: #64748B !important;
    font-size: 0.8125rem !important;
}

code, pre, .mono-data {
    font-family: 'JetBrains Mono', Consolas, Menlo, monospace !important;
    font-size: 0.8125rem !important;
}

/* Metric Cards */
div[data-testid="stMetric"] {
    background-color: #FFFFFF !important;
    border: 1px solid #E2E8F0 !important;
    border-radius: 6px !important;
    padding: 12px 16px !important;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03) !important;
}

div[data-testid="stMetricLabel"] {
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
    color: #64748B !important;
}

div[data-testid="stMetricValue"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 1.625rem !important;
    font-weight: 700 !important;
    color: #0F172A !important;
    margin-top: 4px !important;
}

/* Expanders */
div[data-testid="stExpander"] {
    background-color: #FFFFFF !important;
    border: 1px solid #E2E8F0 !important;
    border-radius: 6px !important;
    margin-bottom: 8px !important;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.02) !important;
}

div[data-testid="stExpander"] summary {
    font-weight: 600 !important;
    color: #0F172A !important;
    font-size: 0.875rem !important;
    padding: 10px 14px !important;
}

div[data-testid="stExpander"] summary:hover {
    color: #2563EB !important;
}

div[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
    padding: 12px 16px !important;
    border-top: 1px solid #F1F5F9 !important;
}

/* Tabs */
div[data-baseweb="tab-list"] {
    border-bottom: 1px solid #E2E8F0 !important;
    background-color: transparent !important;
    gap: 4px !important;
    padding-bottom: 0 !important;
    margin-bottom: 1.5rem !important;
}

button[data-baseweb="tab"] {
    font-family: 'Inter', sans-serif !important;
    font-size: 0.875rem !important;
    font-weight: 500 !important;
    color: #64748B !important;
    background-color: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    padding: 10px 16px !important;
    border-radius: 0 !important;
}

button[data-baseweb="tab"]:hover {
    color: #0F172A !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #2563EB !important;
    border-bottom: 2px solid #2563EB !important;
    font-weight: 600 !important;
}

/* Primary Action Buttons */
button[kind="primary"] {
    background-color: #2563EB !important;
    color: #FFFFFF !important;
    border: 1px solid #1D4ED8 !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.875rem !important;
    padding: 0.5rem 1rem !important;
    box-shadow: 0 1px 2px 0 rgba(37, 99, 235, 0.2) !important;
    transition: background-color 0.15s ease-in-out !important;
}

button[kind="primary"]:hover {
    background-color: #1D4ED8 !important;
    border-color: #1E40AF !important;
}

/* Secondary Buttons */
button[kind="secondary"] {
    background-color: #FFFFFF !important;
    color: #1E293B !important;
    border: 1px solid #CBD5E1 !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.875rem !important;
}

button[kind="secondary"]:hover {
    background-color: #F8FAFC !important;
    border-color: #94A3B8 !important;
}

/* Download Buttons */
[data-testid="stDownloadButton"] button {
    background-color: #FFFFFF !important;
    color: #1E293B !important;
    border: 1px solid #CBD5E1 !important;
    border-radius: 6px !important;
    font-weight: 500 !important;
    font-size: 0.8125rem !important;
    padding: 8px 12px !important;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03) !important;
}

[data-testid="stDownloadButton"] button:hover {
    background-color: #F8FAFC !important;
    border-color: #2563EB !important;
    color: #2563EB !important;
}

/* Section Dividers */
hr {
    margin: 1.5rem 0 !important;
    border-color: #E2E8F0 !important;
}

/* Data Tables */
div[data-testid="stDataFrame"] {
    border: 1px solid #E2E8F0 !important;
    border-radius: 6px !important;
    background-color: #FFFFFF !important;
}

/* Form Inputs */
div[data-baseweb="input"],
div[data-baseweb="select"] {
    border-color: #CBD5E1 !important;
    border-radius: 6px !important;
    background-color: #FFFFFF !important;
}

div[data-baseweb="input"] input {
    color: #0F172A !important;
    background-color: #FFFFFF !important;
    font-size: 0.875rem !important;
}

/* Eliminate 'Press Enter to apply' overlay completely */
[data-testid="InputInstructions"],
div[class*="InputInstructions"],
.stInputInstructions {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    width: 0 !important;
    overflow: hidden !important;
    opacity: 0 !important;
    pointer-events: none !important;
}

/* Hide Streamlit Community Cloud hosting chrome */
[data-testid="stToolbar"],
div[class*="_profileContainer_"],
a[class*="_viewerBadge_"] {
    display: none !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_tmpdir" not in st.session_state:
    st.session_state.last_tmpdir = None

# --- Sidebar Navigation & Input ---
with st.sidebar:
    st.markdown("### VibeSec")
    st.caption("Application Security Assessment for AI-Generated Software")
    st.divider()

    allow_local = os.environ.get("VIBESEC_ALLOW_LOCAL_PATH", "").strip() in ("1", "true", "yes", "on")
    target_options = ["ZIP Archive", "Public GitHub Repository"]
    if allow_local:
        target_options.append("Local Directory (Self-Hosted)")

    input_mode = st.radio(
        "Target Source",
        target_options,
        index=0,
        label_visibility="collapsed",
    )
    local_path = None
    zip_file = None
    github_url = None

    if input_mode == "ZIP Archive":
        zip_file = st.file_uploader(
            "Upload application archive (.zip)",
            type=["zip"],
            key="zip_uploader",
            help="Zip archive containing source code (max 1 GB compressed, up to 50,000 files)",
        )
    elif input_mode == "Public GitHub Repository":
        github_url = st.text_input(
            "GitHub repository URL",
            placeholder="https://github.com/org/repo",
            help="Public GitHub repository URL (shallow cloned or downloaded as ZIP archive)",
        )
    elif allow_local and input_mode == "Local Directory (Self-Hosted)":
        local_path = st.text_input(
            "Local Directory Path",
            value="",
            placeholder="/path/to/project",
            help="Self-hosted local directory path to scan",
        )

    st.write("")
    run_scan_btn = st.button("Execute Security Scan", type="primary")

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
        if input_mode == "ZIP Archive":
            if zip_file is None:
                prog_holder.empty()
                st.error("Please upload a ZIP archive containing project source code before scanning.")
                st.stop()
            zip_path = tmpdir / Path(zip_file.name or "upload.zip").name
            zip_file.seek(0)
            with open(zip_path, "wb") as f_out:
                while True:
                    chunk = zip_file.read(8 * 1024 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)
            res = pipeline.run_pipeline(
                zip_path=zip_path,
                pdf_path=pdf_out,
                progress_callback=update_progress,
            )
            st.session_state.last_result = res
        elif input_mode == "Public GitHub Repository":
            if not github_url or not github_url.strip():
                prog_holder.empty()
                st.error("Please enter a valid public GitHub repository URL (e.g. https://github.com/owner/repo).")
                st.stop()
            res = pipeline.run_pipeline(
                github_url=github_url.strip(),
                pdf_path=pdf_out,
                progress_callback=update_progress,
            )
            st.session_state.last_result = res
        elif allow_local and input_mode == "Local Directory (Self-Hosted)":
            if not local_path or not local_path.strip():
                prog_holder.empty()
                st.error("Please provide a directory path to scan.")
                st.stop()
            p = Path(local_path.strip()).resolve()
            if not p.is_dir():
                prog_holder.empty()
                st.error("Specified directory does not exist or is not accessible.")
                st.stop()
            res = pipeline.run_pipeline(
                dir_path=p,
                pdf_path=pdf_out,
                progress_callback=update_progress,
            )
            st.session_state.last_result = res
        else:
            prog_holder.empty()
            st.error("Please provide a valid scan target.")
            st.stop()

        prog_holder.empty()
        if st.session_state.last_result:
            st.success(
                f"Scan completed: {len(st.session_state.last_result.findings)} findings identified across analyzed attack surface."
            )
    except Exception as exc:
        prog_holder.empty()
        st.error(f"Scan failed: {exc}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        st.session_state.last_tmpdir = None

result = st.session_state.last_result

# --- Main Workspace Header ---
st.markdown("## VibeSec: Security Assessment for AI-Generated Software")
st.caption("Deterministic multi-scanner static pipeline paired with empirical rule validation.")

# Top Status & Coverage Banner
if result is not None:
    # 1. Coverage Banner
    cov = getattr(result, "coverage", None)
    if cov:
        is_complete = cov.status == "COMPLETE"
        badge_bg = "#ECFDF5" if is_complete else "#FEF3C7"
        badge_color = "#15803D" if is_complete else "#B45309"
        badge_border = "#A7F3D0" if is_complete else "#FCD34D"
        files_count = sum(cov.languages.values()) if cov.languages else 0
        langs_str = ", ".join(f"{k}: {v}" for k, v in sorted(cov.languages.items())) if cov.languages else "none"
        fws_str = ", ".join(cov.frameworks) or "none"
        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 12px 16px; margin-bottom: 12px; font-size: 0.875rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <span style="background: {badge_bg}; color: {badge_color}; border: 1px solid {badge_border}; font-size: 0.75rem; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.05em; margin-right: 8px;">{cov.status}</span>
                        <strong style="color: #0F172A;">Analysis Coverage</strong>
                    </div>
                    <div style="color: #475569; font-size: 0.8125rem;">
                        <span>Parsed: <strong>{files_count}</strong> files ({langs_str})</span> &bull;
                        <span>Frameworks: <strong>{fws_str}</strong></span> &bull;
                        <span>Entry Points: <strong>{cov.entry_points_count}</strong></span> &bull;
                        <span>Taint Analysis: <strong>{cov.taint_analysis}</strong></span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if cov.status == "INCOMPLETE":
            st.warning(f"Analysis coverage is INCOMPLETE: {cov.reason or 'Entry points or taint analysis incomplete.'}")

    # 2. Risk Posture Statement
    posture = getattr(result, "risk_posture", "")
    if not posture and getattr(result, "asm", None):
        if getattr(result.asm, "posture", None) and getattr(result.asm.posture, "risk_posture_statement", None):
            posture = result.asm.posture.risk_posture_statement
        elif getattr(result.asm, "risk_posture_statement", None):
            posture = result.asm.risk_posture_statement
    if not posture:
        posture, _ = calculate_risk_posture(result.findings, asm=result.asm, coverage=result.coverage)
    if posture:
        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 4px solid #2563EB; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px;">
                <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #2563EB; margin-bottom: 4px;">Risk Posture</div>
                <div style="color: #0F172A; font-size: 0.9375rem; line-height: 1.5;">{posture}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

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
        with st.container(border=True):
            st.markdown("#### Application Security Assessment")
            st.markdown(
                "Select a target source in the sidebar to execute an automated security scan.\n\n"
                "- **ZIP Archive:** Upload a compressed project archive (.zip) up to 1 GB (up to 50,000 files).\n"
                "- **Public GitHub Repository:** Enter a repository URL to perform an automated clone and inspection.\n\n"
                "The analysis correlates static code analysis (SAST), software composition analysis (SCA), "
                "hardcoded secrets detection, and attack surface reachability without executing target code."
            )
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
            cat_filter = st.selectbox("Category", ["All", "code", "dependency", "secret", "config", "license"])
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
                        st.markdown("**Evidence Snippet**")
                        st.code(f.evidence, language="text")

                    if f.remediation:
                        st.markdown("**Remediation**")
                        st.markdown(
                            f"""
                            <div style="background: #F1F5F9; border-left: 3px solid #2563EB; padding: 10px 14px; border-radius: 4px; font-size: 0.875rem; color: #1E293B;">
                                {f.remediation}
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

            if non_actionable_filtered:
                with st.expander(
                    f"Collapsed Non-Actionable Findings ({len(non_actionable_filtered)} items: test/fixture/script/INFO)",
                    expanded=(len(actionable_filtered) == 0),
                ):
                    st.caption("Non-actionable findings (test/fixture/script files or INFO severity) collapsed into a per-rule, per-folder summary.")
                    summary_groups: dict[tuple[str, str], list[Finding]] = {}
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


# ==============================================================================
# TAB 2: ATTACK SURFACE & PATHS
# ==============================================================================
with tabs[1]:
    if result is None:
        st.info("Execute a security scan from the sidebar to inspect the Application Security Model and attack paths.")
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
                            st.markdown("**Verification Proof of Concept (PoC)**")
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
        st.info("Execute a security scan from the sidebar to inspect dependency intelligence and supply chain status.")
    else:
        st.markdown("#### Dependency Intelligence & Supply Chain")

        # License Policy Summary
        lic_checked = getattr(result, "license_packages_checked", None) or (getattr(result, "metadata", {}) or {}).get("license_packages_checked")
        lic_findings = [f for f in result.findings if f.category == "license"]
        if not lic_checked:
            lic_checked = len(set(f.package_name for f in result.findings if f.package_name)) or (len(getattr(result, "sbom", {}).get("components", [])) if getattr(result, "sbom", None) else 0) or len(lic_findings)
        lic_violations = [f for f in lic_findings if (f.risk_bucket.value if hasattr(f.risk_bucket, "value") else str(f.risk_bucket)) in ("CRITICAL", "HIGH")]
        lic_reviews = [f for f in lic_findings if f not in lic_violations]

        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; font-size: 0.875rem;">
                <strong style="color: #0F172A;">License Policy Evaluation:</strong> 
                <span style="color: #475569;">Checked <strong>{lic_checked}</strong> total packages &bull; 
                <strong style="color: #B91C1C;">{len(lic_violations)}</strong> violations &bull; 
                <strong style="color: #B45309;">{len(lic_reviews)}</strong> review items.</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

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
        st.info("Execute a security scan from the sidebar to generate and export audit reports.")
    else:
        st.markdown("#### Export Security Audit Reports")
        st.caption("Download verifiable audit reports in industry-standard formats for the current scan.")

        rep_col1, rep_col2, rep_col3, rep_col4 = st.columns(4)

        with tempfile.TemporaryDirectory(prefix="vibesec-export-") as exp_tmp:
            exp_dir = Path(exp_tmp)
            safe_target = re.sub(
                r"[^a-zA-Z0-9_\-\.]",
                "_",
                (result.target_name or "scan").replace("https://github.com/", "").replace("/", "_"),
            ).strip("_") or "scan"
            asm_dict = result.asm.to_dict() if result.asm else None
            cov_dict = result.coverage.to_dict() if result.coverage else None
            meta = dict(getattr(result, "metadata", {}) or {})
            meta.update({
                "offline": False,
                "warnings": result.warnings,
                "coverage": cov_dict,
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
                    offline=False,
                )
                if pdf_path.exists():
                    pdf_bytes = pdf_path.read_bytes()
            except Exception as e:
                st.error(f"PDF generation error: {e}")

            with rep_col1:
                with st.container(border=True):
                    st.markdown("**PDF Executive Report**")
                    st.caption("Executive summary with risk posture, compliance breakdown, and findings.")
                    if pdf_bytes:
                        st.download_button(
                            "Download PDF",
                            data=pdf_bytes,
                            file_name=f"{safe_target}-security-report.pdf",
                            mime="application/pdf",
                            key="dl_pdf_btn",
                        )
                    else:
                        st.caption("Not available")

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
                    offline=False,
                )
                if md_path.exists():
                    md_text = md_path.read_text(encoding="utf-8")
            except Exception as e:
                st.error(f"Markdown generation error: {e}")

            with rep_col2:
                with st.container(border=True):
                    st.markdown("**Markdown Technical Report**")
                    st.caption("Developer-focused technical report formatted in GitHub-flavored Markdown.")
                    if md_text:
                        st.download_button(
                            "Download Markdown",
                            data=md_text,
                            file_name=f"{safe_target}-report.md",
                            mime="text/markdown",
                            key="dl_md_btn",
                        )
                    else:
                        st.caption("Not available")

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
                with st.container(border=True):
                    st.markdown("**OASIS SARIF 2.1.0**")
                    st.caption("Static Analysis Results Interchange Format for IDE and CI/CD security tooling.")
                    if sarif_text:
                        st.download_button(
                            "Download SARIF",
                            data=sarif_text,
                            file_name=f"{safe_target}.sarif",
                            mime="application/json",
                            key="dl_sarif_btn",
                        )
                    else:
                        st.caption("Not available")

            # 4. SBOM
            sbom_text = json.dumps(result.sbom, indent=2) if getattr(result, "sbom", None) else ""
            with rep_col4:
                with st.container(border=True):
                    st.markdown("**CycloneDX 1.5 JSON SBOM**")
                    st.caption("Complete Software Bill of Materials formatted in CycloneDX 1.5 JSON specification.")
                    if sbom_text:
                        st.download_button(
                            "Download SBOM",
                            data=sbom_text,
                            file_name=f"{safe_target}-cyclonedx.json",
                            mime="application/json",
                            key="dl_sbom_btn",
                        )
                    else:
                        st.caption("Not available")

        if md_text:
            st.divider()
            st.markdown("#### Technical Report Preview")
            with st.expander("View Rendered Markdown Report", expanded=False):
                st.markdown(md_text)
