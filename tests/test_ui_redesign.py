"""Tests for the professional UI redesign and feature cleanup in VibeSec.

Verifies:
1. Light theme configuration and styles.
2. Complete removal of scan history functionality from the UI.
3. Complete removal of toolchain status section from the UI.
4. Complete removal of offline mode functionality from the UI.
5. Presence and correct structure of the 4 production dashboard tabs.
6. Headless Streamlit AppTest execution.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from vibesec import pipeline
from vibesec.grouping import FixAction
from vibesec.models import (
    AnalysisCoverage,
    Finding,
    Location,
    Severity,
)


def test_theme_config_is_strictly_light():
    """Verify that .streamlit/config.toml enforces a clean light theme."""
    config_path = Path(__file__).resolve().parents[1] / ".streamlit" / "config.toml"
    assert config_path.exists(), "config.toml must exist"
    content = config_path.read_text(encoding="utf-8")
    assert 'base = "light"' in content
    assert 'backgroundColor = "#ffffff"' in content
    assert 'textColor = "#0f172a"' in content
    assert 'primaryColor = "#2563eb"' in content
    assert "maxUploadSize = 1024" in content


def test_input_instructions_ui_glitch_hidden():
    """Verify CSS hides 'Press Enter to apply' overlay that was clipping text input."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    content = app_path.read_text(encoding="utf-8")
    assert '[data-testid="InputInstructions"]' in content
    assert "display: none !important" in content


def test_upload_capacity_limits_1gb_and_50k_files():
    """Verify that upload limits are set to 1 GB and 50,000 files across config and extractor."""
    from vibesec.extractor import MAX_ARCHIVE_BYTES, MAX_ARCHIVE_MEMBERS

    assert MAX_ARCHIVE_BYTES == 1_073_741_824  # 1 GB
    assert MAX_ARCHIVE_MEMBERS == 50_000  # 50,000 file contents


def test_app_py_clean_code_and_zero_emojis():
    """Verify no emojis, no dark mode overrides, and proper styling in app.py."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    content = app_path.read_text(encoding="utf-8")

    # Zero emojis (Unicode emoji blocks)
    emoji_pattern = re.compile(
        "[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF\U00002702-\U000027B0\U000024C2-\U0001F251]"
    )
    assert not emoji_pattern.search(content), "app.py must contain zero emojis"

    # No dark mode media queries
    assert "@media (prefers-color-scheme: dark)" not in content, "Dark mode media query must be removed"

    # Light palette CSS variables present
    assert "--background: #F8FAFC" in content
    assert "--surface: #FFFFFF" in content
    assert "--text-primary: #0F172A" in content
    assert "--primary: #2563EB" in content


def test_scan_history_completely_removed_from_ui():
    """Verify that scan history UI, tables, and buttons are completely removed from app.py."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    content = app_path.read_text(encoding="utf-8")

    assert "_render_history_section" not in content
    assert "Manage Stored Scan History" not in content
    assert "Previous Scans in Local Storage" not in content
    assert "confirm_clear_history" not in content
    assert "btn_load_past_scan" not in content
    assert "storage.list_scans" not in content
    assert "storage.load_scan" not in content
    assert "from vibesec import pipeline, storage" not in content


def test_toolchain_status_completely_removed_from_ui():
    """Verify that Toolchain Status sections, expanders, and cards are removed from app.py."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    content = app_path.read_text(encoding="utf-8")

    # Sidebar toolchain status block
    assert "**Toolchain Status**" not in content
    assert "SAST: Semgrep (custom + audit)" not in content
    # Main dashboard expander
    assert 'with st.expander("Toolchain Execution Status"' not in content


def test_offline_mode_completely_removed_from_ui():
    """Verify that Offline Mode toggle and messages are removed from app.py."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    content = app_path.read_text(encoding="utf-8")

    assert "offline_mode = st.checkbox" not in content
    assert "Offline mode (--no-network)" not in content
    assert "no_network=offline_mode" not in content


def test_streamlit_apptest_initial_state():
    """Verify headless execution of app.py in initial empty state."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)
    at.run()
    assert not at.exception, f"AppTest raised exception: {at.exception}"

    # Verify header
    assert any("VibeSec: Security Assessment" in s.value for s in at.markdown)

    # Verify input options in sidebar
    target_radio = at.sidebar.radio[0]
    assert "ZIP Archive" in target_radio.options
    assert "Public GitHub Repository" in target_radio.options

    # Verify primary scan button
    scan_btn = at.sidebar.button[0]
    assert scan_btn.label == "Execute Security Scan"

    # Verify 4 tabs
    tabs = at.tabs
    assert len(tabs) == 4
    tab_labels = [t.label for t in tabs]
    assert tab_labels == ["Scan", "Attack Surface & Paths", "Dependencies", "Reports"]


def test_streamlit_apptest_with_simulated_scan_result():
    """Verify that all 4 tabs render correctly when a ScanResult is in session state."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)

    # Construct mock findings and scan result
    finding1 = Finding(
        rule_id="vibe.sql.injection",
        category="code",
        title="Unsanitized SQL Query",
        explanation="String formatting in raw query",
        severity=Severity.HIGH,
        risk_bucket=Severity.HIGH,
        confidence=0.9,
        risk_score=8.5,
        location=Location(file="app/db.py", start_line=42),
        cwe="CWE-89",
        owasp_categories=["A03:2021-Injection"],
        evidence="cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
        remediation="Use parameterized queries instead of string concatenation.",
        sources=["entrypoint"],
        taint_reachable=True,
    )
    finding2 = Finding(
        rule_id="vibe.test.secret",
        category="secret",
        title="Test Secret Token",
        explanation="Harmless token in test file",
        severity=Severity.INFO,
        risk_bucket=Severity.INFO,
        confidence=0.5,
        location=Location(file="tests/fixtures.py", start_line=10),
        evidence="token = 'test_token_secret'",
        cwe="CWE-798",
        exposure_class="NON_RUNTIME",
        risk_score=1.0,
    )

    mock_coverage = AnalysisCoverage(
        status="COMPLETE",
        languages={"python": 15},
        frameworks=["fastapi"],
        entry_points_count=3,
        taint_analysis="ACTIVE",
    )

    fix1 = FixAction(
        action_id="fix-1",
        ecosystem="pypi",
        package_name="requests",
        installed_version="2.25.0",
        target_version="2.31.0",
        exposure_class="RUNTIME_PRODUCTION",
        reachability="CALLED",
        manifest_file="requirements.txt",
    )

    mock_result = pipeline.ScanResult(
        target_name="test-org/test-repo",
        profile={"languages": {"python": 15}, "frameworks": ["fastapi"], "app_type": "server"},
        findings=[finding1, finding2],
        fix_actions=[fix1],
        coverage=mock_coverage,
        risk_posture="Moderate security posture: 1 high severity actionable finding requires remediation.",
        sbom={"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"name": "requests", "version": "2.25.0"}]},
    )

    at.session_state["last_result"] = mock_result
    at.run()
    assert not at.exception, f"AppTest with scan result raised exception: {at.exception}"

    # Verify coverage banner rendered
    assert any("Analysis Coverage" in m.value for m in at.markdown)
    assert any("COMPLETE" in m.value for m in at.markdown)

    # Verify risk posture rendered
    assert any("Risk Posture" in m.value for m in at.markdown)
    assert any("Moderate security posture" in m.value for m in at.markdown)

    # Verify metric cards: 6 metrics in Scan tab
    metrics = at.metric
    assert len(metrics) == 6
    metric_labels = [m.label for m in metrics]
    assert metric_labels == ["Total Findings", "Critical", "High", "Medium", "Low", "Info"]
    assert metrics[0].value == "2"  # Total Findings
    assert metrics[2].value == "1"  # High Findings
    assert metrics[5].value == "1"  # Info Findings

    # Verify download buttons in Reports tab (4 download buttons)
    dl_buttons = at.download_button
    assert len(dl_buttons) == 4
    dl_labels = [b.label for b in dl_buttons]
    assert dl_labels == ["Download PDF", "Download Markdown", "Download SARIF", "Download SBOM"]
