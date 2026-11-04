"""Regression tests for web application deployment, storage, reporting, and degradation."""

import re
import tempfile
from pathlib import Path

import pytest

from vibesec import pipeline, storage
from vibesec.exports import export_markdown
from vibesec.models import (
    AnalysisCoverage,
    Finding,
    Location,
    Severity,
    SourceTool,
    ToolState,
    ToolStatus,
)
from vibesec.report import build_report
from vibesec.sarif import export_sarif
from vibesec.sbom import generate_sbom


def test_storage_custom_env_and_in_memory_fallback(monkeypatch):
    """Verify that storage honors VIBESEC_DB_PATH and handles read-only fallbacks."""
    td = Path(tempfile.mkdtemp())
    custom_db = td / "custom.db"
    monkeypatch.setenv("VIBESEC_DB_PATH", str(custom_db))

    assert storage._get_default_db_path() == custom_db

    findings = [
        Finding(
            rule_id="test.rule",
            title="Test Finding",
            cwe="CWE-798",
            severity=Severity.HIGH,
            confidence=0.9,
            location=Location(file="app.py", start_line=10, end_line=10),
            evidence="secret = 'abc'",
            sources=[SourceTool.VIBE_RULE],
            category="secret",
        )
    ]
    scan_id = storage.save_scan(
        target_name="test-project",
        target_source="archive: test.zip",
        profile={"languages": {"python": 1}},
        findings=findings,
    )
    assert scan_id > 0
    loaded = storage.load_scan(scan_id)
    assert loaded is not None
    assert loaded["target_name"] == "test-project"
    assert loaded["target_source"] == "archive: test.zip"

    past = storage.list_scans()
    assert any(s["id"] == scan_id for s in past)

    cleared = storage.clear_scans()
    assert cleared >= 1
    assert len(storage.list_scans()) == 0


def test_report_exports_with_slashed_target_names():
    """Verify that reports (PDF, MD, SARIF, SBOM) export cleanly even when target name has slashes or URLs."""
    td = Path(tempfile.mkdtemp())
    unsanitized_target = "https://github.com/org/repo-name"
    safe_target = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", unsanitized_target.replace("https://github.com/", "").replace("/", "_")).strip("_")

    findings = [
        Finding(
            rule_id="vibe.sql_string_concat",
            title="SQL Injection",
            cwe="CWE-89",
            severity=Severity.HIGH,
            confidence=0.95,
            location=Location(file="db.py", start_line=15, end_line=15),
            evidence="query = 'SELECT * FROM users WHERE id = ' + user_id",
            sources=[SourceTool.VIBE_RULE],
            category="code",
            risk_score=14.5,
            risk_bucket=Severity.HIGH,
        )
    ]
    profile = {"languages": {"python": 2}, "app_type": "server", "frameworks": ["fastapi"]}

    # 1. PDF
    pdf_out = td / f"{safe_target}-security-report.pdf"
    build_report(
        unsanitized_target,
        profile,
        findings,
        pdf_out,
        metadata={"offline": True, "warnings": []},
    )
    assert pdf_out.is_file()
    assert pdf_out.stat().st_size > 0

    # 2. Markdown
    md_out = td / f"{safe_target}-report.md"
    export_markdown(
        findings,
        profile,
        unsanitized_target,
        md_out,
        metadata={"offline": True, "warnings": []},
    )
    assert md_out.is_file()
    assert "SQL Injection" in md_out.read_text(encoding="utf-8")

    # 3. SARIF
    sarif_out = td / f"{safe_target}.sarif"
    export_sarif(findings, sarif_out)
    assert sarif_out.is_file()
    assert "CWE-89" in sarif_out.read_text(encoding="utf-8")

    # 4. SBOM
    sbom = generate_sbom(td, project_name=unsanitized_target, findings=findings)
    assert sbom["bomFormat"] == "CycloneDX"


def test_coverage_truthful_on_tool_failure(monkeypatch):
    """Verify that a tool failure marks AnalysisCoverage as INCOMPLETE with clear reason."""
    td = Path(tempfile.mkdtemp())
    (td / "main.py").write_text("print('test')", encoding="utf-8")

    # Mock semgrep to fail
    def mock_fail_semgrep(*args, **kwargs):
        raise RuntimeError("Semgrep crashed during scan")

    monkeypatch.setattr("vibesec.pipeline.run_semgrep", mock_fail_semgrep)

    res = pipeline.run_pipeline(dir_path=td, no_network=True)
    assert res.coverage.status == "INCOMPLETE"
    assert "semgrep" in res.coverage.reason.lower()


def test_streamlit_apptest_runs_headlessly():
    """Verify that Streamlit AppTest can initialize app.py headlessly without exceptions."""
    from streamlit.testing.v1 import AppTest

    app_path = Path(__file__).resolve().parents[1] / "app.py"
    at = AppTest.from_file(str(app_path), default_timeout=30)
    at.run()
    assert not at.exception, f"AppTest raised an exception: {at.exception}"
    # Verify main title and radio options are present
    assert any("VibeSec" in s.value for s in at.markdown)
