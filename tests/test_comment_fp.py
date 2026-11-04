"""Regression tests for comment and non-executable false positive elimination."""

import tempfile
from pathlib import Path

from vibesec import pipeline
from vibesec.config_exposure import analyze_config_and_frontend_exposure
from vibesec.normalizer import is_comment_or_docstring_only, normalize_all


def test_comment_false_positive_prompt_example():
    """Verify that comments mentioning credentials and safe env lookups do not trigger findings."""
    td = Path(tempfile.mkdtemp())
    safe_code = """# hardcoded credentials
username = "admin"
password = os.getenv("ADMIN_PASSWORD")
"""
    (td / "auth.py").write_text(safe_code, encoding="utf-8")

    # 1. Direct AST syntax validator
    assert is_comment_or_docstring_only(td, "auth.py", 1, 1, rule_id="vibe.hardcoded_credentials", category="secret")
    assert is_comment_or_docstring_only(td, "auth.py", 2, 2, rule_id="vibe.hardcoded_credentials", category="secret")
    assert is_comment_or_docstring_only(td, "auth.py", 3, 3, rule_id="vibe.hardcoded_credentials", category="secret")

    # 2. Config exposure analysis produces 0 findings
    cfg_findings = analyze_config_and_frontend_exposure(td)
    assert len(cfg_findings) == 0

    # 3. Full pipeline run produces 0 secret/credential findings
    res = pipeline.run_pipeline(dir_path=td, no_network=True)
    secret_findings = [f for f in res.findings if f.category == "secret" or "credential" in f.rule_id.lower()]
    assert len(secret_findings) == 0


def test_genuine_secret_detected():
    """Verify that genuine hardcoded credentials ARE detected."""
    td = Path(tempfile.mkdtemp())
    vulnerable_code = """# Configuration
password = "supersecretpassword123"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
"""
    (td / "config.py").write_text(vulnerable_code, encoding="utf-8")

    # Direct AST syntax validator must NOT flag genuine executable assignments as comment-only
    assert not is_comment_or_docstring_only(td, "config.py", 2, 2, rule_id="vibe.hardcoded_credentials", category="secret")
    assert not is_comment_or_docstring_only(td, "config.py", 3, 3, rule_id="vibe.hardcoded_credentials", category="secret")

    # Normalized findings from Semgrep / Gitleaks / Vibe rules
    res = pipeline.run_pipeline(dir_path=td, no_network=True)
    secret_findings = [f for f in res.findings if f.category == "secret" or "credential" in f.rule_id.lower() or "secret" in f.rule_id.lower()]
    assert len(secret_findings) > 0


def test_multiline_docstring_example_not_flagged():
    """Verify that example secrets inside documentation docstrings are not flagged."""
    td = Path(tempfile.mkdtemp())
    doc_code = '''"""
Example API client usage:
    api_key = "sk-1234567890abcdef1234567890abcdef"
    client = Client(api_key=api_key)
"""

def get_client():
    return None
'''
    (td / "client.py").write_text(doc_code, encoding="utf-8")

    # Docstring line 3 is non-executable
    assert is_comment_or_docstring_only(td, "client.py", 3, 3, rule_id="vibe.hardcoded_credentials", category="secret")

    res = pipeline.run_pipeline(dir_path=td, no_network=True)
    secret_findings = [f for f in res.findings if f.category == "secret"]
    assert len(secret_findings) == 0


def test_commented_command_injection_not_flagged():
    """Verify that commented-out insecure commands do not trigger findings."""
    td = Path(tempfile.mkdtemp())
    code = """import subprocess

# Insecure legacy approach:
# os.system("rm -rf " + user_input)

# Safe implementation:
def cleanup(user_input):
    subprocess.run(["rm", "-rf", user_input])
"""
    (td / "runner.py").write_text(code, encoding="utf-8")

    # Comment line 4 is non-executable
    assert is_comment_or_docstring_only(td, "runner.py", 4, 4, rule_id="vibe.command_injection_shell_true", category="code")

    res = pipeline.run_pipeline(dir_path=td, no_network=True)
    cmd_findings = [f for f in res.findings if "command_injection" in f.rule_id.lower()]
    assert len(cmd_findings) == 0


def test_config_exposure_comments_ignored():
    """Verify that commented-out configuration risks are not reported."""
    td = Path(tempfile.mkdtemp())
    code = """# Database connection:
# mongodb://admin:secretpassword@localhost:27017/prod
# app.run(debug=True)
# set_cookie(httponly=False)

def run():
    pass
"""
    (td / "settings.py").write_text(code, encoding="utf-8")

    findings = analyze_config_and_frontend_exposure(td)
    assert len(findings) == 0


def test_javascript_comments_ignored():
    """Verify that JavaScript comments do not trigger secret findings."""
    td = Path(tempfile.mkdtemp())
    code = """// const API_KEY = "sk-1234567890abcdef1234567890abcdef";
/*
 * const SECRET_KEY = "mysecretkey";
 */
const API_KEY = process.env.API_KEY;
"""
    (td / "index.js").write_text(code, encoding="utf-8")

    assert is_comment_or_docstring_only(td, "index.js", 1, 1, rule_id="vibe.hardcoded_credentials", category="secret")
    assert is_comment_or_docstring_only(td, "index.js", 3, 3, rule_id="vibe.hardcoded_credentials", category="secret")

