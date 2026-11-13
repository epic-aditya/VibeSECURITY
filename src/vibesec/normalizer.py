"""Stage 4 — Finding Normalizer.

Converts each scanner's raw JSON into the common Finding schema:
file, line, rule/CWE, severity, confidence, source tool (plan Section 3).

Handles: Gitleaks, Semgrep, Trivy (vuln + misconfig + secret + license),
pip-audit, npm audit, and Bandit.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from .models import Finding, Location, Severity, SourceTool

# CWE fallbacks per tool family when metadata does not carry one.
_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_BANDIT_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_BANDIT_CONFIDENCE = {
    "HIGH": 0.9,
    "MEDIUM": 0.7,
    "LOW": 0.5,
}

_NPM_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_FILE_LINES_CACHE: dict[str, list[str]] = {}

_PLACEHOLDER_EVIDENCE = {
    "requires login", "require login", "requires authentication", "authenticated route",
    "public route", "none", "n/a", "na", "unknown", "requires auth", "requires authorization",
}


def _code_context(root: Path, rel_file: str, start: int, end: int | None = None, radius: int = 1) -> str:
    """Return the real source excerpt (3 lines of context) for a finding."""
    if not rel_file:
        return ""
    # Try resolving candidate paths robustly
    candidates = [
        (root / rel_file).resolve(),
        Path(rel_file).resolve(),
        (root / Path(rel_file).name).resolve(),
    ]
    path: Path | None = None
    for cand in candidates:
        if cand.is_file():
            path = cand
            break

    if not path or not path.is_file():
        # Search inside root for matching filename
        f_name = Path(rel_file).name
        for p in root.rglob(f_name):
            if p.is_file():
                path = p.resolve()
                break

    if not path or not path.is_file():
        return ""

    key = str(path).lower()
    if key not in _FILE_LINES_CACHE:
        try:
            _FILE_LINES_CACHE[key] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            _FILE_LINES_CACHE[key] = []
    lines = _FILE_LINES_CACHE[key]
    if not lines:
        return ""
    end = end or start
    lo = max(0, start - 1 - radius)
    hi = min(len(lines), end + radius)
    return "\n".join(f"{i + 1}| {lines[i]}" for i in range(lo, hi))


def _clean_evidence(raw: str | None, root: Path, rel_file: str, start: int, end: int | None = None) -> str:
    """Evidence must be a verifiable code excerpt, never placeholder prose or leaked auth context."""
    snippet = _code_context(root, rel_file, start, end)
    if snippet:
        return snippet[:800]
    text = (raw or "").strip()
    if any(p in text.lower() for p in _PLACEHOLDER_EVIDENCE) or len(text) < 4:
        return "No readable source excerpt (generated or minified file)."
    return text[:400]


def _rel(path: str, root: Path) -> str:
    if not path:
        return ""
    p_str = str(path).replace("\\", "/").strip()
    root_str = str(root.resolve()).replace("\\", "/").rstrip("/")
    if p_str.lower().startswith(root_str.lower() + "/"):
        return p_str[len(root_str) + 1:].lstrip("/")

    p = Path(path)
    try:
        if not p.is_absolute():
            return p_str.lstrip("./")
    except Exception:
        pass

    try:
        resolved = str(p.resolve()).replace("\\", "/")
        if resolved.lower().startswith(root_str.lower() + "/"):
            return resolved[len(root_str) + 1:].lstrip("/")
    except Exception:
        pass

    root_name = root.name.lower()
    idx = p_str.lower().find(f"/{root_name}/")
    if idx != -1:
        return p_str[idx + len(root_name) + 2:].lstrip("/")

    return p_str.lstrip("./")


_PARSED_AST_CACHE: dict[str, tuple[set[int], dict[int, list[tuple[list[str], ast.AST]]], list[str]]] = {}


def _resolve_source_path(root: Path, rel_file: str) -> Path | None:
    if not rel_file:
        return None
    candidates = [
        (root / rel_file).resolve(),
        Path(rel_file).resolve(),
        (root / Path(rel_file).name).resolve(),
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    f_name = Path(rel_file).name
    for p in root.rglob(f_name):
        if p.is_file():
            return p.resolve()
    return None


_FILTERED_FINDINGS_LEDGER: list[dict[str, Any]] = []


def get_filtered_findings_ledger() -> list[dict[str, Any]]:
    """Return an immutable copy of findings removed by normalizer filters."""
    return list(_FILTERED_FINDINGS_LEDGER)


def clear_filtered_findings_ledger() -> None:
    """Reset the normalizer filtered findings ledger."""
    _FILTERED_FINDINGS_LEDGER.clear()


def _record_filtered_finding(
    rule_id: str,
    rel_file: str,
    line: int,
    category: str,
    reason: str,
    evidence: str = "",
) -> None:
    """Record an audit entry for a finding removed by normalizer filters."""
    _FILTERED_FINDINGS_LEDGER.append({
        "rule_id": rule_id,
        "file": rel_file,
        "line": line,
        "category": category,
        "reason": reason,
        "evidence": evidence[:120].strip(),
    })


def is_javascript_comment_line(line: str, in_multiline: bool) -> tuple[bool, bool]:
    """Parse a single line of JS/TS to determine if it contains only comments or whitespace.

    String-aware: distinguishes '//' inside strings/URLs (e.g., 'postgres://user:pass@host')
    from real comments. Handles quotes, template literals, and escape characters.
    Returns: (is_comment_only, in_multiline_at_end)
    """
    i = 0
    n = len(line)
    has_code = False
    in_single = False
    in_double = False
    in_template = False

    while i < n:
        ch = line[i]
        nxt = line[i + 1] if i + 1 < n else ""

        if in_multiline:
            if ch == "*" and nxt == "/":
                in_multiline = False
                i += 2
                continue
            i += 1
            continue

        if in_single:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_single = False
            has_code = True
            i += 1
            continue

        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            has_code = True
            i += 1
            continue

        if in_template:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "`":
                in_template = False
            has_code = True
            i += 1
            continue

        # Outside strings and block comments
        if ch == "/" and nxt == "/":
            break
        elif ch == "/" and nxt == "*":
            in_multiline = True
            i += 2
            continue
        elif ch == "'":
            in_single = True
            has_code = True
            i += 1
            continue
        elif ch == '"':
            in_double = True
            has_code = True
            i += 1
            continue
        elif ch == "`":
            in_template = True
            has_code = True
            i += 1
            continue
        elif not ch.isspace():
            has_code = True
            i += 1
            continue

        i += 1

    return not has_code, in_multiline


def is_comment_or_docstring_only(
    root: Path,
    rel_file: str,
    start: int,
    end: int | None = None,
    rule_id: str = "",
    category: str = "",
    evidence: str = "",
) -> bool:
    """Determine if a finding's location in source code is purely non-executable comment/docstring,
    or if a secret/credential rule matched non-credential code (such as a username assignment
    or an environment-variable lookup).

    CRITICAL SECURITY INVARIANT:
    Secret findings (category='secret' or credential rules) are NEVER dropped because they
    appear inside comments or docstrings. A leaked secret in a comment is still leaked.
    Comment/docstring suppression applies strictly to code-sink rules (sqli, command injection, etc.).
    """
    if not rel_file:
        return False
    path = _resolve_source_path(root, rel_file)
    if not path or not path.is_file():
        return False

    end_line = end or start
    suffix = path.suffix.lower()

    is_secret_rule = (
        category == "secret"
        or rule_id.startswith("gitleaks.")
        or rule_id.startswith("trivy.secret.")
        or "credential" in rule_id.lower()
        or "secret" in rule_id.lower()
        or "password" in rule_id.lower()
        or "key" in rule_id.lower()
    )

    # Python syntax & AST-aware validation
    if suffix == ".py":
        cache_key = str(path).lower()
        if cache_key not in _PARSED_AST_CACHE:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content, filename=str(path))
                exec_lines: set[int] = set()
                assignments: dict[int, list[tuple[list[str], ast.AST]]] = {}

                for node in ast.walk(tree):
                    if isinstance(node, ast.stmt):
                        if (
                            isinstance(node, ast.Expr)
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)
                        ):
                            continue
                        n_start = getattr(node, "lineno", 0)
                        n_end = getattr(node, "end_lineno", n_start)
                        for ln in range(n_start, n_end + 1):
                            exec_lines.add(ln)

                        if isinstance(node, ast.Assign):
                            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                            assignments.setdefault(node.lineno, []).append((names, node.value))
                        elif isinstance(node, ast.AnnAssign):
                            if isinstance(node.target, ast.Name) and node.value is not None:
                                assignments.setdefault(node.lineno, []).append(([node.target.id], node.value))
                _PARSED_AST_CACHE[cache_key] = (exec_lines, assignments, content.splitlines())
            except Exception:
                _PARSED_AST_CACHE[cache_key] = (set(), {}, [])

        exec_lines, assignments, lines_list = _PARSED_AST_CACHE[cache_key]
        target_lines = set(range(start, end_line + 1))

        # If target lines contain no executable statements (comments or docstrings)
        if target_lines.isdisjoint(exec_lines):
            if is_secret_rule:
                # Check if the comment/docstring lines actually contain a real credential pattern
                # If it's just prose comments (e.g. '# hardcoded credentials', '# TODO: add secret here'):
                # then it is benign comment prose and should be suppressed!
                # BUT if it contains a real credential (AKIA..., ghp_..., eyJ..., or key = '...'):
                # then it must NEVER be suppressed!
                comment_text = "\n".join(lines_list[ln - 1] for ln in target_lines if 1 <= ln <= len(lines_list))
                if any(pat.search(comment_text) for pat in _KNOWN_GENUINE_SECRET_PATTERNS):
                    return False  # Real leaked credential in comment -> DO NOT SUPPRESS!
                return not bool(
                    re.search(
                        r"""(?:key|secret|token|password|auth)\s*[:=]\s*["'][^"'\s]{8,}["']""",
                        comment_text,
                        re.IGNORECASE,
                    )
                )
            return True

        # Secret rules with executable code: check if matching benign non-credential variable or environment lookup
        if is_secret_rule:
            non_sensitive_names = {
                "username", "user", "user_name", "login", "host", "hostname",
                "port", "email", "database", "db", "dbname", "name", "author",
                "sender", "recipient", "account", "account_id", "domain",
            }
            all_safe = True
            found_any_assignment = False
            for ln in target_lines:
                line_assigns = assignments.get(ln, [])
                for names, val_node in line_assigns:
                    found_any_assignment = True
                    if names and all(n.lower() in non_sensitive_names for n in names):
                        continue
                    if isinstance(val_node, ast.Call):
                        call_func = getattr(val_node.func, "attr", "") or getattr(val_node.func, "id", "")
                        if call_func in ("getenv", "get", "environ", "Secret", "fetch", "get_secret"):
                            # Evaluate fallback literal: os.getenv("KEY", "default-value")
                            has_secret_fallback = False
                            if len(val_node.args) >= 2:
                                default_node = val_node.args[1]
                                if isinstance(default_node, ast.Constant) and isinstance(default_node.value, str):
                                    fb_val = default_node.value.strip()
                                    if fb_val and not _is_placeholder_secret(rel_file, fb_val):
                                        benign_literals = {
                                            "development", "dev", "test", "testing", "localhost", "127.0.0.1",
                                            "production", "prod", "none", "true", "false", "default",
                                            "utf-8", "0", "1", "8000", "3000", "5432", "27017", "info", "debug",
                                        }
                                        if fb_val.lower() not in benign_literals and len(fb_val) >= 6:
                                            has_secret_fallback = True
                            if not has_secret_fallback:
                                continue
                            all_safe = False
                            break
                    if isinstance(val_node, ast.Subscript):
                        sub_id = getattr(val_node.value, "id", "") or getattr(val_node.value, "attr", "")
                        if sub_id in ("environ", "env"):
                            continue
                    all_safe = False
                    break
            return bool(found_any_assignment and all_safe)

    # JavaScript / TypeScript validation
    elif suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            lines = []

        if lines:
            line_slice = lines[max(0, start - 1) : end_line]
            line_text = "\n".join(line_slice)

            # Check secret rules in JS/TS
            if is_secret_rule:
                # If target lines are comments, check if they contain real credentials
                all_comment = True
                in_b = False
                for lno in range(1, len(lines) + 1):
                    raw_line = lines[lno - 1]
                    is_c, in_b = is_javascript_comment_line(raw_line, in_b)
                    if lno in range(start, end_line + 1):
                        if not is_c:
                            all_comment = False
                            break
                if all_comment:
                    if any(pat.search(line_text) for pat in _KNOWN_GENUINE_SECRET_PATTERNS):
                        return False  # Real leaked credential in JS comment -> DO NOT SUPPRESS
                    return not bool(
                        re.search(
                            r"""(?:key|secret|token|password|auth)\s*[:=]\s*["'][^"'\s]{8,}["']""",
                            line_text,
                            re.IGNORECASE,
                        )
                    )

                if "process.env" in line_text or "import.meta.env" in line_text:
                    fb_match = re.search(
                        r"""(?:process\.env|import\.meta\.env)\.[A-Za-z0-9_]+\s*(?:\|\||\?\?)\s*["']([^"']+)["']""",
                        line_text,
                    )
                    if fb_match:
                        fb_val = fb_match.group(1).strip()
                        if fb_val and not _is_placeholder_secret(rel_file, fb_val):
                            benign_literals = {"development", "dev", "test", "localhost", "127.0.0.1", "prod", "production", "default"}
                            return not (fb_val.lower() not in benign_literals and len(fb_val) >= 6)
                        return True
                    elif not any(k in line_text for k in ("AKIA", "ghp_", "eyJ", "postgres://", "mongodb://", "redis://")):
                        return True
                return False

            # Non-secret code rules: run string-aware comment parser
            all_comment = True
            in_block = False
            for lno in range(1, len(lines) + 1):
                raw_line = lines[lno - 1]
                is_comment, in_block = is_javascript_comment_line(raw_line, in_block)
                if lno in range(start, end_line + 1):
                    if not is_comment:
                        all_comment = False
                        break
            if all_comment:
                return True

    # Fallback check on evidence string for non-secret rules only
    if not is_secret_rule and evidence:
        ev_lines = [ln.strip() for ln in evidence.strip().splitlines() if ln.strip()]
        if ev_lines and all(ln.startswith(("#", "//", "/*", "*", "*/", '"""', "'''")) for ln in ev_lines):
            return True

    return False


def find_manifest_line(target_path: str, pkg_name: str, root: Path) -> int:
    """Find the 1-indexed line number of a package in its manifest or lockfile."""
    if not pkg_name or pkg_name == "unknown-package":
        return 1
    p = Path(target_path)
    p = (root / p).resolve() if not p.is_absolute() else p.resolve()

    p_str = str(p)
    if p_str not in _FILE_LINES_CACHE:
        try:
            if p.exists() and p.is_file():
                _FILE_LINES_CACHE[p_str] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            else:
                _FILE_LINES_CACHE[p_str] = []
        except Exception:
            _FILE_LINES_CACHE[p_str] = []

    lines = _FILE_LINES_CACHE[p_str]
    if not lines:
        return 1

    fname = p.name.lower()
    escaped = re.escape(pkg_name)
    if "package-lock.json" in fname or "package.json" in fname:
        # Match "node_modules/<pkg>": or "<pkg>":
        pattern = re.compile(rf'["\'](?:node_modules/)?{escaped}["\']\s*:')
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                return idx
    elif "requirements" in fname or fname.endswith(".txt"):
        pattern = re.compile(rf'^\s*{escaped}(?:[=<>~!\s]|$)', re.IGNORECASE)
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                return idx
    elif "pyproject.toml" in fname or "poetry.lock" in fname or "yarn.lock" in fname:
        pattern = re.compile(rf'(?:["\']{escaped}["\']|^\s*{escaped}\s*=)', re.IGNORECASE)
        for idx, line in enumerate(lines, start=1):
            if pattern.search(line):
                return idx

    # Fallback substring search
    pattern_sub = re.compile(rf'["\']?{escaped}["\']?', re.IGNORECASE)
    for idx, line in enumerate(lines, start=1):
        if pattern_sub.search(line):
            return idx
    return 1


def _infer_ecosystem(target: str) -> str:
    t = target.lower().replace("\\", "/")
    if "package.json" in t or "package-lock.json" in t or "yarn.lock" in t:
        return "npm"
    if "requirements" in t or "pyproject.toml" in t or "poetry.lock" in t or "setup.py" in t:
        return "pypi"
    if "cargo" in t:
        return "cargo"
    if "go.mod" in t or "go.sum" in t:
        return "gomod"
    return "npm" if ("node" in t or "js" in t) else "pypi"


def _cwe_from_metadata(metadata: dict, fallback: str = "CWE-0") -> str:
    cwe = metadata.get("cwe") or metadata.get("cwe-id")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
        return cwe.upper()
    return fallback


_KNOWN_GENUINE_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    re.compile(r"github_pat_[0-9a-zA-Z_]{82}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[^\s]+"),
]

_EXPLICIT_PLACEHOLDER_WORDS = {
    "changeme", "change_me", "your_api_key_here", "your-api-key-here",
    "your_key_here", "your-key-here", "your_secret_here", "your-secret-here",
    "insert_key_here", "placeholder", "dummy", "xxxx", "xxxxx", "xxxxxx",
    "<token>", "<api_key>", "<secret>", "<password>",
}

_PLACEHOLDER_SECRET_RE = re.compile(
    r"(?:my_gemini_api_key|your[_-]?key[_-]?here|changeme|<token>|<.*?>|your[_-]?secret|placeholder|dummy|example|xxx+|foo|bar)",
    re.IGNORECASE,
)


def _is_placeholder_secret(file_rel: str, match_text: str) -> bool:
    """True if match_text is demonstrably a placeholder/example credential, NEVER a real secret."""
    if not match_text:
        return True

    clean_match = match_text.strip().strip("'\"`")

    # Genuine credential patterns must NEVER be suppressed, even in example files
    for pat in _KNOWN_GENUINE_SECRET_PATTERNS:
        if pat.search(clean_match):
            return False

    clean_lower = clean_match.lower()

    # Extract value part if assignment or yaml mapping: e.g. "API_KEY = your_key_here" or "pass: changeme"
    val_part = clean_lower
    if "=" in clean_lower:
        val_part = clean_lower.split("=", 1)[1].strip().strip("'\"`")
    elif ":" in clean_lower:
        val_part = clean_lower.split(":", 1)[1].strip().strip("'\"`")

    if val_part in _EXPLICIT_PLACEHOLDER_WORDS or clean_lower in _EXPLICIT_PLACEHOLDER_WORDS:
        return True
    if any(pw in val_part for pw in ("changeme", "your_api_key_here", "your-api-key-here", "your_key_here", "insert_key_here")):
        return True
    if all(c in "xX*#-" for c in val_part) and len(val_part) >= 3:
        return True

    # In template/example files, broader placeholder patterns apply
    f_lower = file_rel.lower()
    if any(k in f_lower for k in (".example", ".sample", ".template", "example.")):
        if _PLACEHOLDER_SECRET_RE.search(clean_match) or _PLACEHOLDER_SECRET_RE.search(val_part):
            return True

    return False


def normalize_gitleaks(raw: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw.get("results", []):
        file_path = item.get("File") or item.get("file") or ""
        rel_f = _rel(file_path, root)
        start = int(item.get("StartLine") or item.get("StartLine".lower()) or 1)
        end = int(item.get("EndLine") or start)
        rule = item.get("RuleID") or item.get("Rule") or "gitleaks.secret"
        match = (item.get("Match") or item.get("Secret") or "")[:200]

        # Only suppress explicit placeholders. Secrets in comments or docstrings are NEVER dropped!
        if _is_placeholder_secret(rel_f, match):
            _record_filtered_finding(
                rule_id=f"gitleaks.{rule}",
                rel_file=rel_f,
                line=start,
                category="secret",
                reason="Placeholder/example credential pattern",
                evidence=match,
            )
            continue

        findings.append(
            Finding(
                rule_id=f"gitleaks.{rule}",
                title=item.get("Description") or f"Potential secret detected ({rule})",
                cwe="CWE-798",
                severity=Severity.HIGH,
                confidence=0.9,
                location=Location(file=rel_f, start_line=start, end_line=end),
                evidence=match,
                sources=[SourceTool.GITLEAKS],
                sensitive_asset="credentials",
                category="secret",
            )
        )
    return findings


def normalize_semgrep(raw: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for item in raw.get("results", []):
        check_id = item.get("check_id", "semgrep.unknown")
        if "vibe." in check_id:
            check_id = "vibe." + check_id.split("vibe.", 1)[1]
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        is_vibe = check_id.startswith("vibe.")
        severity = _map_semgrep_severity(extra.get("severity", "WARNING"), metadata, is_vibe)
        start = int((item.get("start") or {}).get("line", 1))
        end = int((item.get("end") or {}).get("line", start))
        cwe = _cwe_from_metadata(metadata, fallback="CWE-0")
        raw_conf = metadata.get("confidence")
        if isinstance(raw_conf, (int, float)):
            confidence = float(raw_conf)
        elif isinstance(raw_conf, str):
            cu = raw_conf.strip().upper()
            if cu == "HIGH":
                confidence = 0.9
            elif cu in ("MEDIUM", "MODERATE"):
                confidence = 0.7
            elif cu == "LOW":
                confidence = 0.5
            else:
                try:
                    confidence = float(raw_conf)
                except ValueError:
                    confidence = 0.7 if is_vibe else 0.6
        else:
            confidence = 0.7 if is_vibe else 0.6

        cat = metadata.get("category")
        if cat in {"code", "secret", "dependency", "license", "supply_chain", "config"}:
            category = cat
        elif check_id.startswith("gitleaks.") or "secret" in check_id or "credential" in check_id or "password" in check_id or cwe == "CWE-798":
            category = "secret"
        elif "config" in check_id or "cors" in check_id or "csrf" in check_id or "debug" in check_id:
            category = "config"
        elif "supply_chain" in check_id or "squat" in check_id:
            category = "supply_chain"
        else:
            category = "code"

        # Rule 8: vibe.llm_output_to_sql must originate from an LLM call result
        if check_id == "vibe.llm_output_to_sql":
            lines_text = extra.get("lines", "") or ""
            if not any(k in lines_text for k in ("choices", "completions", "chat", "message.content", "resp", "llm")):
                check_id = "vibe.python.sqli"
                cwe = "CWE-89"

        # Rule 9: missing_auth_state_change should not flag auth-bootstrap routes
        if check_id in ("vibe.missing_auth_state_change", "vibe.missing_auth_state_change_js"):
            lines_text = (extra.get("lines", "") or "").lower()
            if any(k in lines_text for k in ("login", "register", "signup", "token", "refresh", "reset", "health", "webhook")):
                continue

        # Rule 10: detect-child-process / command_injection_shell_true:
        # not a finding when shell:false (or execFile) and args are an array, unless tainted
        if "detect-child-process" in check_id or "command_injection_shell_true" in check_id:
            rel_file = _rel(item.get("path", ""), root)
            file_abs = (root / rel_file) if not Path(rel_file).is_absolute() else Path(rel_file)
            lines_text = extra.get("lines", "") or ""
            lines_lower = lines_text.lower()
            is_tainted = bool(extra.get("metadata", {}).get("taint", False)) or ("taint" in extra.get("message", "").lower())

            is_exec_file = "execfile" in lines_lower
            has_shell_false = "shell: false" in lines_lower or "shell:false" in lines_lower
            has_array_args = bool(re.search(r""",\s*\[[^\]]*\]""", lines_text)) or bool(re.search(r"""execFile\s*\([^,]+,\s*\[""", lines_text)) or ("[" in lines_text and "]" in lines_text)

            if file_abs.is_file():
                try:
                    fcontent = file_abs.read_text(encoding="utf-8", errors="ignore")
                    if re.search(r"""promisify\s*\(\s*(?:child_process\.)?execFile\s*\)""", fcontent):
                        is_exec_file = True
                    if re.search(r"""(?:const|let|var)\s+exec\s*=\s*(?:child_process\.)?execFile\b""", fcontent):
                        is_exec_file = True
                except Exception:
                    pass

            if not is_tainted:
                if is_exec_file:
                    continue
                if has_shell_false and has_array_args:
                    continue
                if ("shell: true" not in lines_lower and "shell:true" not in lines_lower) and has_array_args and ("exec(" not in lines_lower and "execsync(" not in lines_lower):
                    continue

        # Rule 11: llm_prompt_injection_concat requires LLM SDK import in file or string flowing to LLM call
        if "llm_prompt_injection_concat" in check_id:
            rel_file = _rel(item.get("path", ""), root)
            file_abs = (root / rel_file) if not Path(rel_file).is_absolute() else Path(rel_file)
            lines_text = extra.get("lines", "") or ""
            if file_abs.is_file():
                try:
                    fcontent = file_abs.read_text(encoding="utf-8", errors="ignore").lower()
                    has_llm_sdk = any(
                        sdk in fcontent for sdk in (
                            "openai", "anthropic", "langchain", "google.generativeai",
                            "groq", "litellm", "cohere", "transformers", "llama_index", "bedrock"
                        )
                    )
                    has_llm_call = any(
                        c in fcontent for c in (
                            "chat.completions", "completions.create", "generate_content",
                            "messages.create", "client.chat", "model.generate"
                        )
                    )
                    if not has_llm_sdk and not has_llm_call:
                        continue
                except Exception:
                    pass

        rel_path = _rel(item.get("path", ""), root)
        if is_comment_or_docstring_only(
            root, rel_path, start, end, rule_id=check_id, category=category, evidence=extra.get("lines", "")
        ):
            _record_filtered_finding(
                rule_id=check_id,
                rel_file=rel_path,
                line=start,
                category=category,
                reason="Non-executable comment, docstring, or benign variable assignment",
                evidence=extra.get("lines", "")[:120],
            )
            continue
        findings.append(
            Finding(
                rule_id=check_id,
                title=extra.get("message", check_id).split("\n")[0][:160],
                cwe=cwe,
                severity=severity,
                confidence=max(0.0, min(1.0, confidence)),
                location=Location(file=rel_path, start_line=start, end_line=end),
                evidence=_clean_evidence(extra.get("lines"), root, rel_path, start, end),
                sources=[SourceTool.VIBE_RULE if is_vibe else SourceTool.SEMGREP],
                taint_reachable=bool(metadata.get("taint", False)),
                auth_context=metadata.get("auth_context"),
                sensitive_asset=metadata.get("sensitive_asset"),
                category=category,
            )
        )
    return findings


def _map_semgrep_severity(raw: str, metadata: dict, is_vibe: bool) -> Severity:
    if is_vibe and metadata.get("severity") in {s.value for s in Severity}:
        return Severity(metadata["severity"])
    return _SEMGREP_SEVERITY.get(raw.upper(), Severity.MEDIUM)


def normalize_trivy(raw: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in raw.get("Results", []) or []:
        target = result.get("Target", "")
        ecosystem = _infer_ecosystem(target)

        # Vulnerabilities (dependency CVEs)
        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg = vuln.get("PkgName", "unknown-package")
            version = vuln.get("InstalledVersion", "?")
            severity = _TRIVY_SEVERITY.get((vuln.get("Severity") or "UNKNOWN").upper(), Severity.INFO)
            fixed = vuln.get("FixedVersion")
            fix_note = f" (fixed in {fixed})" if fixed else ""
            line = find_manifest_line(target, pkg, root)

            aliases = [vuln_id]
            for ref in vuln.get("References", []) or []:
                cve_match = re.search(r"(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", ref, re.IGNORECASE)
                if cve_match and cve_match.group(1).upper() not in aliases:
                    aliases.append(cve_match.group(1).upper())

            finding = Finding(
                rule_id=f"trivy.{vuln_id}",
                title=f"{vuln_id} in {pkg}: {vuln.get('Title') or vuln.get('Description', '')[:80]}",
                cwe="CWE-1395",
                severity=severity,
                confidence=0.95,
                location=Location(file=_rel(target, root), start_line=line, end_line=line),
                evidence=f"{pkg} {version}{fix_note}",
                sources=[SourceTool.TRIVY],
                sensitive_asset="dependency",
                category="dependency",
                package_name=pkg,
                package_version=version,
                ecosystem=ecosystem,
                aliases=aliases,
                affected_instances=[f"{pkg}@{version}"] if version != "?" else [],
            )
            nvd = vuln.get("CweIDs") or []
            if nvd:
                finding.cwe = nvd[0].upper()
            if fixed:
                finding.fix_snippet = f"Upgrade {pkg} to version {fixed}"
            findings.append(finding)

        # Misconfigurations (Dockerfile, IaC, etc.)
        for misconfig in result.get("Misconfigurations", []) or []:
            mc_id = misconfig.get("ID", "UNKNOWN")
            severity = _TRIVY_SEVERITY.get(
                (misconfig.get("Severity") or "UNKNOWN").upper(), Severity.INFO
            )
            title = misconfig.get("Title", mc_id)[:160]
            # Cap Trivy misconfiguration severity consistently with vibe rules
            if "root" in title.lower() or "user" in title.lower():
                severity = Severity.MEDIUM
            elif "secret" in title.lower() or "key" in title.lower() or severity == Severity.CRITICAL and ("dockerfile" in str(target).lower() or mc_id.startswith("DS")):
                severity = Severity.HIGH

            mc_rel = _rel(target, root)
            mc_line = int(misconfig.get("StartLine") or misconfig.get("start_line") or 1)
            findings.append(
                Finding(
                    rule_id=f"trivy.misconfig.{mc_id}",
                    title=title,
                    cwe="CWE-16",
                    severity=severity,
                    confidence=0.85,
                    location=Location(file=mc_rel, start_line=mc_line, end_line=mc_line),
                    evidence=_clean_evidence(misconfig.get("Message", ""), root, mc_rel, mc_line),
                    sources=[SourceTool.TRIVY],
                    remediation=misconfig.get("Resolution", None),
                    category="config",
                )
            )

        # Secrets detected by Trivy
        for secret in result.get("Secrets", []) or []:
            sec_match = (secret.get("Match", "") or "")[:200]
            sec_rel = _rel(target, root)
            if _is_placeholder_secret(sec_rel, sec_match):
                _record_filtered_finding(
                    rule_id=f"trivy.secret.{secret.get('RuleID', 'unknown')}",
                    rel_file=sec_rel,
                    line=secret.get("StartLine", 1),
                    category="secret",
                    reason="Placeholder/example credential pattern",
                    evidence=sec_match,
                )
                continue
            findings.append(
                Finding(
                    rule_id=f"trivy.secret.{secret.get('RuleID', 'unknown')}",
                    title=secret.get("Title", "Secret detected by Trivy")[:160],
                    cwe="CWE-798",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    location=Location(
                        file=sec_rel,
                        start_line=secret.get("StartLine", 1),
                        end_line=secret.get("EndLine", secret.get("StartLine", 1)),
                    ),
                    evidence=sec_match,
                    sources=[SourceTool.TRIVY],
                    sensitive_asset="credentials",
                    category="secret",
                )
            )

        # Licenses - evaluated against license_policy.yaml
        from .license_eval import evaluate_license
        for lic in result.get("Licenses", []) or []:
            lic_name = lic.get("Name", "unknown")
            pkg_name = lic.get("PkgName", "")
            status, lic_sev, notes = evaluate_license(lic_name)
            if status == "ACCEPTABLE":
                continue
            line = find_manifest_line(target, pkg_name, root) if pkg_name else 1
            findings.append(
                Finding(
                    rule_id=f"trivy.license.{lic_name}",
                    title=f"License {status.lower()}: {lic_name} ({pkg_name})",
                    cwe="",  # No CWE-0 for license findings
                    severity=lic_sev,
                    confidence=0.8,
                    location=Location(file=_rel(target, root), start_line=line, end_line=line),
                    evidence=f"Package: {pkg_name} License: {lic_name} - {notes}",
                    sources=[SourceTool.TRIVY],
                    category="license",
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                )
            )

    return findings


def normalize_pip_audit(raw: dict, root: Path) -> list[Finding]:
    """Normalize pip-audit output into Findings."""
    findings: list[Finding] = []
    if raw.get("_skipped"):
        return findings

    for dep in raw.get("dependencies", []):
        pkg_name = dep.get("name", "unknown")
        pkg_version = dep.get("version", "?")
        line = find_manifest_line("requirements.txt", pkg_name, root)
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            fixed = vuln.get("fix_versions", [])
            fix_str = f" (fixed in {', '.join(fixed)})" if fixed else ""
            aliases = [vuln_id]
            for a in vuln.get("aliases", []):
                if a not in aliases:
                    aliases.append(a)

            findings.append(
                Finding(
                    rule_id=f"pip-audit.{vuln_id}",
                    title=f"{vuln_id} in {pkg_name}: {vuln.get('description', '')[:80]}",
                    cwe="CWE-1395",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    location=Location(file="requirements.txt", start_line=line, end_line=line),
                    evidence=f"{pkg_name}=={pkg_version}{fix_str}",
                    sources=[SourceTool.PIP_AUDIT],
                    sensitive_asset="dependency",
                    category="dependency",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    ecosystem="pypi",
                    aliases=aliases,
                    affected_instances=[f"{pkg_name}@{pkg_version}"] if pkg_version != "?" else [],
                    fix_snippet=f"Upgrade {pkg_name} to {', '.join(fixed)}" if fixed else None,
                )
            )
    return findings


def normalize_npm_audit(raw: dict, root: Path) -> list[Finding]:
    """Normalize npm audit output into Findings."""
    findings: list[Finding] = []
    if raw.get("_skipped"):
        return findings

    vulns = raw.get("vulnerabilities", {})
    if isinstance(vulns, dict):
        for pkg_name, info in vulns.items():
            severity = _NPM_SEVERITY.get(
                (info.get("severity") or "moderate").lower(), Severity.MEDIUM
            )
            via = info.get("via", [])
            title_parts = []
            aliases = []
            for v in via[:5]:
                if isinstance(v, dict):
                    title_parts.append(v.get("title", v.get("url", "")))
                    cve = v.get("cve") or v.get("name")
                    if cve:
                        aliases.append(str(cve).upper())
                    url = v.get("url", "")
                    ghsa = re.search(r"(GHSA-[a-z0-9-]+|CVE-\d{4}-\d+)", url, re.IGNORECASE)
                    if ghsa:
                        aliases.append(ghsa.group(1).upper())
                elif isinstance(v, str):
                    title_parts.append(v)
                    if v.upper().startswith("GHSA-") or v.upper().startswith("CVE-"):
                        aliases.append(v.upper())

            title_str = "; ".join(str(p) for p in title_parts if p)[:120] or f"Vulnerability in {pkg_name}"
            fix_avail = info.get("fixAvailable")
            line = find_manifest_line("package.json", pkg_name, root)
            installed_ver = info.get("version", "") or info.get("range", "?")

            findings.append(
                Finding(
                    rule_id=f"npm-audit.{pkg_name}",
                    title=f"{pkg_name}: {title_str}",
                    cwe="CWE-1395",
                    severity=severity,
                    confidence=0.9,
                    location=Location(file="package.json", start_line=line, end_line=line),
                    evidence=f"{pkg_name} {info.get('range', '?')}",
                    sources=[SourceTool.NPM_AUDIT],
                    sensitive_asset="dependency",
                    category="dependency",
                    package_name=pkg_name,
                    package_version=installed_ver,
                    ecosystem="npm",
                    aliases=list(set(aliases)),
                    affected_instances=[f"{pkg_name}@{installed_ver}"] if installed_ver != "?" else [],
                    fix_snippet="npm audit fix" if fix_avail else None,
                )
            )

    return findings


def normalize_bandit(raw: dict, root: Path) -> list[Finding]:
    """Normalize bandit output into Findings."""
    findings: list[Finding] = []
    if raw.get("_skipped"):
        return findings

    for item in raw.get("results", []):
        test_id = item.get("test_id", "unknown")
        severity = _BANDIT_SEVERITY.get(
            (item.get("issue_severity") or "MEDIUM").upper(), Severity.MEDIUM
        )
        confidence = _BANDIT_CONFIDENCE.get(
            (item.get("issue_confidence") or "MEDIUM").upper(), 0.7
        )
        cwe_data = item.get("issue_cwe", {})
        cwe_id = f"CWE-{cwe_data.get('id', 0)}" if isinstance(cwe_data, dict) else "CWE-0"
        line_range = item.get("line_range") or []
        start_line = item.get("line_number", 1)
        end_line = max(line_range) if line_range else start_line

        cat = "secret" if test_id in ("B105", "B106", "B107") or cwe_id == "CWE-798" else "code"

        bandit_rel = _rel(item.get("filename", ""), root)
        if is_comment_or_docstring_only(
            root, bandit_rel, start_line, end_line, rule_id=f"bandit.{test_id}", category=cat, evidence=item.get("code", "")
        ):
            _record_filtered_finding(
                rule_id=f"bandit.{test_id}",
                rel_file=bandit_rel,
                line=start_line,
                category=cat,
                reason="Non-executable comment, docstring, or benign assignment",
                evidence=item.get("code", "")[:120],
            )
            continue
        findings.append(
            Finding(
                rule_id=f"bandit.{test_id}",
                title=item.get("issue_text", "Bandit finding")[:160],
                cwe=cwe_id,
                severity=severity,
                confidence=confidence,
                location=Location(
                    file=bandit_rel,
                    start_line=start_line,
                    end_line=end_line,
                ),
                evidence=_clean_evidence(item.get("code", ""), root, bandit_rel, start_line, end_line),
                sources=[SourceTool.BANDIT],
                category=cat,
            )
        )
    return findings


def normalize_all(
    gitleaks_raw: dict,
    semgrep_raw: dict,
    trivy_raw: dict,
    root: Path,
    *,
    pip_audit_raw: dict | None = None,
    npm_audit_raw: dict | None = None,
    bandit_raw: dict | None = None,
) -> list[Finding]:
    results = (
        normalize_gitleaks(gitleaks_raw, root)
        + normalize_semgrep(semgrep_raw, root)
        + normalize_trivy(trivy_raw, root)
    )
    if pip_audit_raw:
        results += normalize_pip_audit(pip_audit_raw, root)
    if npm_audit_raw:
        results += normalize_npm_audit(npm_audit_raw, root)
    if bandit_raw:
        results += normalize_bandit(bandit_raw, root)
    return results
