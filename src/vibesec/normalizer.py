"""Stage 4 — Finding Normalizer.

Converts each scanner's raw JSON into the common Finding schema:
file, line, rule/CWE, severity, confidence, source tool (plan Section 3).

Handles: Gitleaks, Semgrep, Trivy (vuln + misconfig + secret + license),
pip-audit, npm audit, and Bandit.
"""

from __future__ import annotations

import re
from pathlib import Path

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


_PLACEHOLDER_SECRET_RE = re.compile(
    r"(?:my_gemini_api_key|your[_-]?key[_-]?here|changeme|<token>|<.*?>|your[_-]?secret|placeholder|dummy|example|xxx+|foo|bar)",
    re.IGNORECASE,
)


def _is_placeholder_secret(file_rel: str, match_text: str) -> bool:
    f_lower = file_rel.lower()
    if any(k in f_lower for k in (".example", ".sample", ".template")):
        if _PLACEHOLDER_SECRET_RE.search(match_text):
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
        if _is_placeholder_secret(rel_f, match):
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
            elif "secret" in title.lower() or "key" in title.lower():
                severity = Severity.HIGH
            elif severity == Severity.CRITICAL and ("dockerfile" in str(target).lower() or mc_id.startswith("DS")):
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

            title_str = "; ".join(title_parts)[:120] or f"Vulnerability in {pkg_name}"
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
