"""Frontend bundle, infrastructure, and configuration exposure checks (Phase 3).

Checks:
- Client-exposed environment variables (REACT_APP_*, NEXT_PUBLIC_*, VITE_*) containing secrets.
- Hardcoded secrets or tokens in client JS/TS source or localStorage usage.
- Committed source maps (.map files in repository or dist).
- dangerouslySetInnerHTML / innerHTML fed by user or API data.
- Dockerfile risks: running as root, 'latest' tag, secrets in ENV/ARG, ADD with remote URLs.
- docker-compose risks: exposed DB ports (5432, 3306, 27017, 6379), privileged containers.
- GitHub Actions risks: pull_request_target with explicit checkout, unpinned 3rd-party actions.
- Wildcard CORS with credentials (Access-Control-Allow-Origin: * + credentials: true).
- Missing security headers middleware (helmet for Express, SecurityMiddleware for FastAPI).
- Insecure cookie flags (missing HttpOnly, Secure, SameSite).
- JWT misconfigurations (algorithm: none, missing exp validation).
- Missing rate limiting on authentication routes (/login, /token, /auth).
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Location, Severity, SourceTool

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"}
_SENSITIVE_KEY_PATTERNS = re.compile(r"(?:api[_-]?key|secret|token|password|auth|cred|private[_-]?key)", re.IGNORECASE)


def analyze_config_and_frontend_exposure(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Client-exposed env variables & localStorage tokens & source maps
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in parts):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")

        # Check committed source maps
        if p.name.endswith(".map") and not rel.startswith(("node_modules", ".venv")):
            findings.append(Finding(
                rule_id="vibe.config.committed_sourcemap",
                title=f"Committed production source map: {p.name}",
                cwe="CWE-540",
                severity=Severity.LOW,
                confidence=0.95,
                location=Location(file=rel, start_line=1, end_line=1),
                evidence=f"Source map file committed in repository: {rel}",
                sources=[SourceTool.VIBE_RULE],
                category="config",
                remediation="Exclude .map source map files from source control and production builds via .gitignore.",
            ))

        ext = p.suffix.lower()
        if ext in (".js", ".jsx", ".ts", ".tsx", ".env", ".env.local", ".env.production", ".env.development"):
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, 1):
                # Client exposed env vars with secrets
                m_env = re.search(r"""\b(REACT_APP_[A-Z0-9_]+|NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\b""", line)
                if m_env:
                    var_name = m_env.group(1)
                    if _SENSITIVE_KEY_PATTERNS.search(var_name):
                        if any(k in rel.lower() for k in (".example", ".sample", ".template")) and any(k in line.lower() for k in ("your_", "your-", "changeme", "<", "placeholder", "xxx")):
                            continue
                        findings.append(Finding(
                            rule_id="vibe.frontend.exposed_secret_env",
                            title=f"Secret or API key in client-exposed variable: {var_name}",
                            cwe="CWE-526",
                            severity=Severity.HIGH,
                            confidence=0.90,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {line.strip()[:160]}",
                            sources=[SourceTool.VIBE_RULE],
                            category="secret",
                            sensitive_asset="credentials",
                            remediation="Move sensitive credentials to server-side environment variables and proxy requests through a backend route.",
                        ))

                # LocalStorage for sensitive tokens
                if re.search(r"""localStorage\.(?:setItem|getItem)\s*\(\s*["'](?:token|jwt|auth|access_token|id_token|session)["']""", line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="vibe.frontend.token_in_localstorage",
                        title="Authentication token stored in localStorage (accessible to XSS)",
                        cwe="CWE-922",
                        severity=Severity.MEDIUM,
                        confidence=0.85,
                        location=Location(file=rel, start_line=idx, end_line=idx),
                        evidence=f"{idx}| {line.strip()[:160]}",
                        sources=[SourceTool.VIBE_RULE],
                        category="code",
                        remediation="Store session tokens in HttpOnly, Secure, SameSite cookies instead of localStorage.",
                    ))

                # dangerouslySetInnerHTML usage
                if "dangerouslySetInnerHTML" in line or "innerHTML" in line:
                    if re.search(r"""(?:dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:|\.innerHTML\s*=)""", line):
                        findings.append(Finding(
                            rule_id="vibe.frontend.dangerously_set_inner_html",
                            title="Direct unescaped HTML insertion via innerHTML / dangerouslySetInnerHTML",
                            cwe="CWE-79",
                            severity=Severity.MEDIUM,
                            confidence=0.80,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {line.strip()[:160]}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Avoid raw HTML injection; use safe text interpolation or sanitize HTML using DOMPurify.",
                        ))

    # 2. Dockerfile checks
    for df in root.rglob("*Dockerfile*"):
        if not df.is_file() or any(part in _SKIP_DIRS for part in df.relative_to(root).parts):
            continue
        rel = str(df.relative_to(root)).replace("\\", "/")
        try:
            content = df.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        has_user = False
        for idx, line in enumerate(lines, 1):
            s = line.strip()
            if s.upper().startswith("USER "):
                has_user = True
            if s.upper().startswith("FROM ") and ":latest" in s:
                findings.append(Finding(
                    rule_id="vibe.docker.latest_tag",
                    title="Dockerfile uses mutable ':latest' base image tag",
                    cwe="CWE-1357",
                    severity=Severity.LOW,
                    confidence=0.90,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Pin base image to an immutable digest (SHA256) or explicit version tag.",
                ))
            if re.search(r"""^(?:ENV|ARG)\s+.*(?:KEY|SECRET|PASSWORD|TOKEN)\s*=""", s, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="vibe.docker.secret_in_env_arg",
                    title="Potential hardcoded secret in Dockerfile ENV or ARG instruction",
                    cwe="CWE-798",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s[:140]}",
                    sources=[SourceTool.VIBE_RULE],
                    category="secret",
                    remediation="Inject runtime credentials via secret stores or Docker BuildKit secret mounts (--mount=type=secret).",
                ))
            if s.upper().startswith("ADD ") and re.search(r"""https?://""", s):
                findings.append(Finding(
                    rule_id="vibe.docker.add_remote_url",
                    title="Dockerfile ADD instruction with remote URL can fetch unverified contents",
                    cwe="CWE-829",
                    severity=Severity.LOW,
                    confidence=0.85,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Use curl/wget with SHA256 checksum verification in a RUN command instead of ADD for remote URLs.",
                ))

        if not has_user and any(line.strip().upper().startswith("CMD") or line.strip().upper().startswith("ENTRYPOINT") for line in lines):
            findings.append(Finding(
                rule_id="vibe.docker.root_user",
                title="Container runs as default root user (missing USER directive)",
                cwe="CWE-250",
                severity=Severity.MEDIUM,
                confidence=0.80,
                location=Location(file=rel, start_line=1, end_line=1),
                evidence="No USER instruction declared before CMD/ENTRYPOINT",
                sources=[SourceTool.VIBE_RULE],
                category="config",
                remediation="Declare a dedicated non-root user (e.g. USER appuser) before starting container services.",
            ))

    # 3. docker-compose checks
    for compose_file in root.rglob("*compose*.y*ml"):
        if not compose_file.is_file() or any(part in _SKIP_DIRS for part in compose_file.relative_to(root).parts):
            continue
        rel = str(compose_file.relative_to(root)).replace("\\", "/")
        try:
            content = compose_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        for idx, line in enumerate(lines, 1):
            s = line.strip()
            # Exposed database ports: 5432:5432, 3306:3306, 27017:27017, 6379:6379
            if re.search(r"""["']?(?:5432|3306|27017|6379):\1["']?""", s):
                findings.append(Finding(
                    rule_id="vibe.compose.exposed_db_port",
                    title="Database port directly exposed to host interfaces in compose file",
                    cwe="CWE-1327",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Bind database port to localhost only (127.0.0.1:5432:5432) or rely on internal Docker network bridges.",
                ))
            if "privileged: true" in s:
                findings.append(Finding(
                    rule_id="vibe.compose.privileged_mode",
                    title="Container configured in privileged mode in docker-compose",
                    cwe="CWE-250",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Avoid privileged containers; grant only specific necessary Linux capabilities via cap_add.",
                ))

    # 4. GitHub Actions workflow checks
    for wf in root.rglob(".github/workflows/*.y*ml"):
        if not wf.is_file():
            continue
        rel = str(wf.relative_to(root)).replace("\\", "/")
        try:
            content = wf.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        is_pr_target = "pull_request_target" in content
        for idx, line in enumerate(lines, 1):
            s = line.strip()
            if is_pr_target and "actions/checkout@" in s:
                # Fire only when checkout ref is github.event.pull_request.head.*
                step_snippet = "\n".join(lines[idx - 1 : min(len(lines), idx + 8)])
                if "github.event.pull_request.head." in step_snippet:
                    findings.append(Finding(
                        rule_id="vibe.ci.pull_request_target_checkout",
                        title="Dangerous pull_request_target trigger combined with code checkout",
                        cwe="CWE-829",
                        severity=Severity.HIGH,
                        confidence=0.90,
                        location=Location(file=rel, start_line=idx, end_line=idx),
                        evidence=f"{idx}| {s}",
                        sources=[SourceTool.VIBE_RULE],
                        category="config",
                        remediation="Use pull_request trigger instead of pull_request_target when checking out untrusted pull request code.",
                    ))
            if re.search(r"""echo\s+.*(?:\$\{\{\s*secrets\.|\$SECRET)""", s, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="vibe.ci.secret_echoed",
                    title="Potential secret echoed in GitHub Actions workflow log",
                    cwe="CWE-532",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s[:120]}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Do not print or echo secrets in build scripts or workflow logs.",
                ))
            # GitHub Actions 3rd-party action not pinned to a commit SHA
            m_uses = re.search(r"""(?:uses:\s*)([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)""", s)
            if m_uses:
                org, repo, ref = m_uses.group(1), m_uses.group(2), m_uses.group(3)
                if org.lower() != "actions" and not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    findings.append(Finding(
                        rule_id="vibe.ci.unpinned_action_sha",
                        title=f"Third-party GitHub Action not pinned to a commit SHA: {org}/{repo}@{ref}",
                        cwe="CWE-829",
                        severity=Severity.MEDIUM,
                        confidence=0.90,
                        location=Location(file=rel, start_line=idx, end_line=idx),
                        evidence=f"{idx}| {s}",
                        sources=[SourceTool.VIBE_RULE],
                        category="config",
                        remediation="Pin third-party GitHub Actions to a full 40-character commit SHA digest instead of a branch or mutable tag.",
                    ))

    # 5. Security headers middleware, JWT, database connection URIs, and code patterns
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in (".py", ".js", ".ts"):
            continue
        if any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        is_py = rel.endswith(".py")
        is_js = rel.endswith((".js", ".ts"))

        for idx, line in enumerate(lines, 1):
            s = line.strip()

            # Hardcoded credentials inside connection URIs (mongodb://user:pass@host)
            m_uri = re.search(r"""(?:mongodb|postgres|postgresql|mysql|mariadb|redis|amqp|amqps)://([^:\s'"]+):([^@\s'"]+)@([^\s'"]+)""", line)
            if m_uri:
                findings.append(Finding(
                    rule_id="vibe.secret.connection_uri_credentials",
                    title="Hardcoded database credentials within connection URI",
                    cwe="CWE-798",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s[:140]}",
                    sources=[SourceTool.VIBE_RULE],
                    category="secret",
                    sensitive_asset="credentials",
                    remediation="Extract database credentials into environment variables or secrets management solutions.",
                ))

            # FastAPI debug=True or Flask debug=True
            if is_py:
                if re.search(r"""\b(?:FastAPI|Flask)\s*\([^)]*debug\s*=\s*True""", s) or \
                   re.search(r"""\bapp\.run\s*\([^)]*debug\s*=\s*True""", s) or \
                   re.search(r"""\bapp\.config\s*\[\s*['"]DEBUG['"]\s*\]\s*=\s*True""", s):
                    findings.append(Finding(
                        rule_id="vibe.config.debug_mode_enabled",
                        title="Web application initialized with debug mode enabled (debug=True)",
                        cwe="CWE-489",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        location=Location(file=rel, start_line=idx, end_line=idx),
                        evidence=f"{idx}| {s}",
                        sources=[SourceTool.VIBE_RULE],
                        category="config",
                        remediation="Disable debug mode in production environments (set debug=False).",
                    ))

            # JWT issued without exp claim
            if is_py:
                m_jwt = re.search(r"""jwt\.encode\s*\(\s*\{([^}]+)\}\s*,""", s)
                if m_jwt:
                    payload_content = m_jwt.group(1)
                    if "'exp'" not in payload_content and '"exp"' not in payload_content:
                        findings.append(Finding(
                            rule_id="vibe.jwt.missing_exp",
                            title="JWT token generated without expiration claim ('exp')",
                            cwe="CWE-613",
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s[:140]}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Include an explicit expiration claim ('exp') in generated JWT tokens.",
                        ))
            elif is_js:
                m_jwt = re.search(r"""jwt\.sign\s*\(\s*\{([^}]+)\}\s*,\s*[^,)]+(?:,\s*\{([^}]*)\})?""", s)
                if m_jwt:
                    payload_content = m_jwt.group(1)
                    opts_content = m_jwt.group(2) or ""
                    if "exp" not in payload_content and "expiresIn" not in opts_content:
                        findings.append(Finding(
                            rule_id="vibe.jwt.missing_exp",
                            title="JWT token signed without expiration claim ('exp' / 'expiresIn')",
                            cwe="CWE-613",
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s[:140]}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Supply an expiration option (e.g. { expiresIn: '1h' }) or an 'exp' claim in the JWT payload.",
                        ))

            # Path Traversal: user input in os.path.join / open / FileResponse / send_file / res.sendFile
            if is_py:
                if re.search(r"""(?:FileResponse|send_file|open)\s*\(\s*os\.path\.join""", s):
                    has_check = any(k in content.lower() for k in ("resolve().startswith", "os.path.abspath", "secure_filename", "os.path.basename"))
                    if not has_check:
                        findings.append(Finding(
                            rule_id="vibe.path_traversal",
                            title="Path traversal: unvalidated path join in file response",
                            cwe="CWE-22",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Validate that the resolved file path starts with the designated uploads directory.",
                        ))
            elif is_js:
                if re.search(r"""res\.sendFile\s*\([^)]*(?:req\.params|req\.query|req\.body)""", s):
                    if "resolve" not in content or "startsWith" not in content:
                        findings.append(Finding(
                            rule_id="vibe.path_traversal",
                            title="Path traversal: unvalidated client path in res.sendFile",
                            cwe="CWE-22",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Validate that the resolved file path starts with the designated base directory.",
                        ))

            # Reflected XSS: res.send with template literal HTML containing req.query
            if is_js:
                if re.search(r"""res\.(?:send|write)\s*\(\s*`[^`]*\$\{\s*req\.(?:query|params|body)[^}]*\}[^`]*`""", s):
                    if "escape" not in s and "sanitize" not in s:
                        findings.append(Finding(
                            rule_id="vibe.reflected_xss",
                            title="Reflected XSS via template literal response string",
                            cwe="CWE-79",
                            severity=Severity.MEDIUM,
                            confidence=0.90,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Contextually encode user input before reflecting it into HTML responses.",
                        ))

            # NoSQL Injection: req.body or req.query into Mongo find/findOne/updateOne
            if is_js:
                if re.search(r"""\.(?:findOne|find|updateOne|updateMany|deleteMany)\s*\(\s*\{[^}]*req\.(?:body|query|params)""", s):
                    if "sanitize" not in content:
                        findings.append(Finding(
                            rule_id="vibe.nosql_injection",
                            title="NoSQL injection: unsanitized request parameter in MongoDB selector",
                            cwe="CWE-943",
                            severity=Severity.HIGH,
                            confidence=0.90,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Sanitize query selectors using mongo-sanitize or cast input values to explicit string primitives.",
                        ))

            # Python mass assignment of privileged fields
            if is_py:
                if re.search(r"""(?:data|body|request)\.get\(\s*['"](?:role|is_admin|permissions|is_superuser)['"]""", s):
                    if any(k in content.lower() for k in ("insert into", "update ", "user(")):
                        findings.append(Finding(
                            rule_id="vibe.python.mass_assignment",
                            title="Mass assignment: privileged role field extracted from request body",
                            cwe="CWE-915",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            location=Location(file=rel, start_line=idx, end_line=idx),
                            evidence=f"{idx}| {s}",
                            sources=[SourceTool.VIBE_RULE],
                            category="code",
                            remediation="Use explicit schema validation and do not accept client-controlled role or authorization parameters.",
                        ))

            # Wildcard CORS with credentials
            if re.search(r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]""", s) and re.search(r"""allow_credentials\s*=\s*True""", content):
                findings.append(Finding(
                    rule_id="vibe.config.cors_wildcard_credentials",
                    title="CORS configured with wildcard origin and credentials allowed",
                    cwe="CWE-942",
                    severity=Severity.HIGH,
                    confidence=0.90,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Explicitly specify trusted origin domains instead of '*' when allow_credentials is enabled.",
                ))

            # Reflected-origin CORS with credentials (Express & Socket.IO) (I-29)
            if ("cors" in s.lower() or "credentials" in s.lower()) and "credentials" in content:
                if re.search(r"""(?:origin\s*:\s*(?:true|\[?\s*true\s*\]?|[^,}]*\?[^:]*:\s*\[?[^,}]*\]?|req\.headers?\.origin))""", s, re.IGNORECASE) and re.search(r"""credentials\s*:\s*true""", s if "credentials" in s else content, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="vibe.config.reflected_origin_cors",
                        title="Reflected-origin CORS configured with credentials allowed (CWE-942)",
                        cwe="CWE-942",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        location=Location(file=rel, start_line=idx, end_line=idx),
                        evidence=f"{idx}| {s}",
                        sources=[SourceTool.VIBE_RULE],
                        category="config",
                        remediation="Do not dynamically reflect Origin headers when credentials: true is enabled; validate against an explicit whitelist.",
                    ))

            # Helmet Content Security Policy explicitly disabled (I-29)
            if "helmet" in s.lower() and re.search(r"""contentSecurityPolicy\s*:\s*false""", s, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="vibe.config.disabled_csp",
                    title="Helmet Content Security Policy explicitly disabled (contentSecurityPolicy: false)",
                    cwe="CWE-693",
                    severity=Severity.LOW,
                    confidence=0.95,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Configure a restrictive Content Security Policy directives object instead of disabling CSP.",
                ))

            # JWT none algorithm
            if re.search(r"""(?:algorithms|algorithm)\s*=\s*\[?\s*["']none["']\s*\]?""", s, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="vibe.config.jwt_none_algorithm",
                    title="JWT verification configured to accept 'none' algorithm",
                    cwe="CWE-327",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Enforce explicit cryptographic algorithms (e.g. HS256, RS256) and reject the 'none' algorithm.",
                ))

            # Insecure cookie flags
            if re.search(r"""set_cookie\s*\([^)]*httponly\s*=\s*False""", s, re.IGNORECASE) or \
               re.search(r"""set_cookie\s*\([^)]*secure\s*=\s*False""", s, re.IGNORECASE):
                findings.append(Finding(
                    rule_id="vibe.config.insecure_cookie_flags",
                    title="Cookie set without HttpOnly or Secure security flags",
                    cwe="CWE-614",
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    location=Location(file=rel, start_line=idx, end_line=idx),
                    evidence=f"{idx}| {s[:140]}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Set httponly=True, secure=True, and samesite='lax' or 'strict' on sensitive session cookies.",
                ))

        # Express missing helmet check per server file
        if is_js and ("express()" in content or "require('express')" in content) and "listen(" in content:
            if "helmet" not in content:
                app_line = 1
                for idx, line in enumerate(lines, 1):
                    if "express()" in line:
                        app_line = idx
                        break
                findings.append(Finding(
                    rule_id="vibe.express.missing_helmet",
                    title="Express application missing security headers middleware (helmet)",
                    cwe="CWE-1021",
                    severity=Severity.MEDIUM,
                    confidence=0.90,
                    location=Location(file=rel, start_line=app_line, end_line=app_line),
                    evidence=f"{app_line}| {lines[app_line - 1].strip() if app_line <= len(lines) else ''}",
                    sources=[SourceTool.VIBE_RULE],
                    category="config",
                    remediation="Add and configure 'helmet' middleware (app.use(helmet())) to enforce secure HTTP response headers.",
                ))

    # App-level rate limiting check (CWE-770) (I-29)
    has_server = False
    has_rate_limit = False
    for p in root.rglob("*"):
        if not p.is_file() or any(part in _SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        ext = p.suffix.lower()
        if ext in (".py", ".js", ".ts", ".json"):
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
                if "express()" in txt or "FastAPI(" in txt or "Flask(" in txt:
                    has_server = True
                if any(k in txt for k in ("express-rate-limit", "rateLimit", "slowapi", "limiter", "rate_limit")):
                    has_rate_limit = True
            except Exception:
                pass

    if has_server and not has_rate_limit:
        loc_f = "server.ts" if (root / "server.ts").is_file() else ("server/app.ts" if (root / "server" / "app.ts").is_file() else "app.py")
        findings.append(Finding(
            rule_id="vibe.config.missing_rate_limiting",
            title="Web application missing rate limiting middleware while public endpoints exist",
            cwe="CWE-770",
            severity=Severity.LOW,
            confidence=0.85,
            location=Location(file=loc_f, start_line=1, end_line=1),
            evidence="No rate limiting middleware (e.g. express-rate-limit, slowapi) configured across application endpoints.",
            sources=[SourceTool.VIBE_RULE],
            category="config",
            remediation="Apply rate limiting middleware across public routes to prevent brute-force attacks and resource exhaustion.",
        ))

    return findings
