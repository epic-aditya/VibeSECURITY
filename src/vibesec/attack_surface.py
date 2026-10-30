"""Attack-surface mapper — static route detection for Flask, FastAPI, and Express.

Scans Python and JS/TS files for route decorators / registrations and produces
a summary of detected endpoints, their HTTP methods, inferred auth status, and
any findings that overlap with each endpoint.

Limitations:
  - Auth context is inferred from decorators/middleware and may be incomplete.
  - Only detects explicitly decorated/registered routes, not dynamically
    assembled ones.
  - Does not trace middleware chains in Express.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .extractor import MAX_FILE_BYTES, SKIP_DIRS
from .models import Finding


@dataclass
class Endpoint:
    file: str
    line: int
    method: str
    path: str
    function: str = ""
    authenticated: bool | None = None   # True / False / None (unknown)
    auth_confidence: float = 0.0
    auth_reason: str = ""
    accepts_input: bool = False
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "method": self.method,
            "path": self.path,
            "function": self.function,
            "authenticated": self.authenticated,
            "auth_confidence": self.auth_confidence,
            "auth_reason": self.auth_reason,
            "accepts_input": self.accepts_input,
            "finding_count": len(self.findings),
        }


@dataclass
class AttackSurface:
    endpoints: list[Endpoint] = field(default_factory=list)
    total_routes: int = 0
    public_routes: int = 0
    authenticated_routes: int = 0
    unknown_auth_routes: int = 0
    routes_with_findings: int = 0
    routes_accepting_input: int = 0

    def to_dict(self) -> dict:
        return {
            "total_routes": self.total_routes,
            "public_routes": self.public_routes,
            "authenticated_routes": self.authenticated_routes,
            "unknown_auth_routes": self.unknown_auth_routes,
            "routes_with_findings": self.routes_with_findings,
            "routes_accepting_input": self.routes_accepting_input,
            "endpoints": [e.to_dict() for e in self.endpoints],
        }


# --- Python route patterns ---

# Flask: @app.route("/path", methods=["GET", "POST"])
_FLASK_ROUTE = re.compile(
    r"""@\w+\.route\(\s*["'](?P<path>[^"']+)["']"""
    r"""(?:.*methods\s*=\s*\[(?P<methods>[^\]]*)\])?""",
    re.IGNORECASE,
)

# FastAPI: @app.get("/path"), @router.post("/path")
_FASTAPI_ROUTE = re.compile(
    r"""@\w+\.(?P<method>get|post|put|delete|patch|options|head)\(\s*["'](?P<path>[^"']+)["']""",
    re.IGNORECASE,
)

# Auth decorators
_PYTHON_AUTH_DECORATORS = re.compile(
    r"@(?:login_required|auth_required|jwt_required|requires_auth|"
    r"permission_required|permissions_required|authenticated|"
    r"token_required|api_key_required|admin_required)",
    re.IGNORECASE,
)

# --- JS/TS route patterns ---

# Express: app.get("/path", handler) or router.post("/path", handler)
_EXPRESS_ROUTE = re.compile(
    r"""(?:app|router)\.(?P<method>get|post|put|delete|patch|all|options|head)\(\s*["'`](?P<path>[^"'`]+)["'`]""",
    re.IGNORECASE,
)

# Express auth middleware (common names)
_JS_AUTH_MIDDLEWARE = re.compile(
    r"""(?:authenticate|isAuthenticated|requireAuth|verifyToken|authMiddleware|"""
    r"""isLoggedIn|ensureAuth|protect|requireLogin|checkAuth|passport\.authenticate)""",
    re.IGNORECASE,
)

# Def/function name after route decorator
_PY_FUNC = re.compile(r"def\s+(\w+)\s*\(")

# Input-accepting indicators
_INPUT_INDICATORS = re.compile(
    r"request\.(?:form|json|args|data|files|get_json|body)|"
    r"req\.(?:body|params|query|files)|"
    r"request\.path_params|"
    r"<\w+:\w+>|"
    r":\w+",
    re.IGNORECASE,
)


def _detect_python_routes(text: str, rel_path: str) -> list[Endpoint]:
    """Detect Flask/FastAPI route registrations."""
    endpoints: list[Endpoint] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        # Check Flask-style
        m = _FLASK_ROUTE.search(line)
        if m:
            path = m.group("path")
            methods_str = m.group("methods")
            methods = (
                [s.strip().strip("'\"") for s in methods_str.split(",")]
                if methods_str
                else ["GET"]
            )
            # Look backward for auth decorators
            auth, auth_conf, auth_reason = _infer_python_auth(lines, i - 1)
            func_name = _find_function_name(lines, i - 1)
            for method in methods:
                endpoints.append(Endpoint(
                    file=rel_path, line=i, method=method.upper(),
                    path=path, function=func_name, authenticated=auth,
                    auth_confidence=auth_conf, auth_reason=auth_reason,
                ))
            continue

        # Check FastAPI-style
        m = _FASTAPI_ROUTE.search(line)
        if m:
            auth, auth_conf, auth_reason = _infer_python_auth(lines, i - 1)
            func_name = _find_function_name(lines, i - 1)
            endpoints.append(Endpoint(
                file=rel_path, line=i, method=m.group("method").upper(),
                path=m.group("path"), function=func_name, authenticated=auth,
                auth_confidence=auth_conf, auth_reason=auth_reason,
            ))

    return endpoints


def _detect_js_routes(text: str, rel_path: str) -> list[Endpoint]:
    """Detect Express route registrations."""
    endpoints: list[Endpoint] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        m = _EXPRESS_ROUTE.search(line)
        if m:
            # Check if auth middleware is referenced on the same line or nearby
            auth, auth_conf, auth_reason = _infer_js_auth(line, lines, i - 1)
            endpoints.append(Endpoint(
                file=rel_path, line=i, method=m.group("method").upper(),
                path=m.group("path"), authenticated=auth,
                auth_confidence=auth_conf, auth_reason=auth_reason,
            ))

    return endpoints


_GLOBAL_PY_AUTH = re.compile(
    r"(?:before_request|before_app_request|add_middleware|HTTPBearer|OAuth2PasswordBearer|"
    r"APIKeyHeader|Security\()",
    re.IGNORECASE,
)
_GLOBAL_JS_AUTH = re.compile(
    r"(?:app|router)\.use\([^)]*(?:auth|jwt|passport|session|token)",
    re.IGNORECASE,
)


def _infer_python_auth(lines: list[str], route_line_idx: int) -> tuple[bool | None, float, str]:
    """Infer route auth from decorators/signature; record confidence and reason."""
    start = max(0, route_line_idx - 5)
    end = min(len(lines), route_line_idx + 12)
    block = "\n".join(lines[start:end])
    if _PYTHON_AUTH_DECORATORS.search(block) or re.search(r"\bDepends\s*\(", block):
        return True, 0.9, "Auth decorator or Depends() dependency detected in route block."
    if _GLOBAL_PY_AUTH.search("\n".join(lines)):
        return None, 0.5, "Global auth middleware detected; per-route enforcement unknown."
    return False, 0.6, "No auth decorator, Depends() dependency, or global auth middleware detected."


def _infer_js_auth(route_line: str, lines: list[str], line_idx: int) -> tuple[bool | None, float, str]:
    """Check if auth middleware appears in route arguments or prior app.use matching mount path."""
    m_args = re.search(r"""(?:app|router)\.\w+\(\s*["'`][^"'`]+["'`]\s*,\s*(.*?)(?=\b(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))""", route_line)
    if m_args:
        args_str = m_args.group(1).strip()
        tokens = [t.strip().rstrip(",") for t in args_str.split(",") if t.strip()]
        for tok in tokens:
            if re.search(r"^(?:auth|authenticate|requireAuth|jwtAuth|verifyToken|passport|ensureAuth|checkAuth)$", tok, re.IGNORECASE):
                return True, 0.9, f"Auth middleware referenced on route arguments: {tok}."

    prior_lines = "\n".join(lines[:line_idx])
    if re.search(r"""(?:app|router)\.use\(\s*(?:["'][^"']+["']\s*,\s*)?(?:auth|authenticate|jwt|verifyToken|passport)""", prior_lines, re.IGNORECASE):
        return True, 0.8, "Prior app.use auth middleware registered before route."

    return False, 0.9, "No auth middleware referenced on the route argument list or prior app.use."



def _find_function_name(lines: list[str], decorator_line_idx: int) -> str:
    """Look after the decorator line for a def statement."""
    for offset in range(1, 6):
        idx = decorator_line_idx + offset
        if idx >= len(lines):
            break
        m = _PY_FUNC.search(lines[idx])
        if m:
            return m.group(1)
    return ""


def map_attack_surface(
    root: Path,
    findings: list[Finding] | None = None,
) -> AttackSurface:
    """Scan the project root for route declarations and correlate with findings."""
    endpoints: list[Endpoint] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue

        ext = path.suffix.lower()
        rel = str(path.relative_to(root)).replace("\\", "/")

        if ext == ".py":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            endpoints.extend(_detect_python_routes(text, rel))

        elif ext in {".js", ".ts", ".mjs"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            endpoints.extend(_detect_js_routes(text, rel))

    # Classify auth status
    surface = AttackSurface(endpoints=endpoints, total_routes=len(endpoints))
    for ep in endpoints:
        if ep.authenticated is True:
            surface.authenticated_routes += 1
        elif ep.authenticated is False:
            surface.public_routes += 1
        else:
            surface.unknown_auth_routes += 1
            surface.public_routes += 1  # conservative: unknown = potentially public

    # Check which endpoints accept user input (heuristic: route params or state-changing verbs)
    for ep in endpoints:
        if bool(re.search(r"<\w+>|:\w+", ep.path) or ep.method.upper() in ("POST", "PUT", "PATCH")):
            ep.accepts_input = True
            surface.routes_accepting_input += 1

    # Map findings to endpoints
    if findings:
        for ep in endpoints:
            for f in findings:
                if f.location.file == ep.file and abs(f.location.start_line - ep.line) <= 50:
                    # Finding is in the same file and near the route
                    ep.findings.append(f)
        surface.routes_with_findings = sum(1 for ep in endpoints if ep.findings)

    return surface
