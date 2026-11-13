"""Application Security Model (ASM) (v3).

Builds a deterministic, static model of the application:
- Entrypoints with method, full resolved path, handler, framework, auth_state,
  auth_evidence, and typed parameter validation states.
- Data access sites (SQL, ORM, Mongo, File I/O).
- External call sites (outbound HTTP, LLM APIs, subprocesses, emails).
- Secret use sites & client bundle environment variables.
- Attack paths synthesized by the inter-procedural taint engine.
- Exposure-adjusted posture calculation.

Target code is only ever READ and statically parsed; never executed or imported.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .attack_paths import AttackPath, find_attack_paths
from .attack_surface import AttackSurface
from .grouping import FixAction
from .models import Finding
from .reachability import ReachabilityMap

_SKIP_DIRS = {"tests", "test", "__tests__", "testing", "spec", "specs", "fixtures", "scripts", ".venv", "venv", "node_modules", "build", "dist", ".git", ".next"}
_CLIENT_RECEIVERS = {"axios", "fetch", "http", "https", "request", "client", "api", "supertest", "agent", "needle", "got", "apiclient", "httpclient"}


@dataclass
class RouteParameter:
    name: str
    source_kind: str  # path | query | body | header | cookie | file
    validation: str   # TYPED_MODEL | VALIDATOR | NONE | UNKNOWN
    type_annotation: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_kind": self.source_kind,
            "validation": self.validation,
            "type_annotation": self.type_annotation,
        }


@dataclass
class EntryPoint:
    id: str
    method: str
    path: str
    file: str
    line: int
    handler: str = ""
    framework: str = ""
    auth_state: str = "UNKNOWN"  # PUBLIC | AUTHENTICATED | UNKNOWN
    auth_evidence: str = "none found"
    parameters: list[RouteParameter] = field(default_factory=list)
    auth: str = "unknown"  # legacy compat
    auth_confidence: float = 0.5
    auth_reason: str = ""
    accepts_input: bool = False
    finding_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "file": self.file,
            "line": self.line,
            "handler": self.handler,
            "framework": self.framework,
            "auth_state": self.auth_state,
            "auth_evidence": self.auth_evidence,
            "parameters": [p.to_dict() for p in self.parameters],
            "auth": self.auth_state.lower(),
            "auth_confidence": self.auth_confidence,
            "auth_reason": self.auth_reason or self.auth_evidence,
            "accepts_input": self.accepts_input,
            "finding_count": self.finding_count,
        }


@dataclass
class DataAccessSite:
    id: str
    file: str
    line: int
    kind: str  # sql | orm | mongo | file_io
    operation: str
    target: str = ""
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "operation": self.operation,
            "target": self.target,
            "code_snippet": self.code_snippet,
        }


@dataclass
class ExternalCallSite:
    id: str
    file: str
    line: int
    kind: str  # http | llm | subprocess | email
    target: str = ""
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "target": self.target,
            "code_snippet": self.code_snippet,
        }


@dataclass
class SecretUseSite:
    id: str
    file: str
    line: int
    secret_type: str
    key_name: str = ""
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "secret_type": self.secret_type,
            "key_name": self.key_name,
            "code_snippet": self.code_snippet,
        }


@dataclass
class ClientEnvVar:
    name: str
    file: str
    line: int
    is_sensitive: bool = False
    value_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "is_sensitive": self.is_sensitive,
            "value_snippet": self.value_snippet,
        }


@dataclass
class Asset:
    id: str
    name: str
    kind: str  # credentials | datastore | filesystem | external_service | llm | client_bundle
    exposure: str
    evidence: list[str] = field(default_factory=list)
    finding_count: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "exposure": self.exposure,
            "evidence": list(self.evidence),
            "finding_count": self.finding_count,
        }


@dataclass
class TrustBoundary:
    id: str
    name: str
    from_zone: str
    to_zone: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "from_zone": self.from_zone,
            "to_zone": self.to_zone,
            "evidence": self.evidence,
        }


@dataclass
class Posture:
    public_routes: int = 0
    public_state_changing_routes: int = 0
    runtime_packages_with_findings: int = 0
    toolchain_packages_with_findings: int = 0
    secrets_in_client_bundle: int = 0
    reachable_attack_paths: int = 0
    actionable_findings: int = 0
    deprioritized_findings: int = 0
    deprioritized_dependency_cves: int = 0
    deprioritized_test_toolchain: int = 0
    top_finding_title: str = ""
    top_finding_boundary: str = ""
    suppressed_findings: int = 0
    unauthenticated_critical_paths: int = 0
    cisa_kev_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    max_score: float = 0.0
    risk_posture_statement: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ApplicationSecurityModel:
    entry_points: list[EntryPoint] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    data_access_sites: list[DataAccessSite] = field(default_factory=list)
    external_calls: list[ExternalCallSite] = field(default_factory=list)
    secret_uses: list[SecretUseSite] = field(default_factory=list)
    client_env_vars: list[ClientEnvVar] = field(default_factory=list)
    posture: Posture = field(default_factory=Posture)
    frameworks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "frameworks": list(self.frameworks),
            "posture": self.posture.to_dict(),
            "entry_points": [e.to_dict() for e in self.entry_points],
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "data_access_sites": [d.to_dict() for d in self.data_access_sites],
            "external_calls": [x.to_dict() for x in self.external_calls],
            "secret_uses": [s.to_dict() for s in self.secret_uses],
            "client_env_vars": [c.to_dict() for c in self.client_env_vars],
            "assets": [a.to_dict() for a in self.assets],
            "trust_boundaries": [b.to_dict() for b in self.trust_boundaries],
            "warnings": list(self.warnings),
        }

    def save(self, out_path: str | Path) -> Path:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return out


def _resolve_fastapi_params(args_node: ast.arguments) -> list[RouteParameter]:
    params: list[RouteParameter] = []
    defaults_map: dict[str, ast.expr] = {}
    total_args = len(args_node.args)
    def_count = len(args_node.defaults)
    for i, default in enumerate(args_node.defaults):
        param_idx = total_args - def_count + i
        if param_idx >= 0:
            defaults_map[args_node.args[param_idx].arg] = default

    for arg in args_node.args:
        p_name = arg.arg
        if p_name in ("self", "cls", "request"):
            continue

        type_str = ast.unparse(arg.annotation) if arg.annotation else ""
        default_expr = defaults_map.get(p_name)
        def_str = ast.unparse(default_expr) if default_expr else ""

        # Determine source kind
        source_kind = "query"
        if "Body" in def_str:
            source_kind = "body"
        elif "Path" in def_str:
            source_kind = "path"
        elif "Header" in def_str:
            source_kind = "header"
        elif "Cookie" in def_str:
            source_kind = "cookie"
        elif "File" in def_str or "UploadFile" in type_str:
            source_kind = "file"
        elif type_str in ("dict", "Dict", "Any"):
            source_kind = "body"

        # Determine validation
        if type_str in ("dict", "Dict", "Any") or (not type_str and "Body" in def_str):
            validation = "NONE"
        elif type_str and not type_str.startswith(("dict", "Dict", "Any")):
            # Standard type or Pydantic model
            if type_str in ("str", "int", "float", "bool", "UUID"):
                validation = "VALIDATOR"
            else:
                validation = "TYPED_MODEL"
        elif "validator" in def_str.lower():
            validation = "VALIDATOR"
        else:
            validation = "UNKNOWN"

        params.append(RouteParameter(
            name=p_name,
            source_kind=source_kind,
            validation=validation,
            type_annotation=type_str,
        ))
    return params


def _scan_asm_entities(root: Path) -> tuple[
    list[EntryPoint],
    list[DataAccessSite],
    list[ExternalCallSite],
    list[SecretUseSite],
    list[ClientEnvVar],
    list[str],
]:
    entry_points: list[EntryPoint] = []
    data_access: list[DataAccessSite] = []
    external_calls: list[ExternalCallSite] = []
    secret_uses: list[SecretUseSite] = []
    client_env_vars: list[ClientEnvVar] = []
    detected_frameworks: set[str] = set()

    # Track prefixes: router_var -> prefix string
    router_prefixes: dict[str, str] = {}

    # First pass: collect router prefixes (e.g. app.include_router(r, prefix="/api"))
    for py_file in root.rglob("*.py"):
        rel_parts = [p.lower() for p in py_file.relative_to(root).parts]
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        py_name = py_file.name.lower()
        if ".test." in py_name or py_name.startswith("test_") or py_name.endswith("_test.py"):
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "include_router":
                        detected_frameworks.add("FastAPI")
                        prefix = ""
                        for kw in node.keywords:
                            if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                                prefix = str(kw.value.value)
                        if node.args and isinstance(node.args[0], ast.Name):
                            router_prefixes[node.args[0].id] = prefix
                    elif node.func.attr == "register_blueprint":
                        detected_frameworks.add("Flask")
                        prefix = ""
                        for kw in node.keywords:
                            if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant):
                                prefix = str(kw.value.value)
                        if node.args and isinstance(node.args[0], ast.Name):
                            router_prefixes[node.args[0].id] = prefix
        except Exception:
            continue

    # Second pass: extract endpoints and code sites
    for py_file in root.rglob("*.py"):
        rel_parts = [p.lower() for p in py_file.relative_to(root).parts]
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        py_name = py_file.name.lower()
        if ".test." in py_name or py_name.startswith("test_") or py_name.endswith("_test.py"):
            continue
        rel = str(py_file.relative_to(root)).replace("\\", "/")
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            tree = ast.parse(content, filename=rel)
        except Exception:
            continue

        for node in ast.walk(tree):
            # Check route handlers
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                        method = dec.func.attr.upper()
                        router_obj = ast.unparse(dec.func.value) if hasattr(dec.func, "value") else ""
                        if method in {"GET", "POST", "PUT", "DELETE", "PATCH", "ROUTE", "API_ROUTE"}:
                            route_path = "/"
                            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                                route_path = dec.args[0].value
                            prefix = router_prefixes.get(router_obj, "")
                            full_path = (prefix.rstrip("/") + "/" + route_path.lstrip("/")).replace("//", "/")
                            if not full_path.startswith("/"):
                                full_path = "/" + full_path

                            # Framework
                            fw = "FastAPI" if "FastAPI" in detected_frameworks or method != "ROUTE" else "Flask"
                            detected_frameworks.add(fw)

                            # Auth state
                            auth_state = "PUBLIC"
                            auth_evidence = "none found"
                            dec_str = " ".join(ast.unparse(d) for d in node.decorator_list)
                            if any(k in dec_str.lower() for k in ("login_required", "auth", "jwt", "permission")):
                                auth_state = "AUTHENTICATED"
                                auth_evidence = f"Decorator: {dec_str}"
                            else:
                                for default in node.args.defaults + node.args.kw_defaults:
                                    if default:
                                        d_str = ast.unparse(default)
                                        if "Depends" in d_str and any(k in d_str.lower() for k in ("auth", "user", "token", "jwt", "login")):
                                            auth_state = "AUTHENTICATED"
                                            auth_evidence = f"Dependency: {d_str}"
                                            break

                            params = _resolve_fastapi_params(node.args)
                            entry_points.append(EntryPoint(
                                id="",
                                method="GET" if method in {"ROUTE", "API_ROUTE"} else method,
                                path=full_path,
                                file=rel,
                                line=node.lineno,
                                handler=node.name,
                                framework=fw,
                                auth_state=auth_state,
                                auth_evidence=auth_evidence,
                                parameters=params,
                                accepts_input=len(params) > 0,
                            ))

            # Check calls for data access, external calls, secret uses
            if isinstance(node, ast.Call):
                call_name = ast.unparse(node.func)
                line_no = node.lineno
                snippet = lines[line_no - 1].strip() if 1 <= line_no <= len(lines) else call_name

                # Data access: SQL / ORM / Mongo
                if any(call_name.endswith(f".{m}") or call_name == m for m in ("execute", "executemany", "raw")):
                    data_access.append(DataAccessSite(
                        id=f"da-{len(data_access)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="sql",
                        operation=call_name,
                        code_snippet=snippet[:120],
                    ))
                elif call_name in ("open", "send_file", "send_from_directory"):
                    data_access.append(DataAccessSite(
                        id=f"da-{len(data_access)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="file_io",
                        operation=call_name,
                        code_snippet=snippet[:120],
                    ))
                elif any(m in call_name for m in ("find_one", "insert_one", "update_one", "delete_one")):
                    data_access.append(DataAccessSite(
                        id=f"da-{len(data_access)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="mongo",
                        operation=call_name,
                        code_snippet=snippet[:120],
                    ))

                # External call: HTTP / LLM / Subprocess
                if any(k in call_name for k in ("requests.", "httpx.", "urlopen")):
                    external_calls.append(ExternalCallSite(
                        id=f"ec-{len(external_calls)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="http",
                        target=call_name,
                        code_snippet=snippet[:120],
                    ))
                elif any(k in call_name for k in ("ChatCompletion", "completions.create", "llm.invoke", "llm.predict")):
                    external_calls.append(ExternalCallSite(
                        id=f"ec-{len(external_calls)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="llm",
                        target="OpenAI / LLM Provider",
                        code_snippet=snippet[:120],
                    ))
                elif any(k in call_name for k in ("subprocess.run", "subprocess.call", "os.system", "os.popen", "subprocess.Popen")):
                    external_calls.append(ExternalCallSite(
                        id=f"ec-{len(external_calls)+1:04d}",
                        file=rel,
                        line=line_no,
                        kind="subprocess",
                        target=call_name,
                        code_snippet=snippet[:120],
                    ))

                # Secret usage: os.environ.get(...)
                if "environ.get" in call_name or "getenv" in call_name:
                    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        key = node.args[0].value
                        if any(k in key.lower() for k in ("key", "secret", "token", "password", "auth", "cred")):
                            secret_uses.append(SecretUseSite(
                                id=f"su-{len(secret_uses)+1:04d}",
                                file=rel,
                                line=line_no,
                                secret_type="environment_variable",
                                key_name=key,
                                code_snippet=snippet[:120],
                            ))

    # Scan JS/TS files for Express/Next.js routes and client env vars
    js_exts = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs")
    js_files_list = [
        f for f in root.rglob("*")
        if f.is_file() and f.suffix.lower() in js_exts
        and not any(part.lower() in _SKIP_DIRS for part in f.relative_to(root).parts)
        and ".test." not in f.name.lower()
        and ".spec." not in f.name.lower()
        and not f.name.lower().startswith("test_")
    ]

    def _resolve_relative_module(from_dir: Path, specifier: str) -> Path | None:
        spec = specifier.strip()
        if not (spec.startswith("./") or spec.startswith("../")):
            return None
        target = (from_dir / spec).resolve()
        if target.is_file():
            return target
        for ext in (".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs", ".cjs"):
            c = (from_dir / f"{spec}{ext}").resolve()
            if c.is_file():
                return c
        for ext in (".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs"):
            c = (from_dir / spec / f"index{ext}").resolve()
            if c.is_file():
                return c
        return None

    # Pass 1: Discover module import bindings and app.use router mounts
    router_file_prefixes: dict[Path, str] = {}
    router_var_prefixes: dict[tuple[str, str], str] = {}

    for js_file in js_files_list:
        rel = str(js_file.relative_to(root)).replace("\\", "/")
        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        local_imports: dict[str, Path] = {}
        for imp_m in re.finditer(
            r"""(?:import\s+(?:([a-zA-Z0-9_$]+)|\{\s*([a-zA-Z0-9_$]+)\s*\})\s+from|const\s+([a-zA-Z0-9_$]+)\s*=\s*require)\s*\(\s*['"]([^'"]+)['"]\s*\)?""",
            content,
        ):
            v_name = imp_m.group(1) or imp_m.group(2) or imp_m.group(3)
            spec = imp_m.group(4)
            if v_name and spec:
                target_p = _resolve_relative_module(js_file.parent, spec)
                if target_p:
                    local_imports[v_name] = target_p

        # Find app.use('/prefix', router)
        for use_m in re.finditer(
            r"""(?:app|router|[a-zA-Z0-9_$]+)\.use\(\s*['"]([^'"]+)['"]\s*,\s*([a-zA-Z0-9_$]+)\s*\)""",
            content,
        ):
            mount_pfx = use_m.group(1).rstrip("/")
            if not mount_pfx.startswith("/"):
                mount_pfx = "/" + mount_pfx
            target_var = use_m.group(2)
            if target_var in local_imports:
                router_file_prefixes[local_imports[target_var]] = mount_pfx
            else:
                router_var_prefixes[(rel, target_var)] = mount_pfx

    # Pass 2: Extract endpoints and code sites from JS/TS
    for js_file in js_files_list:
        rel = str(js_file.relative_to(root)).replace("\\", "/")
        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        # Check client exposed env variables
        for idx, line in enumerate(lines, 1):
            for m in re.finditer(r"""\b(REACT_APP_[A-Z0-9_]+|NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+)\b""", line):
                var_name = m.group(1)
                is_sens = any(k in var_name.lower() for k in ("secret", "key", "token", "password", "auth"))
                client_env_vars.append(ClientEnvVar(
                    name=var_name,
                    file=rel,
                    line=idx,
                    is_sensitive=is_sens,
                    value_snippet=line.strip()[:100],
                ))

        # Collect prior app.use / router.use middlewares in this file
        use_middlewares: list[tuple[int, str, str]] = []  # (lineno, mount_path, middleware_name)
        for use_m in re.finditer(r"""(?:app|router)\.use\(\s*(?:["']([^"']+)["']\s*,\s*)?([a-zA-Z0-9_\.]+)\s*""", content):
            use_line = content[: use_m.start()].count("\n") + 1
            mount_prefix = use_m.group(1) or "/"
            mw_name = use_m.group(2)
            use_middlewares.append((use_line, mount_prefix, mw_name))

        file_prefix = router_file_prefixes.get(js_file.resolve(), "")

        # Check if file has express/router/fastify/koa imports or declarations
        has_server_lib = bool(re.search(
            r"""(?:require\(["'](?:express|fastify|koa|@nestjs)["']\)|from\s+["'](?:express|fastify|koa|@nestjs)["']|Router\(\)|express\(\)|fastify\(\))""",
            content,
            re.IGNORECASE,
        ))

        # Identify Map / Set / Cache variables that should never count as route receivers
        map_set_vars = set(re.findall(
            r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*new\s+(?:Map|Set|WeakMap|WeakSet|Cache)\b""",
            content,
            re.IGNORECASE,
        ))
        map_set_vars.update({"map", "set", "cache", "store", "routecache", "cachemap", "headers", "mycache", "sessionstore"})

        # Identify valid receiver variables bound to express/Router/fastify
        valid_receivers = set(re.findall(
            r"""(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:express|Router|express\.Router|fastify)\b""",
            content,
        ))
        for (v_rel, v_name) in router_var_prefixes:
            if v_rel == rel:
                valid_receivers.add(v_name)

        if has_server_lib:
            valid_receivers.add("app")
            valid_receivers.add("router")

        # Check Express routes
        for m in re.finditer(
            r"""(?P<receiver>app|router|[a-zA-Z0-9_$]+)\.(?P<method>get|post|put|delete|patch|all|options|head)\(\s*['"](?P<path>[^'"]+)['"](?P<rest>[^;\n]+)?\)""",
            content,
            re.IGNORECASE,
        ):
            receiver = m.group("receiver")
            method = m.group("method").upper()
            path_str = m.group("path")
            lineno = content[: m.start()].count("\n") + 1

            # Map/Set get/delete never count
            if receiver.lower() in map_set_vars or receiver in map_set_vars:
                continue

            # Exclude HTTP client calls (axios.get, fetch.get, etc.) from being registered as routes
            if receiver.lower() in _CLIENT_RECEIVERS:
                external_calls.append(ExternalCallSite(
                    id=f"ec-{len(external_calls)+1:04d}",
                    file=rel,
                    line=lineno,
                    kind="http",
                    target=f"{receiver}.{method}({path_str})",
                    code_snippet=lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else f"{receiver}.{method}",
                ))
                continue

            # Routes only when receiver comes from express()/Router()/fastify()/etc. in that file or an import
            if receiver not in valid_receivers and receiver not in ("app", "router"):
                continue
            if (receiver in ("app", "router")) and not has_server_lib:
                if not file_prefix and (rel, receiver) not in router_var_prefixes:
                    continue

            detected_frameworks.add("Express")
            rest = (m.group("rest") or "").strip()

            prefix = "" if receiver == "app" else (router_var_prefixes.get((rel, receiver)) or file_prefix)
            full_path = (prefix.rstrip("/") + "/" + path_str.lstrip("/")).replace("//", "/")
            if not full_path.startswith("/"):
                full_path = "/" + full_path

            is_auth = False
            auth_evidence = "none found"

            # 1. Route argument list check
            mid_args = rest.lstrip(",").strip()
            handler_str = ""
            if mid_args:
                tokens = [t.strip().rstrip(",") for t in mid_args.split(",") if t.strip()]
                if tokens:
                    handler_str = tokens[-1]
                for tok in tokens[:-1] if len(tokens) > 1 else tokens:
                    if re.search(r"(?:auth|authenticate|requireAuth|jwtAuth|verifyToken|passport|ensureAuth|checkAuth|isAuth)", tok, re.IGNORECASE):
                        is_auth = True
                        auth_evidence = f"Route argument middleware: {tok}"
                        break

            # 2. Prior app.use / router.use check
            if not is_auth:
                for u_line, u_mount, u_mw in use_middlewares:
                    if u_line < lineno:
                        if path_str.startswith(u_mount) or u_mount == "/":
                            if re.search(r"(?:auth|authenticate|jwt|verifyToken|passport)", u_mw, re.IGNORECASE):
                                is_auth = True
                                auth_evidence = f"Prior app.use middleware: {u_mw} (mount: {u_mount})"
                                break

            # Parameter discovery from route path (:param)
            route_params: list[RouteParameter] = []
            for p_m in re.finditer(r":([a-zA-Z0-9_]+)", path_str):
                route_params.append(RouteParameter(
                    name=p_m.group(1),
                    source_kind="path",
                    validation="NONE",
                ))

            clean_handler = handler_str.split("=>")[0].strip()[:40] if handler_str else ""
            if not clean_handler or "function" in clean_handler or "(" in clean_handler:
                clean_handler = f"handler_{method.lower()}_{path_str.replace('/', '_').strip('_')}"

            entry_points.append(EntryPoint(
                id="",
                method="ALL" if method == "ALL" else method,
                path=full_path,
                file=rel,
                line=lineno,
                handler=clean_handler,
                framework="Express",
                auth_state="AUTHENTICATED" if is_auth else "PUBLIC",
                auth_evidence=auth_evidence,
                parameters=route_params,
                accepts_input=len(route_params) > 0 or method in ("POST", "PUT", "PATCH"),
            ))

    # Deduplicate entrypoints & assign IDs
    deduped_eps: list[EntryPoint] = []
    seen: set[tuple[str, str, str]] = set()
    for ep in sorted(entry_points, key=lambda e: (e.file, e.line, e.path, e.method)):
        ep_key = (ep.file, ep.method, ep.path)
        if ep_key in seen:
            continue
        seen.add(ep_key)
        deduped_eps.append(ep)

    for idx, ep in enumerate(deduped_eps, 1):
        ep.id = f"ep-{idx:04d}"

    # A CLI with no HTTP server reports 0 routes
    from .extractor import profile_project
    prof = profile_project(root)
    is_cli_no_http = (prof.app_type == "cli") and not any(
        fw.lower() in ("fastapi", "flask", "express", "nestjs", "fastify", "django", "koa") for fw in detected_frameworks
    )
    if is_cli_no_http:
        deduped_eps = []

    return deduped_eps, data_access, external_calls, secret_uses, client_env_vars, sorted(detected_frameworks)


def build_asm(
    root: Path | None = None,
    findings: list[Finding] | None = None,
    fix_actions: list[FixAction] | None = None,
    attack_surface: AttackSurface | None = None,
    reachability: ReachabilityMap | None = None,
    frameworks: list[str] | None = None,
    suppressed_count: int = 0,
) -> ApplicationSecurityModel:
    """Build the serializable Application Security Model from measured static evidence."""
    findings = findings or []
    fix_actions = fix_actions or []

    if root is not None:
        eps, data_access, external_calls, secret_uses, client_env_vars, auto_fws = _scan_asm_entities(root)
        fws = sorted(set((frameworks or []) + auto_fws))
        attack_paths = find_attack_paths(root, findings=findings, entry_points=eps)
    else:
        eps, data_access, external_calls, secret_uses, client_env_vars = [], [], [], [], []
        fws = sorted(set(frameworks or []))
        attack_paths = []

    asm = ApplicationSecurityModel(
        frameworks=fws,
        entry_points=eps,
        data_access_sites=data_access,
        external_calls=external_calls,
        secret_uses=secret_uses,
        client_env_vars=client_env_vars,
        attack_paths=attack_paths,
    )

    # Posture calculations
    public_eps = [e for e in eps if e.auth_state == "PUBLIC"]
    asm.posture.public_routes = len(public_eps)
    asm.posture.public_state_changing_routes = sum(
        1 for e in public_eps if e.method in ("POST", "PUT", "PATCH", "DELETE")
    )
    asm.posture.secrets_in_client_bundle = sum(1 for c in client_env_vars if c.is_sensitive)
    asm.posture.reachable_attack_paths = len(attack_paths)

    runtime_pkgs: set[str] = set()
    toolchain_pkgs: set[str] = set()
    for f in findings:
        if f.category == "dependency" and f.package_name:
            if (f.exposure_class or "").startswith("RUNTIME"):
                runtime_pkgs.add(f.package_name.lower())
            elif (f.exposure_class or "").startswith("TOOLCHAIN") or f.exposure_class == "TEST":
                toolchain_pkgs.add(f.package_name.lower())

    asm.posture.runtime_packages_with_findings = len(runtime_pkgs)
    asm.posture.toolchain_packages_with_findings = len(toolchain_pkgs)

    dep_findings = [f for f in findings if f.category == "dependency"]
    asm.posture.deprioritized_findings = sum(
        1 for f in dep_findings
        if (f.exposure_class or "").startswith("TOOLCHAIN")
        or f.exposure_class == "TEST"
        or f.reachability in ("TOOLCHAIN", "NOT_IMPORTED")
    )
    asm.posture.actionable_findings = sum(
        1 for f in findings
        if f.category != "dependency"
        or f.reachability in ("CALLED", "IMPORTED", "TRANSITIVE_OF_RUNTIME")
    )
    asm.posture.suppressed_findings = suppressed_count

    # Risk posture statement
    from .prioritizer import calculate_risk_posture
    posture_stmt, posture_details = calculate_risk_posture(findings, asm=asm)
    asm.posture.risk_posture_statement = posture_stmt
    for k, v in posture_details.items():
        if hasattr(asm.posture, k):
            setattr(asm.posture, k, v)

    # Build Assets & Trust Boundaries
    assets_map: dict[str, Asset] = {}
    if data_access:
        assets_map["asset-datastore"] = Asset(
            "asset-datastore", "Application datastore", "datastore", "internal",
            [f"{d.file}:{d.line}" for d in data_access[:5]],
        )
    if external_calls:
        assets_map["asset-external"] = Asset(
            "asset-external", "External network services & APIs", "external_service", "external",
            [f"{x.file}:{x.line}" for x in external_calls[:5]],
        )
    if secret_uses:
        assets_map["asset-credentials"] = Asset(
            "asset-credentials", "Application credentials & API keys", "credentials", "internal",
            [f"{s.file}:{s.line}" for s in secret_uses[:5]],
        )
    if client_env_vars:
        assets_map["asset-client"] = Asset(
            "asset-client", "Client bundle environment", "client_bundle", "public",
            [f"{c.file}:{c.line}" for c in client_env_vars[:5]],
        )
    asm.assets = sorted(assets_map.values(), key=lambda a: a.id)

    if public_eps:
        asm.trust_boundaries.append(TrustBoundary(
            "tb-internet", "Internet to application boundary", "internet", "application",
            f"{len(public_eps)} public route(s) exposed without authentication",
        ))
    if data_access:
        asm.trust_boundaries.append(TrustBoundary(
            "tb-datastore", "Application to datastore boundary", "application", "datastore",
            f"{len(data_access)} data access call site(s) detected",
        ))
    if external_calls:
        asm.trust_boundaries.append(TrustBoundary(
            "tb-external", "Application to external network boundary", "application", "external_network",
            f"{len(external_calls)} outbound external call site(s) detected",
        ))

    return asm
