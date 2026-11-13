"""Deterministic, static taint analysis for Python web handlers (Phase 2).

The analyzer parses Python ASTs only — target code is never imported or run.
It tracks request-controlled values from route parameters and request globals
to high-impact sinks, with one-level interprocedural parameter propagation
inside each module. Findings carry the full evidence chain so the report can
show *why* a flow is believed reachable.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .imports import iter_source_files
from .models import Finding, Location, Severity, SourceTool

try:
    import yaml

    _YAML_OK = True
except Exception:  # pragma: no cover
    _YAML_OK = False

_DATA_FILE = Path(__file__).resolve().parent / "data" / "taint_catalog.yaml"

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "route", "api_route"}
_SQL_SINKS = {"execute", "executemany"}
_SHELL_SINKS = {"system", "popen", "run", "call", "Popen", "check_output", "check_call"}
_SKIP_DIRS = {"tests", "test", "__tests__", ".venv", "venv", "node_modules", "build", "dist"}


@dataclass(frozen=True)
class Taint:
    origin: str
    chain: tuple[str, ...] = ()

    def extend(self, step: str) -> Taint:
        return Taint(self.origin, self.chain + (step,))


@dataclass
class SinkSpec:
    name: str
    cwe: str
    rule: str
    severity: str
    impact: str
    confidence: float
    rationale: str


@dataclass
class SourceSpec:
    name: str
    origin: str


@dataclass
class TaintFlow:
    rule_id: str
    cwe: str
    severity: str
    impact: str
    confidence: float
    rationale: str
    file: str
    line: int
    end_line: int
    chain: list[str] = field(default_factory=list)
    snippet: str = ""
    function: str = ""
    auth_context: str = "unknown"

    def to_finding(self) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=_title_for(self.impact),
            cwe=self.cwe,
            severity=_severity(self.severity),
            confidence=self.confidence,
            location=Location(file=self.file, start_line=self.line, end_line=self.end_line),
            evidence=self.snippet,
            sources=[SourceTool.VIBE_RULE],
            taint_reachable=True,
            impact_class=self.impact,
            auth_context=self.auth_context,
            category="code",
            explanation=(
                f"Static taint analysis found a {self.impact.replace('_', ' ')} flow with "
                f"{max(0, len(self.chain) - 1)} step(s); confidence {self.confidence:.2f}. "
                f"{self.rationale}"
            ),
            evidence_chain=list(self.chain),
        )


def _title_for(impact: str) -> str:
    return {
        "sql_injection": "Tainted input reaches SQL execution",
        "command_execution": "Tainted input reaches shell command execution",
        "code_execution": "Tainted input reaches dynamic code execution",
        "deserialization": "Tainted input reaches unsafe deserialization",
        "path_traversal": "Tainted input reaches filesystem path",
        "ssrf": "Tainted input reaches server-side HTTP request",
        "xss": "Tainted input reaches unescaped HTML rendering",
    }.get(impact, "Tainted input reaches a high-impact sink")


def _severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError:
        return Severity.HIGH


def _load_catalog() -> tuple[dict[str, SourceSpec], dict[str, SinkSpec], set[str]]:
    sources: dict[str, SourceSpec] = {}
    sinks: dict[str, SinkSpec] = {}
    sanitizers: set[str] = set()
    if _YAML_OK and _DATA_FILE.is_file():
        data = yaml.safe_load(_DATA_FILE.read_text(encoding="utf-8")) or {}
        for item in data.get("sources") or []:
            for name in item.get("match") or []:
                sources[name] = SourceSpec(str(name), str(item.get("origin", "request.input")))
        for item in data.get("sinks") or []:
            spec = SinkSpec(
                name=str(item.get("id", "")),
                cwe=str(item.get("cwe", "CWE-20")),
                rule=str(item.get("rule", "vibe.taint.unknown")),
                severity=str(item.get("severity", "HIGH")),
                impact=str(item.get("impact", "unknown")),
                confidence=float(item.get("confidence", 0.8)),
                rationale=str(item.get("rationale", "")),
            )
            for name in item.get("match") or []:
                sinks[str(name)] = spec
        for item in data.get("sanitizers") or []:
            for name in item.get("match") or []:
                sanitizers.add(str(name))
    if not sinks:
        sinks = {
            "execute": SinkSpec("sql", "CWE-89", "vibe.taint.sql_injection", "HIGH", "sql_injection", 0.9, ""),
            "os.system": SinkSpec("cmd", "CWE-78", "vibe.taint.command_injection", "CRITICAL", "command_execution", 0.9, ""),
            "eval": SinkSpec("eval", "CWE-95", "vibe.taint.code_injection", "CRITICAL", "code_execution", 0.9, ""),
        }
    if not sources:
        sources = {"Body": SourceSpec("Body", "request.body"), "request.args": SourceSpec("request.args", "request.query")}
    sanitizers = sanitizers or {"int", "float", "html.escape", "shlex.quote"}
    return sources, sinks, sanitizers


_SOURCES, _SINKS, _SANITIZERS = _load_catalog()


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _source_spec(node: ast.AST) -> SourceSpec | None:
    dotted = _dotted(node)
    if not dotted:
        return None
    for key, spec in _SOURCES.items():
        if dotted == key or dotted.endswith(f".{key}") or dotted.startswith(f"{key}."):
            return spec
    return None


def _sink_spec(dotted: str) -> SinkSpec | None:
    if dotted in _SINKS:
        return _SINKS[dotted]
    short = _short(dotted)
    if short in _SINKS:
        return _SINKS[short]
    if dotted.endswith(".execute") or dotted.endswith(".executemany"):
        return _SINKS.get(short)
    return None


def _is_sanitizer(dotted: str) -> bool:
    return dotted in _SANITIZERS or _short(dotted) in _SANITIZERS


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return _dotted(node)


def _is_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        name = _decorator_name(dec)
        if name and _short(name).lower() in _ROUTE_METHODS:
            return True
    return False


def _param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = node.args
    return [a.arg for a in list(args.args) + list(args.kwonlyargs)]


def _route_tainted_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Taint]:
    tainted: dict[str, Taint] = {}
    if not _is_route(node):
        return tainted
    positional = list(node.args.args) + list(node.args.kwonlyargs)
    defaults = [None] * (len(node.args.args) - len(node.args.defaults)) + list(node.args.defaults)
    for idx, arg in enumerate(positional):
        if arg.arg in ("self", "cls"):
            continue
        default = defaults[idx] if idx < len(defaults) else None
        origin = "request.input"
        if isinstance(default, ast.Call):
            spec = _source_spec(default.func)
            if spec:
                origin = spec.origin
        if isinstance(default, ast.Call) and _short(_dotted(default.func)) == "Depends":
            continue
        tainted[arg.arg] = Taint(origin, (f"route parameter '{arg.arg}' ({origin})",))
    return tainted


def _union(taints: list[Taint | None] | Iterable[Taint | None]) -> Taint | None:
    for t in taints:
        if t is not None:
            return t
    return None


def _expr_taint(node: ast.AST | None, env: dict[str, Taint], functions: Mapping[str, Any]) -> Taint | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Constant):
        return None
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _expr_taint(node.value, env, functions)
    if isinstance(node, ast.JoinedStr):
        return _union([_expr_taint(v, env, functions) for v in node.values])
    if isinstance(node, ast.FormattedValue):
        return _expr_taint(node.value, env, functions)
    if isinstance(node, ast.BinOp):
        return _union([_expr_taint(node.left, env, functions), _expr_taint(node.right, env, functions)])
    if isinstance(node, ast.BoolOp):
        return _union([_expr_taint(v, env, functions) for v in node.values])
    if isinstance(node, ast.Compare):
        return _union([_expr_taint(node.left, env, functions)] + [_expr_taint(c, env, functions) for c in node.comparators])
    if isinstance(node, ast.IfExp):
        return _union([_expr_taint(node.body, env, functions), _expr_taint(node.orelse, env, functions)])
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _union([_expr_taint(e, env, functions) for e in node.elts])
    if isinstance(node, ast.Dict):
        return _union([_expr_taint(v, env, functions) for v in node.values])
    if isinstance(node, ast.Await):
        return _expr_taint(node.value, env, functions)
    if isinstance(node, ast.Call):
        dotted = _dotted(node.func)
        if _is_sanitizer(dotted):
            return None
        spec = _source_spec(node.func)
        if spec:
            return Taint(spec.origin, (f"{spec.origin}",))
        args = [_expr_taint(a, env, functions) for a in node.args]
        args += [_expr_taint(kw.value, env, functions) for kw in node.keywords]
        return _union(args)
    return None


def _sql_is_parameterized(call: ast.Call) -> bool:
    if len(call.args) >= 2:
        return True
    return any(kw.arg in ("parameters", "params", "args") for kw in call.keywords)


def _command_has_shell(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _statement_blocks(stmt: ast.stmt) -> list[list[ast.stmt]]:
    blocks: list[list[ast.stmt]] = []
    for attr in ("body", "orelse", "finalbody"):
        block = getattr(stmt, attr, None)
        if isinstance(block, list):
            blocks.append([s for s in block if isinstance(s, ast.stmt)])
    for handler in getattr(stmt, "handlers", []) or []:
        blocks.append([s for s in getattr(handler, "body", []) if isinstance(s, ast.stmt)])
    return blocks


def _analyze_statements(
    statements: list[ast.stmt],
    env: dict[str, Taint],
    file_rel: str,
    functions: Mapping[str, Any],
    flows: list[TaintFlow],
    seen: set[tuple[str, int, str]],
    callee_taint: dict[str, dict[str, Taint]],
    lines: list[str],
    auth_context: str,
    function_name: str,
) -> None:
    for stmt in statements:
        _analyze_statement(
            stmt, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name
        )


def _analyze_statement(
    stmt: ast.stmt,
    env: dict[str, Taint],
    file_rel: str,
    functions: Mapping[str, Any],
    flows: list[TaintFlow],
    seen: set[tuple[str, int, str]],
    callee_taint: dict[str, dict[str, Taint]],
    lines: list[str],
    auth_context: str,
    function_name: str,
) -> None:
    if isinstance(stmt, ast.Assign):
        taint = _expr_taint(stmt.value, env, functions)
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                if taint:
                    env[target.id] = taint.extend(f"{file_rel}:{stmt.lineno} assignment '{target.id}'")
                else:
                    env.pop(target.id, None)
        _check_call(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name, stmt.lineno)
    elif isinstance(stmt, ast.AnnAssign):
        taint = _expr_taint(stmt.value, env, functions)
        if taint and isinstance(stmt.target, ast.Name):
            env[stmt.target.id] = taint
        _check_call(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name, stmt.lineno)
        if stmt.value is not None:
            _check_nested_calls(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)
    elif isinstance(stmt, ast.AugAssign):
        taint = _union([_expr_taint(stmt.value, env, functions), env.get(_dotted(stmt.target))])
        if taint and isinstance(stmt.target, ast.Name):
            env[stmt.target.id] = taint
        _check_call(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name, stmt.lineno)
    elif isinstance(stmt, ast.Expr):
        _check_call(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name, stmt.lineno)
        if not isinstance(stmt.value, ast.Call):
            _check_nested_calls(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)
    elif isinstance(stmt, ast.Return):
        _check_nested_calls(stmt.value, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)
    elif isinstance(stmt, ast.If):
        _check_nested_calls(stmt.test, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)
        for block in _statement_blocks(stmt):
            _analyze_statements(block, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)
    else:
        for block in _statement_blocks(stmt):
            _analyze_statements(block, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)


def _check_nested_calls(
    node: ast.AST | None,
    env: dict[str, Taint],
    file_rel: str,
    functions: Mapping[str, Any],
    flows: list[TaintFlow],
    seen: set[tuple[str, int, str]],
    callee_taint: dict[str, dict[str, Taint]],
    lines: list[str],
    auth_context: str,
    function_name: str,
) -> None:
    if node is None:
        return
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and not isinstance(child, ast.Expr):
            _emit_sink(child, env, file_rel, flows, seen, lines, auth_context, function_name)
        if isinstance(child, ast.Call):
            _propagate_call(child, env, file_rel, functions, callee_taint)


def _check_call(
    node: ast.AST | None,
    env: dict[str, Taint],
    file_rel: str,
    functions: Mapping[str, Any],
    flows: list[TaintFlow],
    seen: set[tuple[str, int, str]],
    callee_taint: dict[str, dict[str, Taint]],
    lines: list[str],
    auth_context: str,
    function_name: str,
    line: int,
) -> None:
    if not isinstance(node, ast.Call):
        return
    _emit_sink(node, env, file_rel, flows, seen, lines, auth_context, function_name)
    _propagate_call(node, env, file_rel, functions, callee_taint)
    for arg in list(node.args) + [kw.value for kw in node.keywords]:
        _check_nested_calls(arg, env, file_rel, functions, flows, seen, callee_taint, lines, auth_context, function_name)


def _emit_sink(
    call: ast.Call,
    env: dict[str, Taint],
    file_rel: str,
    flows: list[TaintFlow],
    seen: set[tuple[str, int, str]],
    lines: list[str],
    auth_context: str,
    function_name: str,
) -> None:
    dotted = _dotted(call.func)
    spec = _sink_spec(dotted)
    if spec is None:
        return
    short = _short(dotted)
    if short in _SQL_SINKS and _sql_is_parameterized(call):
        return
    if short in _SHELL_SINKS and not _command_has_shell(call) and short not in ("system", "popen"):
        return

    candidates: list[Taint | None] = []
    if call.args:
        candidates.append(_expr_taint(call.args[0], env, {}))
    else:
        candidates.extend(_expr_taint(kw.value, env, {}) for kw in call.keywords)
    if short in _SQL_SINKS or short in ("open", "render_template_string"):
        taint = candidates[0] if candidates else None
    else:
        taint = _union(candidates)
    if taint is None:
        return

    key = (file_rel, call.lineno, spec.rule)
    if key in seen:
        return
    seen.add(key)
    snippet = _snippet(lines, call.lineno)
    chain = list(taint.chain) + [f"{file_rel}:{call.lineno} sink {dotted} ({spec.impact})"]
    flows.append(
        TaintFlow(
            rule_id=spec.rule,
            cwe=spec.cwe,
            severity=spec.severity,
            impact=spec.impact,
            confidence=spec.confidence,
            rationale=spec.rationale,
            file=file_rel,
            line=call.lineno,
            end_line=getattr(call, "end_lineno", call.lineno) or call.lineno,
            chain=chain,
            snippet=snippet,
            function=function_name,
            auth_context=auth_context,
        )
    )


def _propagate_call(
    call: ast.Call,
    env: dict[str, Taint],
    file_rel: str,
    functions: Mapping[str, Any],
    callee_taint: dict[str, dict[str, Taint]],
) -> None:
    name = _short(_dotted(call.func))
    target = functions.get(name)
    if not isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return
    params = _param_names(target)
    args = list(call.args)
    for idx, arg in enumerate(args):
        if idx >= len(params):
            break
        taint = _expr_taint(arg, env, functions)
        if taint:
            callee_taint.setdefault(name, {})[params[idx]] = taint.extend(
                f"{file_rel}:{call.lineno} argument {idx + 1} -> {name}({params[idx]})"
            )
    for kw in call.keywords:
        if kw.arg and kw.arg in params:
            taint = _expr_taint(kw.value, env, functions)
            if taint:
                callee_taint.setdefault(name, {})[kw.arg] = taint.extend(
                    f"{file_rel}:{call.lineno} argument {kw.arg} -> {name}"
                )


def _snippet(lines: list[str], line: int) -> str:
    if not lines:
        return ""
    lo = max(0, line - 2)
    hi = min(len(lines), line + 1)
    return "\n".join(f"{i + 1}| {lines[i]}" for i in range(lo, hi))[:800]


def _auth_context(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    for dec in node.decorator_list:
        if "login_required" in _decorator_name(dec):
            return "authenticated"
    for arg in list(node.args.args) + list(node.args.kwonlyargs):
        default = None
        if isinstance(arg.annotation, ast.Name):
            default = arg.annotation.id
        if default in ("Depends",):
            return "authenticated"
    for stmt in ast.walk(node):
        if isinstance(stmt, ast.Call) and _short(_dotted(stmt.func)) == "Depends":
            return "authenticated"
    return "public"


def analyze_module(path: Path, root: Path) -> list[TaintFlow]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(path))
    except Exception:
        return []

    try:
        file_rel = str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        file_rel = path.name
    lines = source.splitlines()

    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, node)
    if not functions:
        return []

    callee_taint: dict[str, dict[str, Taint]] = {}
    for name, node in functions.items():
        initial = _route_tainted_params(node)
        if initial:
            callee_taint.setdefault(name, {}).update(initial)

    flows: list[TaintFlow] = []
    seen: set[tuple[str, int, str]] = set()
    for _ in range(5):
        before = {name: dict(vals) for name, vals in callee_taint.items()}
        for name, node in functions.items():
            env = dict(callee_taint.get(name, {}))
            auth = _auth_context(node) if _is_route(node) else "unknown"
            _analyze_statements(
                [s for s in node.body if isinstance(s, ast.stmt)],
                env,
                file_rel,
                functions,
                flows,
                seen,
                callee_taint,
                lines,
                auth,
                name,
            )
        if callee_taint == before:
            break

    return flows


def find_taint_flows(root: Path) -> list[TaintFlow]:
    flows: list[TaintFlow] = []
    for path, rel in iter_source_files(root):
        if path.suffix.lower() != ".py":
            continue
        if any(part.lower() in _SKIP_DIRS for part in rel.parts):
            continue
        flows.extend(analyze_module(path, root))
    return flows
