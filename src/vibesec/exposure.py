"""Dependency exposure classification (v3).

Replaces the prod/dev-only notion. For every lockfile package, answer:
"Can this package's code reach the shipped runtime, or is it only used to
build/test the app?"

Classes:
- RUNTIME_SERVER     backend runtime code (Python/FastAPI/Flask/Express server)
- RUNTIME_BUNDLE     frontend code that ships to the browser
- TOOLCHAIN_BUILD    build/transpile/typecheck only
- TOOLCHAIN_DEVSERVER hot-reload/dev-server only
- TEST               tests only
- UNKNOWN            cannot be determined

Method: full lockfile dependency graph + source imports + toolchain root seeds.
A package is runtime only if reachable from an imported runtime root and not
exclusively reachable through a toolchain root. The shortest chain is recorded
as evidence (e.g. "react-scripts > webpack-dev-server > express > proxy-addr").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dep_graph import DependencyGraph
from .imports import SourceImports, collect_imports

try:
    import yaml

    _YAML_OK = True
except Exception:  # pragma: no cover - pyyaml is a declared dependency
    _YAML_OK = False

_DATA_DIR = Path(__file__).resolve().parent / "data"

RUNTIME_SERVER = "RUNTIME_SERVER"
RUNTIME_BUNDLE = "RUNTIME_BUNDLE"
TOOLCHAIN_BUILD = "TOOLCHAIN_BUILD"
TOOLCHAIN_DEVSERVER = "TOOLCHAIN_DEVSERVER"
TEST = "TEST"
UNKNOWN = "UNKNOWN"

RUNTIME_CLASSES = {RUNTIME_SERVER, RUNTIME_BUNDLE}
DEPRIORITIZED_CLASSES = {TOOLCHAIN_BUILD, TOOLCHAIN_DEVSERVER, TEST}

_DEFAULT_TOOLCHAIN: dict[str, dict[str, Any]] = {
    "react-scripts": {"dev_server": False, "ecosystem": "npm"},
    "webpack": {"dev_server": False, "ecosystem": "npm"},
    "webpack-cli": {"dev_server": False, "ecosystem": "npm"},
    "webpack-dev-server": {"dev_server": True, "ecosystem": "npm"},
    "webpack-dev-middleware": {"dev_server": True, "ecosystem": "npm"},
    "vite": {"dev_server": True, "ecosystem": "npm"},
    "@vitejs/plugin-react": {"dev_server": True, "ecosystem": "npm"},
    "@vitejs/plugin-react-swc": {"dev_server": True, "ecosystem": "npm"},
    "@tailwindcss/vite": {"dev_server": False, "ecosystem": "npm"},
    "tsx": {"dev_server": False, "ecosystem": "npm"},
    "@babel/core": {"dev_server": False, "ecosystem": "npm"},
    "eslint": {"dev_server": False, "ecosystem": "npm"},
    "jest": {"dev_server": False, "ecosystem": "npm", "test": True},
    "typescript": {"dev_server": False, "ecosystem": "npm"},
    "postcss": {"dev_server": False, "ecosystem": "npm"},
    "tailwindcss": {"dev_server": False, "ecosystem": "npm"},
    "craco": {"dev_server": False, "ecosystem": "npm"},
    "parcel": {"dev_server": True, "ecosystem": "npm"},
    "rollup": {"dev_server": False, "ecosystem": "npm"},
    "esbuild": {"dev_server": False, "ecosystem": "npm"},
    "nodemon": {"dev_server": True, "ecosystem": "npm"},
    "ts-node": {"dev_server": False, "ecosystem": "npm"},
    "pytest": {"dev_server": False, "ecosystem": "pypi", "test": True},
    "mypy": {"dev_server": False, "ecosystem": "pypi"},
    "ruff": {"dev_server": False, "ecosystem": "pypi"},
    "black": {"dev_server": False, "ecosystem": "pypi"},
}


def load_toolchain_roots() -> dict[str, dict[str, Any]]:
    path = _DATA_DIR / "toolchain_roots.yaml"
    roots = dict(_DEFAULT_TOOLCHAIN)
    if _YAML_OK and path.is_file():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for name, meta in (data.get("toolchain_roots") or {}).items():
                roots[str(name).lower()] = dict(meta or {})
        except Exception:
            pass
    return roots


@dataclass
class ExposureInfo:
    package_name: str
    exposure_class: str = UNKNOWN
    evidence_chain: list[str] = field(default_factory=list)
    runtime_reachable: bool = False
    rationale: str = ""
    confidence: float = 0.3

    @property
    def chain_text(self) -> str:
        return " > ".join(self.evidence_chain)

    @property
    def is_runtime(self) -> bool:
        return self.exposure_class in RUNTIME_CLASSES

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "exposure_class": self.exposure_class,
            "evidence_chain": list(self.evidence_chain),
            "chain_text": self.chain_text,
            "runtime_reachable": self.runtime_reachable,
            "rationale": self.rationale,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ExposureInfo:
        return cls(
            package_name=d.get("package_name", ""),
            exposure_class=d.get("exposure_class", UNKNOWN),
            evidence_chain=list(d.get("evidence_chain") or []),
            runtime_reachable=bool(d.get("runtime_reachable", False)),
            rationale=d.get("rationale", ""),
            confidence=float(d.get("confidence", 0.3) or 0.3),
        )


def _normalize(name: str) -> str:
    return (name or "").lower().strip()


def _is_frontend_project(root: Path) -> bool:
    for pj in root.rglob("package.json"):
        if any(part.lower() in {"node_modules", ".git"} for part in pj.parts):
            continue
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        deps: dict[str, Any] = {}
        for key in ("dependencies", "devDependencies"):
            deps.update(data.get(key) or {})
        if any(k in deps for k in ("react", "react-dom", "next", "vue", "svelte", "@angular/core", "solid-js")):
            return True
    return False


def _shortest_paths(graph: DependencyGraph, roots: list[str], limit: int = 8) -> dict[str, list[str]]:
    """BFS from roots. Returns package -> shortest root-to-package chain."""
    paths: dict[str, list[str]] = {}
    for root_name in roots:
        root_norm = _normalize(root_name)
        node = graph.get_node(root_norm)
        if not node:
            continue
        start = _normalize(node.name)
        if start not in paths:
            paths[start] = [start]
        queue: list[tuple[str, list[str]]] = [(start, [start])]
        while queue:
            curr, chain = queue.pop(0)
            if len(chain) > limit:
                continue
            curr_node = graph.get_node(curr)
            if not curr_node:
                continue
            for dep in curr_node.dependencies:
                dep_norm = _normalize(dep)
                if dep_norm in paths:
                    continue
                dep_node = graph.get_node(dep_norm)
                if not dep_node:
                    continue
                dep_name = _normalize(dep_node.name)
                paths[dep_name] = chain + [dep_name]
                queue.append((dep_name, chain + [dep_name]))
    return paths


def _detect_workspace_roles(root: Path) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Map direct package names to their workspace role (RUNTIME_SERVER or RUNTIME_BUNDLE).
    Returns:
    - pkg_to_role: global fallback pkg -> role
    - ws_dir_to_role: workspace rel_path -> role
    - ws_pkg_to_role: f"{ws_dir}/{pkg}" -> role
    """
    pkg_to_role: dict[str, str] = {}
    ws_dir_to_role: dict[str, str] = {}
    ws_pkg_to_role: dict[str, str] = {}

    # 1. Python manifests -> RUNTIME_SERVER
    for req in root.rglob("*requirement*.txt"):
        if any(part.lower() in {"node_modules", ".git", ".venv", "venv", "dist", "build"} for part in req.parts):
            continue
        ws_dir = str(req.parent.relative_to(root)).replace("\\", "/")
        if ws_dir == ".":
            ws_dir = ""
        ws_dir_to_role[ws_dir] = RUNTIME_SERVER
        try:
            for line in req.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
                if m:
                    p = m.group(1).lower().strip()
                    pkg_to_role[p] = RUNTIME_SERVER
                    if ws_dir:
                        ws_pkg_to_role[f"{ws_dir}/{p}"] = RUNTIME_SERVER
        except Exception:
            pass

    # 2. Node manifests -> Role detection per workspace
    for pj in root.rglob("package.json"):
        if any(part.lower() in {"node_modules", ".git", ".venv", "venv", "dist", "build"} for part in pj.parts):
            continue
        ws_dir = str(pj.parent.relative_to(root)).replace("\\", "/")
        if ws_dir == ".":
            ws_dir = ""
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        deps = data.get("dependencies", {}) or {}
        dev_deps = data.get("devDependencies", {}) or {}
        all_deps = {**deps, **dev_deps}

        has_bundler = any(k in all_deps for k in ("react-scripts", "vite", "next", "webpack", "rollup", "parcel", "esbuild"))
        has_ui = any(k in all_deps for k in ("react", "react-dom", "vue", "svelte", "@angular/core", "solid-js"))
        has_server = any(k in all_deps for k in ("express", "fastify", "koa", "nestjs", "hapi", "restify"))

        if has_bundler and has_ui:
            role = RUNTIME_BUNDLE
        elif has_server and not has_bundler or has_server:
            role = RUNTIME_SERVER
        elif has_bundler:
            role = RUNTIME_BUNDLE
        else:
            role = RUNTIME_BUNDLE if has_ui else RUNTIME_SERVER

        ws_dir_to_role[ws_dir] = role

        for p in deps:
            p_norm = p.lower().strip()
            if ws_dir:
                ws_pkg_to_role[f"{ws_dir}/{p_norm}"] = role
            if p_norm not in pkg_to_role or role == RUNTIME_SERVER:
                pkg_to_role[p_norm] = role

        for p in dev_deps:
            p_norm = p.lower().strip()
            if ws_dir:
                ws_pkg_to_role[f"{ws_dir}/{p_norm}"] = TOOLCHAIN_BUILD

    return pkg_to_role, ws_dir_to_role, ws_pkg_to_role


def classify_exposure(
    root: Path,
    graph: DependencyGraph | None,
    imports: SourceImports | None = None,
) -> dict[str, ExposureInfo]:
    """Return package -> ExposureInfo for every node in the dependency graph."""
    if graph is None:
        return {}
    imports = imports or collect_imports(root)
    toolchain = load_toolchain_roots()
    ws_roles, ws_dir_roles, ws_pkg_roles = _detect_workspace_roles(root)

    runtime_roots: list[tuple[str, str]] = []
    tc_roots: list[str] = []

    for name, node in graph.nodes.items():
        norm = _normalize(name)
        if norm in toolchain or norm.startswith("@types/"):
            tc_roots.append(norm)
            continue
        if node.direct:
            if node.ecosystem == "pypi" or norm in imports.python:
                runtime_roots.append((norm, RUNTIME_SERVER))
            elif norm in ws_roles:
                runtime_roots.append((norm, ws_roles[norm]))
            elif norm in imports.javascript:
                evidence_files = imports.javascript.get(norm, [])
                is_server = any(
                    p.startswith(("server/", "backend/", "api/", "server.", "app."))
                    or any(k in norm for k in ("express", "mongoose", "fastify", "koa", "jsonwebtoken", "mongodb", "helmet", "cors", "socket.io"))
                    for p in evidence_files
                )
                runtime_roots.append((norm, RUNTIME_SERVER if is_server else RUNTIME_BUNDLE))
            elif node.scope == "prod":
                runtime_roots.append((norm, RUNTIME_SERVER))
            else:
                tc_roots.append(norm)
        elif node.scope == "dev":
            tc_roots.append(norm)

    runtime_paths: dict[str, list[str]] = {}
    runtime_class_of: dict[str, str] = {}
    for root_name, cls in runtime_roots:
        for pkg, chain in _shortest_paths(graph, [root_name]).items():
            if pkg not in runtime_paths or len(chain) < len(runtime_paths[pkg]):
                runtime_paths[pkg] = chain
                runtime_class_of[pkg] = cls

    tc_paths = _shortest_paths(graph, tc_roots)

    result: dict[str, ExposureInfo] = {}
    for name, node in graph.nodes.items():
        norm = _normalize(name)
        tc_meta = toolchain.get(norm, {})
        is_test_root = bool(tc_meta.get("test")) or any(k in norm for k in ("jest", "pytest", "vitest", "mocha", "cypress", "playwright", "testing-library"))
        is_devserver_root = bool(tc_meta.get("dev_server"))

        if norm.startswith("@types/"):
            chain = tc_paths.get(norm, [norm])
            info = ExposureInfo(
                package_name=norm,
                exposure_class=TOOLCHAIN_BUILD,
                evidence_chain=chain,
                rationale="TypeScript type declaration package (@types/*); used for compile-time checking only.",
                confidence=0.95,
            )
        elif norm in imports.javascript:
            evidence_files = imports.javascript.get(norm, [])
            is_server = any(
                p.startswith(("server/", "backend/", "api/", "server.", "app."))
                or any(k in norm for k in ("express", "mongoose", "fastify", "koa", "jsonwebtoken", "mongodb", "helmet", "cors", "socket.io"))
                for p in evidence_files
            )
            is_client = any(
                p.startswith(("src/", "frontend/", "client/", "public/", "pages/", "components/"))
                for p in evidence_files
            )
            role = RUNTIME_SERVER if is_server else (RUNTIME_BUNDLE if is_client else ws_roles.get(norm, RUNTIME_SERVER))
            info = ExposureInfo(
                package_name=norm,
                exposure_class=role,
                evidence_chain=[norm],
                runtime_reachable=True,
                rationale=f"Imported by {'server-side Node' if role == RUNTIME_SERVER else 'shipped frontend'} source.",
                confidence=0.95,
            )
        elif norm in imports.python:
            info = ExposureInfo(
                package_name=norm,
                exposure_class=RUNTIME_SERVER,
                evidence_chain=[norm],
                runtime_reachable=True,
                rationale="Imported by backend Python source, so it can execute on the server.",
                confidence=0.95,
            )
        elif norm in imports.config and norm not in runtime_paths:
            chain = tc_paths.get(norm, [norm])
            info = ExposureInfo(
                package_name=norm,
                exposure_class=TOOLCHAIN_BUILD,
                evidence_chain=chain,
                rationale="Only referenced by build/config files; it does not ship to runtime.",
                confidence=0.75,
            )
        elif norm in runtime_paths:
            chain = runtime_paths[norm]
            root_dep = chain[0] if chain else norm
            cls = runtime_class_of.get(norm, ws_roles.get(root_dep, RUNTIME_SERVER))
            info = ExposureInfo(
                package_name=norm,
                exposure_class=cls,
                evidence_chain=chain,
                runtime_reachable=True,
                rationale=f"Transitively reachable from imported runtime package '{chain[0]}'.",
                confidence=0.9,
            )
        elif norm in tc_paths:
            chain = tc_paths[norm]
            on_path = [p for p in chain if p in toolchain]
            devserver = is_devserver_root or any(toolchain.get(p, {}).get("dev_server") for p in on_path)
            test_only = is_test_root or any(toolchain.get(p, {}).get("test") for p in on_path)
            cls = TOOLCHAIN_DEVSERVER if devserver else (TEST if test_only else TOOLCHAIN_BUILD)
            info = ExposureInfo(
                package_name=norm,
                exposure_class=cls,
                evidence_chain=chain,
                rationale=(
                    "Reachable only through the dev-server toolchain; it does not reach production."
                    if cls == TOOLCHAIN_DEVSERVER
                    else "Reachable only through build/test tooling; it does not reach production."
                ),
                confidence=0.85,
            )
        elif node.scope == "dev":
            cls = TEST if is_test_root else (TOOLCHAIN_DEVSERVER if is_devserver_root else TOOLCHAIN_BUILD)
            info = ExposureInfo(
                package_name=norm,
                exposure_class=cls,
                evidence_chain=[norm],
                rationale="Declared as a development dependency with no runtime import path.",
                confidence=0.7,
            )
        elif node.direct:
            exp_c = ws_roles.get(norm, RUNTIME_SERVER if node.ecosystem == "pypi" else UNKNOWN)
            info = ExposureInfo(
                package_name=norm,
                exposure_class=exp_c,
                evidence_chain=[norm],
                rationale=f"Direct dependency in workspace ({exp_c})." if exp_c != UNKNOWN else "Direct dependency with no source import detected; runtime use is unknown.",
                confidence=0.6 if exp_c != UNKNOWN else 0.4,
            )
        else:
            info = ExposureInfo(
                package_name=norm,
                exposure_class=UNKNOWN,
                evidence_chain=[],
                rationale="No runtime or toolchain path could be resolved from the lockfile graph.",
                confidence=0.3,
            )
        result[norm] = info

    for ws_pkg, role in ws_pkg_roles.items():
        parts = ws_pkg.split("/", 1)
        pkg_name = parts[1] if len(parts) > 1 else ws_pkg
        ws_name = parts[0] if len(parts) > 1 else ""
        if role == TOOLCHAIN_BUILD:
            exp_c = TOOLCHAIN_BUILD
        elif role in RUNTIME_CLASSES:
            exp_c = role
        else:
            exp_c = role
        result[ws_pkg] = ExposureInfo(
            package_name=pkg_name,
            exposure_class=exp_c,
            evidence_chain=[ws_pkg],
            runtime_reachable=(exp_c in RUNTIME_CLASSES),
            rationale=f"Workspace '{ws_name}' direct package classified as {exp_c}.",
            confidence=0.9,
        )

    return result


def summarize_exposure(exposures: dict[str, ExposureInfo]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for info in exposures.values():
        summary[info.exposure_class] = summary.get(info.exposure_class, 0) + 1
    return dict(sorted(summary.items()))


def classify_file_exposure(file_path: str | Path) -> str:
    """Classify a source file into an exposure class:
    - TEST: test suites, specs, fixtures, mocks
    - TOOLCHAIN_BUILD: build scripts, tooling, configs, linters, packaging
    - RUNTIME_BUNDLE: frontend client code (React, Vue, browser scripts)
    - RUNTIME_SERVER: backend server runtime (FastAPI, Flask, Express, etc.)
    - UNKNOWN: uncategorized
    """
    p_str = str(file_path).replace("\\", "/").lower().strip()
    while p_str.startswith("./"):
        p_str = p_str[2:]

    parts = [part.lower() for part in Path(p_str).parts]
    filename = Path(p_str).name.lower()

    # Test directories and test files
    test_dirs = {"tests", "test", "__tests__", "testing", "spec", "specs", "fixtures", "test_fixtures", "mocks", "mock"}
    if any(d in test_dirs for d in parts):
        return TEST
    if filename.startswith("test_") or filename.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts", ".test.jsx", ".test.tsx")):
        return TEST

    # Deployment / infra / migration scripts (production execution environment)
    deploy_keywords = {"deploy", "release", "prod", "production", "migrate", "migration", "provision", "infra", "terraform", "k8s", "helm"}
    if any(k in filename.lower() or any(k in part.lower() for part in parts) for k in deploy_keywords):
        if any(d in {"scripts", "tools", "tasks", "infra", "deploy", "ci"} for d in parts):
            return RUNTIME_SERVER

    # Toolchain / build / scripts
    toolchain_dirs = {"scripts", "tools", "tooling", "build", "tasks", ".github", ".husky"}
    if any(d in toolchain_dirs for d in parts):
        return TOOLCHAIN_BUILD
    if filename in (
        "webpack.config.js", "vite.config.js", "vite.config.ts", "rollup.config.js",
        "setup.py", "conftest.py", "makefile", "dockerfile", "docker-compose.yml",
        "docker-compose.yaml", "package.json", "package-lock.json", "requirements.txt",
        "pyproject.toml", "tsconfig.json", "babel.config.js", ".eslintrc.js"
    ) or filename.endswith((".config.js", ".config.ts", ".config.mjs", ".config.json")):
        return TOOLCHAIN_BUILD

    # Documentation
    doc_dirs = {"docs", "doc", "documentation"}
    if any(d in doc_dirs for d in parts):
        return TOOLCHAIN_BUILD

    # Client frontend bundle
    client_dirs = {"frontend", "client", "ui", "public", "static"}
    if any(d in client_dirs for d in parts):
        return RUNTIME_BUNDLE
    if any(p_str.startswith(f"{d}/") for d in ("src/components", "src/pages", "src/views")):
        return RUNTIME_BUNDLE

    # Server backend runtime
    server_dirs = {"backend", "server", "api", "routes", "controllers", "services", "models"}
    if any(d in server_dirs for d in parts):
        return RUNTIME_SERVER
    if filename in ("main.py", "app.py", "server.js", "index.js"):
        return RUNTIME_SERVER

    return UNKNOWN
