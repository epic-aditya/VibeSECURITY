"""Reachability analysis v2 (exposure-aware).

Statuses:
- CALLED                    imported in source and a symbol/namespace is used
- IMPORTED                  imported in runtime source
- TRANSITIVE_OF_RUNTIME     not imported directly but reachable from a runtime root
- TOOLCHAIN                 build/dev-server/test only (does not reach production)
- NOT_IMPORTED              declared but no import and no runtime path
- UNKNOWN                   could not be determined

The status is derived from the dependency graph, source imports, and the
exposure classifier. If UNKNOWN exceeds 20% of graph packages, a warning is
recorded and the lockfile graph result is used as the fallback.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .dep_graph import DependencyGraph, build_project_dependency_graph
from .exposure import (
    RUNTIME_CLASSES,
    ExposureInfo,
    classify_exposure,
)
from .exposure import (
    UNKNOWN as EXPOSURE_UNKNOWN,
)
from .imports import (
    BUILTIN_PY_IMPORT_TO_DIST,
    STDLIB_MODULES,
    collect_imports,
    extract_js_package_name,
    is_config_file,
    iter_source_files,
)

_CONFIG_FILE_PATTERNS = [
    re.compile(r"webpack\..*", re.I),
    re.compile(r"babel\..*", re.I),
    re.compile(r"\.babelrc.*", re.I),
    re.compile(r"postcss\..*", re.I),
    re.compile(r"vite\.config\..*", re.I),
    re.compile(r"rollup\.config\..*", re.I),
    re.compile(r"tsconfig.*\.json", re.I),
    re.compile(r"eslint.*", re.I),
    re.compile(r"prettier.*", re.I),
    re.compile(r"jest\.config\..*", re.I),
    re.compile(r"next\.config\..*", re.I),
    re.compile(r"tailwind\.config\..*", re.I),
]

_SKIP_DIRS = {
    "node_modules", "tests", "test", "__tests__", ".git", ".venv", "venv", "env",
    "build", "dist", ".next", "out", "__pycache__", ".pytest_cache", ".eggs",
}


@dataclass
class UsageInfo:
    package_name: str
    status: str = "NOT_IMPORTED"
    evidence: list[str] = field(default_factory=list)
    is_called: bool = False
    in_config: bool = False
    scope: str = "prod"
    exposure_class: str = EXPOSURE_UNKNOWN
    evidence_chain: list[str] = field(default_factory=list)
    origin: str = ""  # py | js | config
    direct: bool = False

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "status": self.status,
            "evidence": list(self.evidence),
            "is_called": self.is_called,
            "in_config": self.in_config,
            "scope": self.scope,
            "exposure_class": self.exposure_class,
            "evidence_chain": list(self.evidence_chain),
            "origin": self.origin,
            "direct": self.direct,
        }

    @classmethod
    def from_dict(cls, d: dict) -> UsageInfo:
        return cls(
            package_name=d.get("package_name", ""),
            status=d.get("status", "NOT_IMPORTED"),
            evidence=d.get("evidence", []) or [],
            is_called=bool(d.get("is_called", False)),
            in_config=bool(d.get("in_config", False)),
            scope=d.get("scope", "prod"),
            exposure_class=d.get("exposure_class", EXPOSURE_UNKNOWN),
            evidence_chain=d.get("evidence_chain", []) or [],
            origin=d.get("origin", ""),
            direct=bool(d.get("direct", False)),
        )


class ReachabilityMap:
    VALID_STATUSES = {
        "CALLED", "IMPORTED", "TRANSITIVE_OF_RUNTIME", "TOOLCHAIN",
        "NOT_IMPORTED", "UNKNOWN",
    }

    def __init__(self, usages: dict[str, UsageInfo] | None = None, warnings: list[str] | None = None):
        self.usages: dict[str, UsageInfo] = usages or {}
        self.warnings: list[str] = warnings or []

    @property
    def package_usage(self) -> dict[str, UsageInfo]:
        return self.usages

    def to_dict(self) -> dict:
        return {
            "usages": {k: v.to_dict() for k, v in self.usages.items()},
            "warnings": list(self.warnings),
        }

    @classmethod
    def from_dict(cls, d: dict) -> ReachabilityMap:
        raw = d.get("usages", {}) or {}
        usages = {k: UsageInfo.from_dict(v) if isinstance(v, dict) else v for k, v in raw.items()}
        return cls(usages, list(d.get("warnings") or []))

    def get_status(self, package_name: str) -> str:
        pkg = package_name.lower().strip()
        if pkg in self.usages:
            return self.usages[pkg].status
        for k, info in self.usages.items():
            if k == pkg or k.split("/")[-1] == pkg or pkg.split("/")[-1] == k:
                return info.status
        return "UNKNOWN"

    def get_evidence(self, package_name: str) -> list[str]:
        pkg = package_name.lower().strip()
        if pkg in self.usages:
            return self.usages[pkg].evidence[:3]
        for k, info in self.usages.items():
            if k == pkg or k.split("/")[-1] == pkg or pkg.split("/")[-1] == k:
                return info.evidence[:3]
        return []

    def get_exposure(self, package_name: str, file_path: str | None = None) -> ExposureInfo | None:
        pkg = package_name.lower().strip()
        if file_path:
            norm_fp = file_path.replace("\\", "/")
            ws = norm_fp.split("/")[0] if "/" in norm_fp else ""
            if ws:
                ws_key = f"{ws}/{pkg}"
                if ws_key in self.usages:
                    info = self.usages[ws_key]
                    return ExposureInfo(
                        package_name=info.package_name,
                        exposure_class=info.exposure_class,
                        evidence_chain=info.evidence_chain,
                    )
        usage_info: UsageInfo | None = self.usages.get(pkg)
        if usage_info is None:
            for k, cand in self.usages.items():
                if k == pkg or k.split("/")[-1] == pkg or pkg.split("/")[-1] == k:
                    usage_info = cand
                    break
        if usage_info is None:
            return None
        return ExposureInfo(
            package_name=usage_info.package_name,
            exposure_class=usage_info.exposure_class,
            evidence_chain=usage_info.evidence_chain,
        )


def _is_config_file(rel_path: Path) -> bool:
    name = rel_path.name.lower()
    return any(p.match(name) for p in _CONFIG_FILE_PATTERNS)


def analyze_reachability(root: Path, dep_graph: DependencyGraph | None = None) -> ReachabilityMap:
    if dep_graph is None:
        dep_graph = build_project_dependency_graph(root)

    imports = collect_imports(root)
    exposures = classify_exposure(root, dep_graph, imports)

    usages: dict[str, UsageInfo] = {}
    for pkg, node in dep_graph.nodes.items():
        exp = exposures.get(pkg.lower().strip())
        usages[pkg] = UsageInfo(
            package_name=pkg,
            scope=node.scope,
            direct=node.direct,
            exposure_class=exp.exposure_class if exp else EXPOSURE_UNKNOWN,
            evidence_chain=exp.evidence_chain if exp else [],
        )

    for ws_k, exp in exposures.items():
        if "/" in ws_k and ws_k not in usages:
            usages[ws_k] = UsageInfo(
                package_name=exp.package_name,
                scope="prod" if exp.exposure_class in RUNTIME_CLASSES else "dev",
                direct=True,
                exposure_class=exp.exposure_class,
                evidence_chain=exp.evidence_chain,
            )

    # Read npm scripts so build tools referenced only there are recognized.
    pkg_json = root / "package.json"
    scripts_text = ""
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            scripts_text = " ".join(str(v) for v in data.get("scripts", {}).values()).lower()
        except Exception:
            scripts_text = ""
    for pkg, info in usages.items():
        short = pkg.split("/")[-1]
        if scripts_text and re.search(rf"\b{re.escape(short)}\b", scripts_text):
            info.in_config = True
            info.evidence.append("package.json:scripts")

    has_source_files = False
    import_to_dist = dict(BUILTIN_PY_IMPORT_TO_DIST)

    for path, rel in iter_source_files(root):
        ext = path.suffix.lower()
        is_config = is_config_file(rel) or _is_config_file(rel)
        if ext == ".py":
            has_source_files = True
            _analyze_python_file(path, rel, usages, import_to_dist, is_config)
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            has_source_files = True
            _analyze_js_file(path, rel, usages, is_config)

    # Ensure imports outside the lockfile still appear (evidence providers differ).
    for pkg in imports.all_packages:
        usages.setdefault(pkg, UsageInfo(package_name=pkg, exposure_class=(
            "RUNTIME_BUNDLE" if pkg in imports.javascript else "RUNTIME_SERVER" if pkg in imports.python else "TOOLCHAIN_BUILD"
        )))
        usages[pkg].evidence_chain = usages[pkg].evidence_chain or [pkg]
        usages[pkg].origin = "js" if pkg in imports.javascript else "py" if pkg in imports.python else "config"

    warnings: list[str] = []
    graph_packages = 0
    unknown_packages = 0
    for info in usages.values():
        exp_cls = info.exposure_class
        if info.is_called:
            info.status = "CALLED"
        elif info.evidence and not info.in_config:
            info.status = "IMPORTED"
        elif exp_cls in ("TOOLCHAIN_BUILD", "TOOLCHAIN_DEVSERVER", "TEST"):
            info.status = "TOOLCHAIN"
        elif exp_cls in RUNTIME_CLASSES and not info.direct:
            info.status = "TRANSITIVE_OF_RUNTIME"
        elif not has_source_files:
            info.status = "UNKNOWN"
        else:
            info.status = "NOT_IMPORTED"


        if info.package_name in dep_graph.nodes:
            graph_packages += 1
            if info.status == "UNKNOWN":
                unknown_packages += 1

    if graph_packages and unknown_packages / graph_packages > 0.20:
        warnings.append(
            f"Reachability fallback: {unknown_packages}/{graph_packages} packages UNKNOWN "
            "(>20%); using lockfile graph exposure with reduced confidence."
        )

    return ReachabilityMap(usages, warnings)


def _analyze_python_file(
    file_path: Path,
    rel_path: Path,
    usages: dict[str, UsageInfo],
    import_to_dist: dict[str, str],
    is_config: bool,
) -> None:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(content, filename=str(file_path))
    except Exception:
        return

    rel_str = str(rel_path).replace("\\", "/")
    imported_names: dict[str, tuple[str, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_module = alias.name.split(".")[0].lower()
                if root_module in STDLIB_MODULES:
                    continue
                imported_names[alias.asname or alias.name.split(".")[0]] = (
                    import_to_dist.get(root_module, root_module), node.lineno,
                )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            root_module = node.module.split(".")[0].lower()
            if root_module in STDLIB_MODULES:
                continue
            dist = import_to_dist.get(root_module, root_module)
            for alias in node.names:
                imported_names[alias.asname or alias.name] = (dist, node.lineno)

    referenced: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            referenced.add(node.value.id)
            called.add(node.value.id)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                called.add(node.func.value.id)

    for local_name, (dist_name, line) in imported_names.items():
        info = usages.setdefault(dist_name, UsageInfo(package_name=dist_name))
        info.origin = "py"
        ev = f"{rel_str}:{line}"
        if len(info.evidence) < 3 and ev not in info.evidence:
            info.evidence.append(ev)
        if is_config:
            info.in_config = True
        elif local_name in called or local_name in referenced:
            info.is_called = True


_JS_IMPORT_PATTERNS = [
    re.compile(
        r"""(?:import\s+(?:(?:[\w*\s{},$]+)\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]"""
    ),
]


def _analyze_js_file(
    file_path: Path,
    rel_path: Path,
    usages: dict[str, UsageInfo],
    is_config: bool,
) -> None:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    rel_str = str(rel_path).replace("\\", "/")
    for idx, line in enumerate(content.splitlines(), start=1):
        for pat in _JS_IMPORT_PATTERNS:
            for match in pat.finditer(line):
                pkg = extract_js_package_name(match.group(1))
                if not pkg:
                    continue
                info = usages.setdefault(pkg, UsageInfo(package_name=pkg))
                info.origin = info.origin or ("config" if is_config else "js")
                ev = f"{rel_str}:{idx}"
                if len(info.evidence) < 3 and ev not in info.evidence:
                    info.evidence.append(ev)
                if is_config:
                    info.in_config = True
                else:
                    short = pkg.split("/")[-1]
                    if re.search(rf"\b{re.escape(short)}\b\s*[\(\.\[]", content):
                        info.is_called = True
