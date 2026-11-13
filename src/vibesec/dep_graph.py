"""Dependency graph parsing and scope propagation for Python and JavaScript.

Supports:
- npm: package.json, package-lock.json (v1, v2, v3), yarn.lock (best-effort)
- python: requirements.txt, pyproject.toml (PEP 621 and Poetry)

Propagates scope:
Direct: prod | dev | optional
Transitive: prod if reachable from any direct prod dependency; otherwise dev or optional.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DepNode:
    name: str
    version: str = ""
    ecosystem: str = "npm"
    direct: bool = False
    scope: str = "prod"  # "prod" | "dev" | "optional"
    dependencies: list[str] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)
    alias_of: str | None = None

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "direct": self.direct,
            "scope": self.scope,
            "dependencies": list(self.dependencies),
            "dependents": list(self.dependents),
        }
        if self.alias_of:
            d["alias_of"] = self.alias_of
        return d

    @classmethod
    def from_dict(cls, d: dict) -> DepNode:
        return cls(
            name=d.get("name", ""),
            version=d.get("version", ""),
            ecosystem=d.get("ecosystem", "npm"),
            direct=bool(d.get("direct", False)),
            scope=d.get("scope", "prod"),
            dependencies=d.get("dependencies", []) or [],
            dependents=d.get("dependents", []) or [],
            alias_of=d.get("alias_of"),
        )


def resolve_npm_alias(spec: str) -> tuple[str, str] | None:
    """Parse 'npm:target-pkg@^version' -> ('target-pkg', '^version')."""
    if not isinstance(spec, str) or not spec.startswith("npm:"):
        return None
    raw = spec[4:]
    if raw.startswith("@"):
        parts = raw[1:].split("@", 1)
        target_name = "@" + parts[0]
        ver = parts[1] if len(parts) > 1 else ""
    else:
        parts = raw.split("@", 1)
        target_name = parts[0]
        ver = parts[1] if len(parts) > 1 else ""
    return (target_name.lower().strip(), ver.strip())


@dataclass
class DependencyGraph:
    nodes: dict[str, DepNode] = field(default_factory=dict)
    ecosystem: str = "npm"

    def to_dict(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> DependencyGraph:
        raw_nodes = d.get("nodes", {}) or {}
        nodes = {k: DepNode.from_dict(v) if isinstance(v, dict) else v for k, v in raw_nodes.items()}
        return cls(nodes=nodes, ecosystem=d.get("ecosystem", "npm"))

    def get_node(self, name: str) -> DepNode | None:
        n = name.lower().strip()
        if n in self.nodes:
            return self.nodes[n]
        # Check without scope prefix e.g. @org/
        for k, node in self.nodes.items():
            if k == n or k.split("/")[-1] == n or n.split("/")[-1] == k:
                return node
        return None

    def get_scope(self, name: str) -> str:
        node = self.get_node(name)
        return node.scope if node else "prod"

    def is_direct(self, name: str) -> bool:
        node = self.get_node(name)
        return node.direct if node else False


def parse_package_json(path: Path) -> dict[str, str]:
    """Return dict of {package_name: direct_scope} from package.json."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return {}

    direct_scopes: dict[str, str] = {}
    for pkg in data.get("dependencies", {}) or {}:
        direct_scopes[pkg.lower().strip()] = "prod"
    for pkg in data.get("devDependencies", {}) or {}:
        # prod takes precedence if mistakenly in both
        if pkg.lower().strip() not in direct_scopes:
            direct_scopes[pkg.lower().strip()] = "dev"
    for pkg in data.get("optionalDependencies", {}) or {}:
        if pkg.lower().strip() not in direct_scopes:
            direct_scopes[pkg.lower().strip()] = "optional"
    return direct_scopes


def parse_package_lock(lock_path: Path, package_json_path: Path | None = None) -> DependencyGraph:
    """Parse package-lock.json (v1, v2, v3) into a DependencyGraph."""
    graph = DependencyGraph(ecosystem="npm")
    direct_scopes = parse_package_json(package_json_path) if package_json_path else {}

    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return graph

    # v2 and v3 format: "packages"
    if "packages" in data and isinstance(data["packages"], dict):
        packages = data["packages"]
        # Root package
        root_pkg = packages.get("") or {}
        root_deps = root_pkg.get("dependencies", {}) or {}
        root_dev_deps = root_pkg.get("devDependencies", {}) or {}
        root_opt_deps = root_pkg.get("optionalDependencies", {}) or {}

        for k in root_deps:
            direct_scopes[k.lower().strip()] = "prod"
        for k in root_dev_deps:
            if k.lower().strip() not in direct_scopes:
                direct_scopes[k.lower().strip()] = "dev"
        for k in root_opt_deps:
            if k.lower().strip() not in direct_scopes:
                direct_scopes[k.lower().strip()] = "optional"

        for pkg_key, pkg_info in packages.items():
            if not pkg_key or not isinstance(pkg_info, dict):
                continue
            # Extract package name from node_modules path
            # e.g., "node_modules/axios" -> "axios", "node_modules/@babel/core" -> "@babel/core"
            parts = pkg_key.split("node_modules/")
            name = parts[-1].lower().strip()
            if not name:
                continue

            version = pkg_info.get("version", "")
            alias_target = None
            raw_pname = pkg_info.get("name")
            if isinstance(raw_pname, str) and raw_pname.lower() != name:
                alias_target = raw_pname.lower().strip()
            elif isinstance(version, str) and version.startswith("npm:"):
                resolved = resolve_npm_alias(version)
                if resolved:
                    alias_target = resolved[0]
                    version = resolved[1]

            is_dev = bool(pkg_info.get("dev", False))
            is_opt = bool(pkg_info.get("optional", False))
            
            raw_scope = "dev" if is_dev else ("optional" if is_opt else "prod")
            is_direct = name in direct_scopes
            scope = direct_scopes[name] if is_direct else raw_scope

            sub_deps = list((pkg_info.get("dependencies", {}) or {}).keys())
            sub_deps_clean = [d.lower().strip() for d in sub_deps]

            if name not in graph.nodes:
                graph.nodes[name] = DepNode(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    direct=is_direct,
                    scope=scope,
                    dependencies=sub_deps_clean,
                    alias_of=alias_target,
                )
            else:
                # Merge
                node = graph.nodes[name]
                if alias_target and not node.alias_of:
                    node.alias_of = alias_target
                if is_direct:
                    node.direct = True
                    node.scope = direct_scopes[name]
                node.dependencies = list(set(node.dependencies + sub_deps_clean))

    # v1 format or fallback: "dependencies"
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def _walk_v1(deps_dict: dict, parent_name: str | None = None):
            for name_raw, info in deps_dict.items():
                if not isinstance(info, dict):
                    continue
                name = name_raw.lower().strip()
                version = info.get("version", "")
                is_dev = bool(info.get("dev", False))
                is_opt = bool(info.get("optional", False))
                is_direct = name in direct_scopes
                scope = direct_scopes[name] if is_direct else ("dev" if is_dev else ("optional" if is_opt else "prod"))

                if name not in graph.nodes:
                    graph.nodes[name] = DepNode(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        direct=is_direct,
                        scope=scope,
                    )
                if parent_name and parent_name in graph.nodes:
                    graph.nodes[parent_name].dependencies.append(name)

                if "dependencies" in info and isinstance(info["dependencies"], dict):
                    _walk_v1(info["dependencies"], parent_name=name)

        _walk_v1(data["dependencies"])

    _propagate_scopes(graph)
    return graph


def parse_yarn_lock(yarn_path: Path, package_json_path: Path | None = None) -> DependencyGraph:
    """Best-effort parser for yarn.lock."""
    graph = DependencyGraph(ecosystem="npm")
    direct_scopes = parse_package_json(package_json_path) if package_json_path else {}

    try:
        content = yarn_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return graph

    current_pkgs: list[str] = []
    current_version = ""
    current_deps: list[str] = []
    in_deps = False

    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue

        if not line.startswith(" ") and not line.startswith("\t"):
            # Header line: "axios@^0.21.1", "@babel/core@^7.0.0":
            if current_pkgs and current_version:
                for cp in current_pkgs:
                    is_dir = cp in direct_scopes
                    graph.nodes[cp] = DepNode(
                        name=cp,
                        version=current_version,
                        ecosystem="npm",
                        direct=is_dir,
                        scope=direct_scopes.get(cp, "prod"),
                        dependencies=list(current_deps),
                    )
            current_pkgs = []
            current_version = ""
            current_deps = []
            in_deps = False

            raw_names = trimmed.rstrip(":").split(",")
            for rn in raw_names:
                rn_clean = rn.strip().strip('"').strip("'")
                # e.g., @scope/pkg@^1.0.0 or pkg@^1.0.0
                if "@" in rn_clean[1:]:
                    pkg_name = rn_clean[: rn_clean.rfind("@")].lower().strip()
                else:
                    pkg_name = rn_clean.lower().strip()
                if pkg_name not in current_pkgs:
                    current_pkgs.append(pkg_name)
        elif trimmed.startswith("version "):
            current_version = trimmed.split("version ", 1)[-1].strip().strip('"')
        elif trimmed == "dependencies:":
            in_deps = True
        elif in_deps:
            if line.startswith("    ") or line.startswith("\t\t"):
                # Dependency item: foo "1.0.0"
                dep_name = trimmed.split()[0].strip('"').lower()
                current_deps.append(dep_name)
            else:
                in_deps = False

    if current_pkgs and current_version:
        for cp in current_pkgs:
            is_dir = cp in direct_scopes
            graph.nodes[cp] = DepNode(
                name=cp,
                version=current_version,
                ecosystem="npm",
                direct=is_dir,
                scope=direct_scopes.get(cp, "prod"),
                dependencies=list(current_deps),
            )

    _propagate_scopes(graph)
    return graph


def parse_requirements_txt(req_path: Path, scope: str = "prod") -> DependencyGraph:
    """Parse requirements.txt into DependencyGraph."""
    graph = DependencyGraph(ecosystem="pypi")
    try:
        content = req_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return graph

    # Infer dev if file name suggests dev/test
    fname = req_path.name.lower()
    if any(k in fname for k in ("dev", "test", "lint", "ci", "build")):
        scope = "dev"

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i") or line.startswith("-e"):
            continue
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=<>~!]+)(.+))?", line)
        if m:
            pkg_name = m.group(1).lower().strip()
            version = m.group(3).strip() if m.group(3) else ""
            graph.nodes[pkg_name] = DepNode(
                name=pkg_name,
                version=version,
                ecosystem="pypi",
                direct=True,
                scope=scope,
            )
    return graph


def parse_pyproject_toml(pyproject_path: Path) -> DependencyGraph:
    """Parse pyproject.toml (PEP 621 and Poetry) into DependencyGraph."""
    graph = DependencyGraph(ecosystem="pypi")
    try:
        content = pyproject_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return graph

    # Check for tomllib (3.11+) or basic regex parser
    data = None
    try:
        import tomllib  # Python 3.11+
        data = tomllib.loads(content)
    except Exception:
        pass

    if data:
        # PEP 621: [project.dependencies]
        proj = data.get("project", {})
        for dep in proj.get("dependencies", []):
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep)
            if m:
                pname = m.group(1).lower().strip()
                graph.nodes[pname] = DepNode(name=pname, ecosystem="pypi", direct=True, scope="prod")

        # PEP 621: [project.optional-dependencies]
        opt_deps = proj.get("optional-dependencies", {})
        for group, deps in opt_deps.items():
            sc = "dev" if any(k in group.lower() for k in ("dev", "test", "lint")) else "optional"
            for dep in deps:
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep)
                if m:
                    pname = m.group(1).lower().strip()
                    if pname not in graph.nodes:
                        graph.nodes[pname] = DepNode(name=pname, ecosystem="pypi", direct=True, scope=sc)

        # Poetry: [tool.poetry.dependencies]
        poetry = data.get("tool", {}).get("poetry", {})
        for pname in poetry.get("dependencies", {}):
            if pname.lower() == "python":
                continue
            pname = pname.lower().strip()
            graph.nodes[pname] = DepNode(name=pname, ecosystem="pypi", direct=True, scope="prod")

        for pname in poetry.get("dev-dependencies", {}):
            pname = pname.lower().strip()
            if pname not in graph.nodes:
                graph.nodes[pname] = DepNode(name=pname, ecosystem="pypi", direct=True, scope="dev")

        for group_name, group_data in poetry.get("group", {}).items():
            sc = "dev" if "dev" in group_name.lower() or "test" in group_name.lower() else "optional"
            for pname in (group_data.get("dependencies", {}) or {}):
                pname = pname.lower().strip()
                if pname not in graph.nodes:
                    graph.nodes[pname] = DepNode(name=pname, ecosystem="pypi", direct=True, scope=sc)
    else:
        # Fallback regex parser
        in_deps = False
        in_dev = False
        for line in content.splitlines():
            trimmed = line.strip()
            if trimmed.startswith("["):
                in_deps = "dependencies" in trimmed and "dev" not in trimmed
                in_dev = any(k in trimmed for k in ("dev-dependencies", "group.dev", "test"))
                continue
            if (in_deps or in_dev) and "=" in trimmed:
                pname = trimmed.split("=")[0].strip().strip('"').strip("'").lower()
                if pname and pname != "python":
                    graph.nodes[pname] = DepNode(
                        name=pname,
                        ecosystem="pypi",
                        direct=True,
                        scope="dev" if in_dev else "prod",
                    )

    return graph


def _propagate_scopes(graph: DependencyGraph) -> None:
    """Propagate scope: any package reachable from a direct prod package becomes prod."""
    # Build reverse lookup and adjacency
    prod_roots = [n.name for n in graph.nodes.values() if n.direct and n.scope == "prod"]

    queue = list(prod_roots)
    visited: set[str] = set(queue)

    while queue:
        curr = queue.pop(0)
        curr_node = graph.get_node(curr)
        if not curr_node:
            continue
        curr_node.scope = "prod"

        for dep_name in curr_node.dependencies:
            dep_node = graph.get_node(dep_name)
            if dep_node and dep_name not in visited:
                dep_node.scope = "prod"
                visited.add(dep_name)
                queue.append(dep_name)


_MANIFEST_SKIP = {"node_modules", ".git", ".venv", "venv", "env", "dist", "build", ".next", "out", "__pycache__"}


def _merge_graph(target: DependencyGraph, source: DependencyGraph) -> None:
    for name, node in source.nodes.items():
        existing = target.nodes.get(name)
        if existing is None:
            target.nodes[name] = node
            continue
        existing.direct = existing.direct or node.direct
        existing.dependencies = sorted(set(existing.dependencies + node.dependencies))
        if node.direct and node.scope != "prod":
            existing.scope = node.scope
        if node.version and not existing.version:
            existing.version = node.version
        if node.ecosystem and existing.ecosystem != node.ecosystem:
            existing.ecosystem = node.ecosystem


def _iter_manifests(root: Path, filename: str):
    for path in root.rglob(filename):
        if any(part.lower() in _MANIFEST_SKIP for part in path.relative_to(root).parts[:-1]):
            continue
        yield path


def build_project_dependency_graph(root: Path) -> DependencyGraph:
    """Inspect the whole project tree and build a combined DependencyGraph.

    Nested manifests (e.g. frontend/package-lock.json, backend/requirements.txt)
    are discovered so lockfile graph traversal actually works for monorepos.
    """
    graph = DependencyGraph()
    ecosystems: set[str] = set()

    # NPM lockfiles (v1/v2/v3) first; a sibling package.json supplies direct scopes.
    for lock in _iter_manifests(root, "package-lock.json"):
        pj = lock.parent / "package.json"
        npm_graph = parse_package_lock(lock, pj if pj.is_file() else None)
        _merge_graph(graph, npm_graph)
        ecosystems.add("npm")

    for lock in _iter_manifests(root, "yarn.lock"):
        pj = lock.parent / "package.json"
        yarn_graph = parse_yarn_lock(lock, pj if pj.is_file() else None)
        _merge_graph(graph, yarn_graph)
        ecosystems.add("npm")

    lock_dirs = {lock.parent for lock in _iter_manifests(root, "package-lock.json")} | {
        lock.parent for lock in _iter_manifests(root, "yarn.lock")
    }
    for pj in _iter_manifests(root, "package.json"):
        if pj.parent in lock_dirs:
            continue
        direct = parse_package_json(pj)
        try:
            pj_data = json.loads(pj.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pj_data = {}
        alias_map: dict[str, tuple[str, str]] = {}
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            for k_name, v_spec in (pj_data.get(sec, {}) or {}).items():
                if isinstance(v_spec, str) and v_spec.startswith("npm:"):
                    resolved = resolve_npm_alias(v_spec)
                    if resolved:
                        alias_map[k_name.lower().strip()] = resolved

        for k, v in direct.items():
            alias_info = alias_map.get(k)
            alias_target = alias_info[0] if alias_info else None
            alias_ver = alias_info[1] if alias_info else ""
            graph.nodes.setdefault(
                k,
                DepNode(
                    name=k,
                    direct=True,
                    scope=v,
                    ecosystem="npm",
                    alias_of=alias_target,
                    version=alias_ver,
                ),
            )
            graph.nodes[k].direct = True
            if alias_target:
                graph.nodes[k].alias_of = alias_target
                graph.nodes.setdefault(
                    alias_target,
                    DepNode(name=alias_target, direct=True, scope=v, ecosystem="npm", version=alias_ver),
                )
        if direct:
            ecosystems.add("npm")

    # PyPI manifests anywhere in the tree.
    for req_file in _iter_manifests(root, "requirements.txt"):
        _merge_graph(graph, parse_requirements_txt(req_file))
        ecosystems.add("pypi")
    for req_file in root.rglob("*requirement*.txt"):
        if any(part.lower() in _MANIFEST_SKIP for part in req_file.relative_to(root).parts[:-1]):
            continue
        if req_file.name == "requirements.txt":
            continue
        _merge_graph(graph, parse_requirements_txt(req_file))
        ecosystems.add("pypi")
    for pyproject in _iter_manifests(root, "pyproject.toml"):
        _merge_graph(graph, parse_pyproject_toml(pyproject))
        ecosystems.add("pypi")

    if len(ecosystems) > 1:
        graph.ecosystem = "mixed"
    elif ecosystems:
        graph.ecosystem = next(iter(ecosystems))

    return graph
