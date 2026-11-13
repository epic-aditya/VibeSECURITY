"""Static import discovery shared by reachability and exposure classification.

Read-only: parses source text/AST, never imports or executes scanned code.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from .extractor import MAX_FILE_BYTES

SKIP_DIRS = {
    "node_modules", "tests", "test", "__tests__", ".git", ".venv", "venv", "env",
    "build", "dist", ".next", "out", "__pycache__", ".pytest_cache", ".eggs",
    ".tox", "coverage", "vendor",
}

CONFIG_FILE_PATTERNS = [
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
    re.compile(r"craco\.config\..*", re.I),
]

STDLIB_MODULES: set[str] = {
    "os", "sys", "re", "math", "time", "datetime", "json", "pathlib", "collections",
    "itertools", "functools", "typing", "subprocess", "hashlib", "shutil", "tempfile",
    "unittest", "logging", "io", "copy", "socket", "http", "urllib", "sqlite3", "base64",
    "threading", "multiprocessing", "asyncio", "dataclasses", "enum", "inspect", "importlib",
    "traceback", "uuid", "warnings", "platform", "glob", "shlex", "ast", "contextlib",
    "csv", "statistics", "secrets", "hmac", "ssl", "email", "smtplib", "ftplib",
    "xml", "html", "webbrowser", "argparse", "getpass", "zipfile", "tarfile", "gzip",
}

BUILTIN_PY_IMPORT_TO_DIST: dict[str, str] = {
    "yaml": "pyyaml",
    "pil": "pillow",
    "jwt": "pyjwt",
    "cv2": "opencv-python",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "dotenv": "python-dotenv",
    "dateutil": "python-dateutil",
    "crypto": "pycryptodome",
    "cryptography": "cryptography",
    "sqlalchemy": "sqlalchemy",
    "pydantic": "pydantic",
    "fastapi": "fastapi",
    "flask": "flask",
    "requests": "requests",
    "pytest": "pytest",
    "starlette": "starlette",
    "jinja2": "jinja2",
    "werkzeug": "werkzeug",
    "click": "click",
    "semgrep": "semgrep",
    "bandit": "bandit",
    "reportlab": "reportlab",
    "matplotlib": "matplotlib",
    "uvicorn": "uvicorn",
    "gunicorn": "gunicorn",
    "pymongo": "pymongo",
    "psycopg2": "psycopg2",
    "redis": "redis",
    "openai": "openai",
    "anthropic": "anthropic",
    "langchain": "langchain",
}

_JS_IMPORT_PATTERNS = [
    re.compile(
        r"""(?:import\s+(?:(?:[\w*\s{},$]+)\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"]+)['"]"""
    ),
]


@dataclass
class SourceImports:
    python: dict[str, list[str]] = field(default_factory=dict)
    javascript: dict[str, list[str]] = field(default_factory=dict)
    config: dict[str, list[str]] = field(default_factory=dict)

    @property
    def all_packages(self) -> set[str]:
        return set(self.python) | set(self.javascript) | set(self.config)


def py_import_to_dist() -> dict[str, str]:
    mapping = dict(BUILTIN_PY_IMPORT_TO_DIST)
    try:
        import importlib.metadata

        if hasattr(importlib.metadata, "packages_distributions"):
            for imp, dists in importlib.metadata.packages_distributions().items():
                if dists:
                    mapping[imp.lower()] = dists[0].lower()
    except Exception:
        pass
    return mapping


def extract_js_package_name(specifier: str) -> str | None:
    spec = specifier.strip()
    if not spec or spec.startswith(".") or spec.startswith("/"):
        return None
    if spec.startswith("node:"):
        return None
    if spec.startswith("@"):
        parts = spec.split("/")
        return f"{parts[0]}/{parts[1]}".lower() if len(parts) >= 2 else spec.lower()
    return spec.split("/")[0].lower()


def is_config_file(rel_path: Path) -> bool:
    name = rel_path.name.lower()
    return any(p.match(name) for p in CONFIG_FILE_PATTERNS)


def iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part.lower() in SKIP_DIRS for part in rel.parts[:-1]):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        yield path, rel


def _add(bucket: dict[str, list[str]], pkg: str, evidence: str) -> None:
    ev = bucket.setdefault(pkg, [])
    if len(ev) < 3 and evidence not in ev:
        ev.append(evidence)


def collect_imports(root: Path) -> SourceImports:
    out = SourceImports()
    import_to_dist = py_import_to_dist()

    for path, rel in iter_source_files(root):
        rel_str = str(rel).replace("\\", "/")
        ext = path.suffix.lower()
        config = is_config_file(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if ext == ".py":
            try:
                tree = ast.parse(text, filename=str(path))
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split(".")[0].lower()
                        if mod in STDLIB_MODULES:
                            continue
                        pkg = import_to_dist.get(mod, mod)
                        _add(out.python, pkg, f"{rel_str}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    mod = node.module.split(".")[0].lower()
                    if mod in STDLIB_MODULES:
                        continue
                    pkg = import_to_dist.get(mod, mod)
                    _add(out.python, pkg, f"{rel_str}:{node.lineno}")

        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            for idx, line in enumerate(text.splitlines(), start=1):
                for pat in _JS_IMPORT_PATTERNS:
                    for match in pat.finditer(line):
                        pkg_str = extract_js_package_name(match.group(1))
                        if pkg_str:
                            _add(out.config if config else out.javascript, pkg_str, f"{rel_str}:{idx}")

    return out
