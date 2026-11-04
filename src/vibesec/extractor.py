"""Stage 2 — Project Extractor + Profiler.

Unzips / shallow-clones into an isolated temp folder and profiles the project
by file inspection ONLY. The target project is never built or executed
(plan Section 2.3: dropping DAST is a deliberate security decision).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

GITHUB_URL_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", "dist", "build", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "vendor", ".idea", ".vscode",
}

MAX_FILE_BYTES = 1_000_000  # never read giant files into memory during profiling

# Resource guards for uploaded archives (prevents ZIP bombs / disk exhaustion).
MAX_ARCHIVE_MEMBERS = 50_000
MAX_UNCOMPRESSED_BYTES = 1_000_000_000  # 1 GB


@dataclass
class ProjectProfile:
    root: Path
    languages: dict[str, int] = field(default_factory=dict)  # ext -> file count
    frameworks: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    file_count: int = 0
    app_type: str = "library"  # server | cli | library | frontend

    def to_dict(self) -> dict:
        return {
            "languages": self.languages,
            "frameworks": self.frameworks,
            "entry_points": self.entry_points,
            "dependency_files": self.dependency_files,
            "file_count": self.file_count,
            "app_type": self.app_type,
        }


class ExtractionError(Exception):
    pass


def extract_zip(zip_path: str | Path, dest: Path) -> Path:
    """Safely extract a ZIP upload, rejecting path-traversal entries, drive letters, and symlinks."""
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        members = zf.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ExtractionError(
                f"Archive rejected: {len(members)} entries exceeds the {MAX_ARCHIVE_MEMBERS} entry limit."
            )
        total_uncompressed = sum(m.file_size for m in members)
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise ExtractionError(
                "Archive rejected: uncompressed size "
                f"({total_uncompressed} bytes) exceeds the {MAX_UNCOMPRESSED_BYTES} byte limit."
            )
        for member in members:
            filename = member.filename.replace("\\", "/")
            # Reject absolute paths or Windows drive letters (e.g. C:/ or C:)
            if filename.startswith("/") or (len(filename) > 1 and filename[1] == ":"):
                raise ExtractionError(f"Unsafe archive entry rejected (absolute/drive path): {member.filename}")
            # Reject directory traversal components
            parts = Path(filename).parts
            if any(p in ("..", "/", "\\") for p in parts):
                raise ExtractionError(f"Unsafe archive entry rejected (traversal): {member.filename}")
            # Reject symlinks (external_attr high byte = 0o120000)
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ExtractionError(f"Unsafe archive entry rejected (symlink): {member.filename}")
            # Verify resolved target remains strictly within dest directory
            target_path = (dest / filename).resolve()
            try:
                target_path.relative_to(dest)
            except ValueError:
                raise ExtractionError(
                    f"Unsafe archive entry rejected (escapes target): {member.filename}"
                ) from None

        # Safe extraction
        zf.extractall(dest)

    # If the archive wrapped everything in a single top-level dir, descend into it.
    entries = [p for p in dest.iterdir() if p.name not in {".git", "__MACOSX"}]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def clone_github(url: str, dest: Path) -> Path:
    """Shallow, read-only clone of a public GitHub repository."""
    match = GITHUB_URL_RE.match(url.strip())
    if not match:
        raise ExtractionError("Only public https://github.com/<owner>/<repo> URLs are supported.")
    dest.mkdir(parents=True, exist_ok=True)
    repo_dest = (dest / "repo").resolve()
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", "--", url.strip(), str(repo_dest)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise ExtractionError(f"git clone failed: {result.stderr.strip()[:300]}")
    return repo_dest



_FRAMEWORK_MARKERS: dict[str, list[str]] = {
    "flask": ["flask"],
    "fastapi": ["fastapi"],
    "django": ["django"],
    "express": ["\"express\"", "'express'"],
    "nestjs": ["@nestjs/"],
}

_ENTRY_FILES = {
    "app.py", "main.py", "server.py", "application.py", "wsgi.py", "asgi.py",
    "index.js", "server.js", "app.js", "index.ts", "server.ts", "app.ts",
}

_DEP_FILES = {
    "requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}

_EXT_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
}


def profile_project(root: Path) -> ProjectProfile:
    """Detect languages, frameworks, and entry points by file inspection only."""
    profile = ProjectProfile(root=root)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue

        profile.file_count += 1
        ext = path.suffix.lower()
        if ext in _EXT_LANG:
            lang = _EXT_LANG[ext]
            profile.languages[lang] = profile.languages.get(lang, 0) + 1

        rel = str(path.relative_to(root)).replace("\\", "/")
        if path.name in _DEP_FILES:
            profile.dependency_files.append(rel)
        if path.name in _ENTRY_FILES:
            profile.entry_points.append(rel)

        # Framework detection: dependency manifests + imports in Python files.
        if path.name in {"requirements.txt", "pyproject.toml"} or ext == ".py":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for framework, markers in _FRAMEWORK_MARKERS.items():
                if framework in profile.frameworks:
                    continue
                if any(m in text for m in markers):
                    profile.frameworks.append(framework)
        elif path.name == "package.json":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for framework in ("express", "nestjs"):
                if framework not in profile.frameworks and any(
                    m in text for m in _FRAMEWORK_MARKERS[framework]
                ):
                    profile.frameworks.append(framework)

    profile.entry_points.sort()
    profile.dependency_files.sort()

    # Determine application type: server, cli, or library
    server_fws = {"fastapi", "flask", "express", "nestjs", "django", "fastify", "koa", "tornado", "sanic", "aiohttp"}
    cli_markers = {"click", "argparse", "typer", "commander", "yargs", "caporal", "oclif"}
    frontend_fws = {"react", "vue", "angular", "svelte", "solid", "vite", "preact"}

    has_server = any(fw.lower() in server_fws for fw in profile.frameworks)
    has_cli = any(fw.lower() in cli_markers for fw in profile.frameworks)
    has_frontend = any(fw.lower() in frontend_fws for fw in profile.frameworks)

    if not has_frontend:
        if (root / "index.html").is_file() or (root / "public" / "index.html").is_file() or (root / "src" / "index.html").is_file():
            has_frontend = True
        elif (root / "vite.config.js").is_file() or (root / "vite.config.ts").is_file() or (root / "webpack.config.js").is_file():
            has_frontend = True

    # Check package.json for "bin"
    pj_path = root / "package.json"
    if pj_path.is_file():
        try:
            pj_content = pj_path.read_text(encoding="utf-8", errors="ignore")
            if '"bin"' in pj_content:
                has_cli = True
        except Exception:
            pass

    # Check python manifests for scripts
    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        try:
            pyproject_content = pyproject_path.read_text(encoding="utf-8", errors="ignore")
            if "project.scripts" in pyproject_content or "console_scripts" in pyproject_content:
                has_cli = True
        except Exception:
            pass

    if any(ep.endswith("cli.py") or "/bin/" in ep.replace("\\", "/") for ep in profile.entry_points):
        has_cli = True

    if has_server:
        profile.app_type = "server"
    elif has_frontend:
        profile.app_type = "frontend"
    elif has_cli:
        profile.app_type = "cli"
    else:
        profile.app_type = "library"

    return profile


def cleanup(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def make_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="vibesec-"))
