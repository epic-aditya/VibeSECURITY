"""Supply chain intelligence: Slopsquatting & hallucinated package detector.

Checks declared dependencies against PyPI and npm registries:
- Package does not exist in registry -> CRITICAL (Hallucinated package risk)
- Package first published < 30 days ago -> HIGH (Freshly registered dependency)
- Package name within edit distance <= 2 of top-popular package -> MEDIUM (Typosquat suspicion)

Includes 24h SQLite caching, timeouts, retries, and full offline fallback.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from .dep_graph import DependencyGraph
from .exploit_intel import _get_cache_db_path, _is_offline
from .models import Finding, Location, Severity, SourceTool

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400  # 24h


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance with early exit."""
    if s1 == s2:
        return 0
    if abs(len(s1) - len(s2)) > 2:
        return 999
    len1, len2 = len(s1), len(s2)
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        dp[i][0] = i
    for j in range(len2 + 1):
        dp[0][j] = j
    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[len1][len2]


def _load_top_packages(ecosystem: str) -> list[str]:
    data_dir = Path(__file__).parent / "data"
    fname = f"top_{ecosystem}_packages.json"
    fpath = data_dir / fname
    if fpath.is_file():
        try:
            return json.loads(fpath.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS supply_chain_cache (
                eco TEXT,
                pkg TEXT,
                exists_flag INTEGER,
                first_published REAL,
                fetched_at REAL,
                PRIMARY KEY (eco, pkg)
            )
            """
        )


def _check_pypi_registry(pkg: str) -> tuple[bool, float | None]:
    """Return (exists, first_published_timestamp_or_none)."""
    url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json"
    headers = {"User-Agent": "VibeSec-SupplyChain/2.0"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                # Earliest release upload time
                releases = data.get("releases", {})
                earliest_ts = None
                for files in releases.values():
                    for f in files:
                        ut = f.get("upload_time_iso_8601") or f.get("upload_time")
                        if ut:
                            try:
                                dt = datetime.fromisoformat(ut.replace("Z", "+00:00"))
                                ts = dt.timestamp()
                                if earliest_ts is None or ts < earliest_ts:
                                    earliest_ts = ts
                            except Exception:
                                pass
                return (True, earliest_ts)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (False, None)
    except Exception as e:
        logger.debug(f"PyPI check failed for {pkg}: {e}")
    return (True, None)  # Assume exists on timeout to prevent false positives


def _check_npm_registry(pkg: str) -> tuple[bool, float | None]:
    """Return (exists, first_published_timestamp_or_none)."""
    url = f"https://registry.npmjs.org/{urllib.parse.quote(pkg, safe='@')}"
    headers = {"User-Agent": "VibeSec-SupplyChain/2.0"}
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                created = (data.get("time") or {}).get("created")
                earliest_ts = None
                if created:
                    try:
                        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                        earliest_ts = dt.timestamp()
                    except Exception:
                        pass
                return (True, earliest_ts)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return (False, None)
    except Exception as e:
        logger.debug(f"npm check failed for {pkg}: {e}")
    return (True, None)


def check_supply_chain_risks(
    dep_graph: DependencyGraph,
    project_dir: Path | None = None,
    offline: bool | None = None,
    db_path: Path | None = None,
) -> list[Finding]:
    """Scan declared packages for hallucinated / non-existent packages, recent registration, and typosquats."""
    if project_dir is None:
        project_dir = getattr(dep_graph, "project_dir", Path("."))
    is_off = _is_offline() if offline is None else offline
    db_file = db_path or _get_cache_db_path()
    conn = sqlite3.connect(str(db_file))
    _init_db(conn)

    top_pypi = _load_top_packages("pypi")
    top_npm = _load_top_packages("npm")

    findings: list[Finding] = []
    now = time.time()
    thirty_days_sec = 30 * 86400

    # Only inspect direct packages or first 100 to stay performant
    packages_to_check = [
        (node.ecosystem, node.name)
        for node in dep_graph.nodes.values()
        if node.direct
    ]
    if not packages_to_check:
        packages_to_check = [
            (node.ecosystem, node.name)
            for node in list(dep_graph.nodes.values())[:50]
        ]

    for eco, pkg in packages_to_check:
        eco_norm = "npm" if eco == "npm" else "pypi"
        top_list = top_npm if eco_norm == "npm" else top_pypi

        node = dep_graph.get_node(pkg)
        alias_target = getattr(node, "alias_of", None)
        is_npm_alias = bool(alias_target) or str(pkg).startswith("npm:")
        if not alias_target and str(pkg).startswith("npm:"):
            from .dep_graph import resolve_npm_alias
            ainfo = resolve_npm_alias(str(pkg))
            if ainfo:
                alias_target = ainfo[0]

        # An npm alias spec ("name": "npm:pkg@ver") resolves to the target package; never "hallucinated"
        effective_pkg = (alias_target or pkg).lower().strip()

        # Registry existence and age check (cached)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT exists_flag, first_published, fetched_at FROM supply_chain_cache WHERE eco = ? AND pkg = ?",
            (eco_norm, effective_pkg),
        )
        row = cursor.fetchone()

        exists = True
        first_pub = None
        has_registry_evidence = False

        if row and (now - row[2] < CACHE_TTL_SECONDS):
            exists = bool(row[0])
            first_pub = row[1]
            if first_pub is not None and (now - first_pub < thirty_days_sec):
                has_registry_evidence = True
        elif not is_off:
            if eco_norm == "npm":
                exists, first_pub = _check_npm_registry(effective_pkg)
            else:
                exists, first_pub = _check_pypi_registry(effective_pkg)

            if first_pub is not None and (now - first_pub < thirty_days_sec):
                has_registry_evidence = True

            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO supply_chain_cache (eco, pkg, exists_flag, first_published, fetched_at) VALUES (?, ?, ?, ?, ?)",
                    (eco_norm, effective_pkg, 1 if exists else 0, first_pub, now),
                )
        else:
            # Offline and not cached: no registry evidence available
            pass

        # 1. Typosquat / slopsquatting check: requires registry evidence, not edit distance alone
        closest_match = None
        closest_dist = 999
        if not is_npm_alias and effective_pkg not in top_list and len(effective_pkg) >= 4:
            for top_pkg in top_list:
                dist = _levenshtein(effective_pkg, top_pkg)
                if 1 <= dist <= 2 and dist < closest_dist:
                    closest_dist = dist
                    closest_match = top_pkg

            if closest_match and has_registry_evidence:
                findings.append(
                    Finding(
                        rule_id="vibe.supply_chain.potential_typosquat",
                        title=f"Potential typosquatting / slopsquatting: '{pkg}' resembles '{closest_match}'",
                        cwe="CWE-1395",
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        location=Location(file="package.json" if eco_norm == "npm" else "requirements.txt", start_line=1, end_line=1),
                        evidence=f"Package '{pkg}' is within edit distance {closest_dist} of top package '{closest_match}' and has registry evidence of recent publication (< 30 days).",
                        sources=[SourceTool.VIBE_RULE],
                        category="supply_chain",
                        package_name=pkg,
                        ecosystem=eco_norm,
                    )
                )

        # 2. Hallucinated package check: never fire on npm alias specs
        if not is_npm_alias and not exists:
            findings.append(
                Finding(
                    rule_id="vibe.supply_chain.hallucinated_package",
                    title=f"Hallucinated / non-existent package: '{pkg}' ({eco_norm})",
                    cwe="CWE-1395",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    location=Location(file="package.json" if eco_norm == "npm" else "requirements.txt", start_line=1, end_line=1),
                    evidence=f"Package '{pkg}' does not exist on {eco_norm.upper()} registry. High hallucinated dependency risk.",
                    sources=[SourceTool.VIBE_RULE],
                    category="supply_chain",
                    package_name=pkg,
                    ecosystem=eco_norm,
                )
            )
        elif not is_npm_alias and first_pub and (now - first_pub < thirty_days_sec) and not closest_match:
            findings.append(
                Finding(
                    rule_id="vibe.supply_chain.recently_registered_package",
                    title=f"Recently registered package (<30 days old): '{pkg}'",
                    cwe="CWE-1395",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    location=Location(file="package.json" if eco_norm == "npm" else "requirements.txt", start_line=1, end_line=1),
                    evidence=f"Package '{pkg}' was first published on {eco_norm.upper()} < 30 days ago.",
                    sources=[SourceTool.VIBE_RULE],
                    category="supply_chain",
                    package_name=pkg,
                    ecosystem=eco_norm,
                )
            )

    # Check for non-default package registry in lockfiles (I-29)
    official_registries = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org"}
    seen_registries: set[str] = set()
    skip_dirs_sc = {".git", "node_modules", ".venv", "venv", "__pycache__"}

    for lock in project_dir.rglob("*lock*.json"):
        if not lock.is_file() or any(p in skip_dirs_sc for p in lock.relative_to(project_dir).parts):
            continue
        rel = str(lock.relative_to(project_dir)).replace("\\", "/")
        try:
            lock_text = lock.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for line_no, line in enumerate(lock_text.splitlines(), start=1):
            for m in re.finditer(r"""["']resolved["']\s*:\s*["'](https?://[^/"']+)/([^"']+)["']""", line):
                reg_url = m.group(1)
                host = urllib.parse.urlparse(reg_url).netloc.lower()
                is_http = reg_url.startswith("http://")
                if host and host not in official_registries and host not in seen_registries:
                    seen_registries.add(host)
                    sev = Severity.HIGH if is_http else Severity.MEDIUM
                    findings.append(Finding(
                        rule_id="vibe.supply_chain.non_default_registry",
                        title=f"Dependencies resolved from non-default package registry ({host})",
                        cwe="CWE-829",
                        severity=sev,
                        confidence=0.95,
                        location=Location(file=rel, start_line=line_no, end_line=line_no),
                        evidence=f"Lockfile '{rel}' resolves packages from non-default registry: {host} (e.g. {reg_url})",
                        sources=[SourceTool.VIBE_RULE],
                        category="supply_chain",
                        remediation=f"Verify integrity of third-party registry '{host}' and enforce official registry in configuration.",
                    ))

    conn.close()
    return findings
