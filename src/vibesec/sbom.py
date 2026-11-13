"""SBOM (Software Bill of Materials) generation module (CycloneDX v1.5 format).

Parses Python and Node.js dependency manifests, sets component scope
(required/optional/excluded) from prod/dev, and adds a vulnerabilities section
with VEX-compliant reachability analysis (code_not_reachable for NOT_IMPORTED).
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .dep_graph import DependencyGraph, build_project_dependency_graph
from .models import Finding


def _parse_requirements_txt(content: str, dep_graph: DependencyGraph | None = None) -> list[dict]:
    components = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[=~><!]+([a-zA-Z0-9_\-\.]+))?", line)
        if match:
            name, version = match.group(1).lower().strip(), match.group(2) or "unknown"
            scope = dep_graph.get_scope(name) if dep_graph else "prod"
            cdx_scope = "required" if scope == "prod" else ("optional" if scope == "optional" else "excluded")
            comp: dict = {
                "type": "library",
                "name": name,
                "version": version,
                "scope": cdx_scope,
                "purl": f"pkg:pypi/{name}@{version}" if version != "unknown" else f"pkg:pypi/{name}",
                "bom-ref": f"pkg:pypi/{name}@{version}",
            }
            # Extract lockfile integrity hash if present in --hash flag
            match_hash = re.search(r"--hash=(sha256|sha384|sha512):([a-fA-F0-9]+)", line)
            if match_hash:
                alg_name = match_hash.group(1).upper()
                alg_map = {"SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512"}
                comp["hashes"] = [{"alg": alg_map[alg_name], "content": match_hash.group(2).lower()}]
            components.append(comp)
    return components


def _parse_package_lock_json(content: str, dep_graph: DependencyGraph | None = None) -> list[dict]:
    components = []
    try:
        data = json.loads(content)
        packages = data.get("packages", {})
        if packages:
            for pkg_path, info in packages.items():
                if not pkg_path or pkg_path == "":
                    continue
                name = pkg_path.split("node_modules/")[-1].lower().strip()
                version = info.get("version", "unknown")
                scope = dep_graph.get_scope(name) if dep_graph else ("dev" if info.get("dev") else "prod")
                cdx_scope = "required" if scope == "prod" else ("optional" if scope == "optional" else "excluded")
                comp: dict = {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "scope": cdx_scope,
                    "purl": f"pkg:npm/{name}@{version}",
                    "bom-ref": f"pkg:npm/{name}@{version}",
                }
                integrity = info.get("integrity")
                if integrity and isinstance(integrity, str) and "-" in integrity:
                    alg_raw, b64_hash = integrity.split("-", 1)
                    alg_map = {
                        "sha512": "SHA-512",
                        "sha384": "SHA-384",
                        "sha256": "SHA-256",
                        "sha1": "SHA-1",
                    }
                    if alg_raw.lower() in alg_map:
                        try:
                            b64_clean = b64_hash.split("?")[0].strip()
                            raw_bytes = base64.b64decode(b64_clean)
                            comp["hashes"] = [
                                {
                                    "alg": alg_map[alg_raw.lower()],
                                    "content": raw_bytes.hex(),
                                }
                            ]
                        except Exception:
                            pass
                lic = info.get("license")
                if lic:
                    comp["licenses"] = [{"license": {"name": str(lic)}}]
                components.append(comp)
        else:
            deps = data.get("dependencies", {})
            for name_raw, info in deps.items():
                name = name_raw.lower().strip()
                version = info.get("version", "unknown")
                scope = dep_graph.get_scope(name) if dep_graph else ("dev" if info.get("dev") else "prod")
                cdx_scope = "required" if scope == "prod" else ("optional" if scope == "optional" else "excluded")
                comp = {
                    "type": "library",
                    "name": name,
                    "version": version,
                    "scope": cdx_scope,
                    "purl": f"pkg:npm/{name}@{version}",
                    "bom-ref": f"pkg:npm/{name}@{version}",
                }
                integrity = info.get("integrity")
                if integrity and isinstance(integrity, str) and "-" in integrity:
                    alg_raw, b64_hash = integrity.split("-", 1)
                    alg_map = {
                        "sha512": "SHA-512",
                        "sha384": "SHA-384",
                        "sha256": "SHA-256",
                        "sha1": "SHA-1",
                    }
                    if alg_raw.lower() in alg_map:
                        try:
                            b64_clean = b64_hash.split("?")[0].strip()
                            raw_bytes = base64.b64decode(b64_clean)
                            comp["hashes"] = [
                                {
                                    "alg": alg_map[alg_raw.lower()],
                                    "content": raw_bytes.hex(),
                                }
                            ]
                        except Exception:
                            pass
                lic = info.get("license")
                if lic:
                    comp["licenses"] = [{"license": {"name": str(lic)}}]
                components.append(comp)
    except Exception:
        pass
    return components


def _parse_package_json(content: str, dep_graph: DependencyGraph | None = None) -> list[dict]:
    components = []
    try:
        data = json.loads(content)
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for name_raw, ver in deps.items():
            name = name_raw.lower().strip()
            clean_ver = re.sub(r"^[\^~>=<]+", "", ver) or "unknown"
            scope = dep_graph.get_scope(name) if dep_graph else "prod"
            cdx_scope = "required" if scope == "prod" else ("optional" if scope == "optional" else "excluded")
            components.append({
                "type": "library",
                "name": name,
                "version": clean_ver,
                "scope": cdx_scope,
                "purl": f"pkg:npm/{name}@{clean_ver}",
                "bom-ref": f"pkg:npm/{name}@{clean_ver}",
            })
    except Exception:
        pass
    return components


def generate_sbom(
    project_dir: Path,
    project_name: str = "project",
    findings: list[Finding] | None = None,
    dep_graph: DependencyGraph | None = None,
) -> dict:
    """Generate CycloneDX v1.5 JSON SBOM from project manifests with component scope and VEX vulnerabilities."""
    if dep_graph is None:
        dep_graph = build_project_dependency_graph(project_dir)

    components: list[dict] = []
    seen: set[str] = set()

    _SKIP = {"node_modules", ".git", ".venv", "venv", "dist", "build"}

    # Python manifests anywhere in project tree
    for req_file in project_dir.rglob("*requirement*.txt"):
        if any(part.lower() in _SKIP for part in req_file.relative_to(project_dir).parts[:-1]):
            continue
        try:
            for c in _parse_requirements_txt(req_file.read_text(encoding="utf-8", errors="replace"), dep_graph):
                key = f"{c['name']}@{c['version']}"
                if key not in seen:
                    seen.add(key)
                    components.append(c)
        except Exception:
            pass

    # Node manifests anywhere in project tree
    for pkg_lock in project_dir.rglob("package-lock.json"):
        if any(part.lower() in _SKIP for part in pkg_lock.relative_to(project_dir).parts[:-1]):
            continue
        try:
            for c in _parse_package_lock_json(pkg_lock.read_text(encoding="utf-8", errors="replace"), dep_graph):
                key = f"{c['name']}@{c['version']}"
                if key not in seen:
                    seen.add(key)
                    components.append(c)
        except Exception:
            pass

    for pkg_json in project_dir.rglob("package.json"):
        if any(part.lower() in _SKIP for part in pkg_json.relative_to(project_dir).parts[:-1]):
            continue
        if (pkg_json.parent / "package-lock.json").is_file():
            continue
        try:
            for c in _parse_package_json(pkg_json.read_text(encoding="utf-8", errors="replace"), dep_graph):
                key = f"{c['name']}@{c['version']}"
                if key not in seen:
                    seen.add(key)
                    components.append(c)
        except Exception:
            pass

    # Build CycloneDX v1.5 JSON structure
    root_ref = f"pkg:generic/{project_name}@1.0.0"
    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [
                {
                    "vendor": "VibeSec",
                    "name": "VibeSec SBOM Engine",
                    "version": "2.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project_name,
                "version": "1.0.0",
            },
        },
        "components": components,
    }

    # Add vulnerabilities section with reachability analysis if findings provided
    if findings:
        vuln_list = []
        bom_refs = {c["bom-ref"] for c in components}
        comp_by_name = {c["name"]: c["bom-ref"] for c in components}

        for f in findings:
            if f.category != "dependency":
                continue
            vuln_id = f.aliases[0] if f.aliases else f.rule_id
            eco = f.ecosystem or "npm"
            reach = f.reachability or "UNKNOWN"
            exp_cls = f.exposure_class or "UNKNOWN"

            # Phase 8: NOT_IMPORTED is never not_affected (cannot prove non-exploitability statically).
            # Mark CALLED as exploitable; everything else as in_triage with reachability taxonomy properties.
            if reach == "CALLED":
                state = "exploitable"
                justification = None
            else:
                state = "in_triage"
                justification = None

            analysis = {
                "state": state,
                "detail": f"Exposure: {exp_cls}, Reachability: {reach}, Scope: {f.scope}, EPSS: {f.epss_score}",
            }
            if justification:
                analysis["justification"] = justification

            ver = f.package_version if (f.package_version and f.package_version != "?") else "unknown"
            pkg_norm = (f.package_name or "unknown").lower().strip()
            exact_ref = f"pkg:{eco}/{pkg_norm}@{ver}"
            if exact_ref in bom_refs:
                affects_ref = exact_ref
            elif pkg_norm in comp_by_name:
                affects_ref = comp_by_name[pkg_norm]
            else:
                affects_ref = exact_ref
                components.append({
                    "type": "library",
                    "name": pkg_norm,
                    "version": ver,
                    "scope": "required" if exp_cls.startswith("RUNTIME") else "excluded",
                    "purl": exact_ref,
                    "bom-ref": exact_ref,
                })
                bom_refs.add(exact_ref)
                comp_by_name[pkg_norm] = exact_ref

            vuln_props = [
                {"name": "vibesec:reachability", "value": str(reach)},
                {"name": "vibesec:exposure_class", "value": str(exp_cls)},
                {"name": "vibesec:scope", "value": str(f.scope or "prod")},
            ]

            vuln_item = {
                "bom-ref": f"vuln-{vuln_id}",
                "id": vuln_id,
                "source": {"name": "NVD" if vuln_id.startswith("CVE-") else "GHSA"},
                "ratings": [
                    {
                        "score": f.risk_score,
                        "severity": f.severity.value.lower() if hasattr(f.severity, "value") else "info",
                        "method": "other",
                    }
                ],
                "affects": [
                    {
                        "ref": affects_ref,
                    }
                ],
                "analysis": analysis,
                "properties": vuln_props,
            }
            vuln_list.append(vuln_item)

        if vuln_list:
            sbom["vulnerabilities"] = vuln_list

    # Build CycloneDX dependencies graph linking root application to direct and transitive deps
    comp_by_name = {c["name"]: c["bom-ref"] for c in components}
    dep_entries: list[dict] = []
    root_deps: list[str] = []

    for c in components:
        comp_ref = c["bom-ref"]
        comp_name = c["name"]
        dep_node = dep_graph.get_node(comp_name) if dep_graph else None
        if (dep_node and dep_node.direct) or (not dep_node and c.get("scope") == "required"):
            root_deps.append(comp_ref)

        comp_deps: list[str] = []
        if dep_node and dep_node.dependencies:
            for child_name in dep_node.dependencies:
                cn = child_name.lower().strip()
                if cn in comp_by_name and comp_by_name[cn] != comp_ref:
                    comp_deps.append(comp_by_name[cn])

        entry: dict[str, Any] = {"ref": comp_ref}
        if comp_deps:
            entry["dependsOn"] = sorted(list(set(comp_deps)))
        dep_entries.append(entry)

    # Insert root application node
    dep_entries.insert(0, {
        "ref": root_ref,
        "dependsOn": sorted(list(set(root_deps))),
    })
    sbom["dependencies"] = dep_entries

    return sbom


def export_sbom_json(
    project_dir: Path,
    output_file: Path,
    project_name: str = "project",
    findings: list[Finding] | None = None,
    dep_graph: DependencyGraph | None = None,
) -> Path:
    """Generate and write CycloneDX JSON to output_file."""
    sbom = generate_sbom(project_dir, project_name=project_name, findings=findings, dep_graph=dep_graph)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return output_file
