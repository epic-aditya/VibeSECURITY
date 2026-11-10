"""VibeSec CLI — scan, doctor, list, show, bench, demo.

Supports:
- vibesec scan (--dir, --pdf, --markdown, --sarif, --sbom, --offline, --fail-on)
- vibesec doctor (diagnose external tools)
- vibesec demo (scan bundled demo application)
- vibesec bench (run evaluation benchmark)
- vibesec list, show
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from vibesec import pipeline, storage
from vibesec.models import Severity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vibesec",
        description="VibeSec — Automated Security Assessment Platform for AI-Generated Applications"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # --- scan ---
    scan = sub.add_parser("scan", help="Scan a ZIP, local directory, or GitHub repo")
    scan.add_argument("--zip", type=Path, help="Path to ZIP archive")
    scan.add_argument("--dir", type=Path, help="Path to local directory to scan")
    scan.add_argument("--path", type=Path, help="Path to local directory to scan (alias for --dir)")
    scan.add_argument("--github", help="https://github.com/owner/repo")
    scan.add_argument("--explain", action="store_true", help="Enable LLM explanations (needs API key)")
    scan.add_argument("--pdf", type=Path, help="Write PDF report to this path")
    scan.add_argument("--json", action="store_true", help="Print findings as JSON")
    scan.add_argument("--sarif", type=Path, help="Write SARIF report to this path")
    scan.add_argument("--markdown", type=Path, help="Write Markdown report to this path")
    scan.add_argument("--sbom", type=Path, help="Write CycloneDX JSON SBOM to this path")
    scan.add_argument("--fix-plan", action="store_true", help="Print ordered FixAction dependency upgrade plan")
    scan.add_argument(
        "--min-reachability",
        choices=["CALLED", "IMPORTED", "TRANSITIVE_OF_RUNTIME", "TOOLCHAIN", "NOT_IMPORTED"],
        help="Filter findings by minimum reachability level",
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit with code 1 if any unsuppressed finding at or above this severity exists (CI gate)",
    )
    scan.add_argument("--output", type=Path, help="Directory for all output files")

    # --- asm ---
    asm = sub.add_parser("asm", help="Print the Application Security Model as JSON")
    asm.add_argument("--scan", type=int, help="Scan ID (defaults to latest stored scan)")
    asm.add_argument("--dir", type=Path, help="Scan a local directory instead of stored history")

    # --- paths ---
    paths = sub.add_parser("paths", help="Print ranked attack paths as JSON")
    paths.add_argument("--scan", type=int, help="Scan ID (defaults to latest stored scan)")
    paths.add_argument("--dir", type=Path, help="Scan a local directory instead of stored history")

    # --- bench ---
    sub.add_parser("bench", help="Run evaluation benchmark")

    # --- list ---
    sub.add_parser("list", help="List past scans")

    # --- show ---
    show = sub.add_parser("show", help="Show findings for a past scan")
    show.add_argument("scan_id", type=int)

    # --- clear ---
    clear_p = sub.add_parser("clear", help="Clear past scan history from local storage")
    clear_p.add_argument("--yes", "-y", action="store_true", help="Confirm deletion without prompting")

    # --- doctor ---
    sub.add_parser("doctor", help="Check installed scanner tools, versions, and installation hints")

    # --- demo ---
    demo = sub.add_parser("demo", help="Scan bundled demo app and generate PDF and Markdown reports")
    demo.add_argument("--output", type=Path, default=Path("build/demo"), help="Output directory for reports")

    args = parser.parse_args(argv)

    if args.cmd == "clear":
        return _handle_clear(args)
    if args.cmd == "doctor":
        return _handle_doctor()
    if args.cmd == "demo":
        return _handle_demo(args)
    if args.cmd == "scan":
        return _handle_scan(args)
    if args.cmd == "asm":
        return _handle_asm(args, paths_only=False)
    if args.cmd == "paths":
        return _handle_asm(args, paths_only=True)
    if args.cmd == "bench":
        return _handle_bench()
    if args.cmd == "list":
        return _handle_list()
    if args.cmd == "show":
        return _handle_show(args)
    return 0


def _handle_doctor() -> int:
    from .scanners.base import find_executable, get_tool_version
    tools = [
        ("semgrep", "pip install semgrep or brew install semgrep"),
        ("gitleaks", "brew install gitleaks or choco install gitleaks / download binary"),
        ("trivy", "brew install trivy or choco install trivy / download binary"),
        ("bandit", "pip install bandit"),
        ("pip-audit", "pip install pip-audit"),
        ("npm", "install Node.js from https://nodejs.org/"),
    ]
    print("VibeSec Doctor — Scanner Toolchain Audit\n")
    print(f"  {'Tool':<12} {'Installed':<12} {'Version':<14} {'Install Hint'}")
    print("  " + "-" * 70)
    for name, hint in tools:
        exe = find_executable(name)
        installed = "YES" if exe else "NO"
        ver = get_tool_version(name) or "-"
        print(f"  {name:<12} {installed:<12} {ver:<14} {hint if not exe else ''}")
    print()
    return 0


def _handle_demo(args) -> int:
    print("Demo fixtures are not bundled in this production release. Use 'vibesec scan --dir <path>' to scan your application.")
    return 0


def _handle_scan(args) -> int:
    if getattr(args, "path", None) and not args.dir:
        args.dir = args.path

    if not args.zip and not args.github and not args.dir:
        print("error: one of --zip, --dir, or --github is required", file=sys.stderr)
        return 1

    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        if not args.pdf:
            args.pdf = out_dir / "vibesec-security-report.pdf"
        if not args.sarif:
            args.sarif = out_dir / "vibesec.sarif"
        if not args.html:
            args.html = out_dir / "vibesec-report.html"
        if not args.csv:
            args.csv = out_dir / "vibesec-findings.csv"
        if not args.markdown:
            args.markdown = out_dir / "vibesec-report.md"
        if not args.sbom:
            args.sbom = out_dir / "vibesec-cyclonedx-sbom.json"

    try:
        result = pipeline.run_pipeline(
            zip_path=args.zip,
            github_url=args.github,
            dir_path=args.dir,
            explain=args.explain,
            pdf_path=args.pdf,
            min_reachability=args.min_reachability,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Scan #{result.scan_id} — {result.target_name}")
    print(
        f"Profile: {len(result.profile.get('languages', {}))} languages, "
        f"{len(result.profile.get('frameworks', []))} frameworks, "
        f"{result.profile.get('file_count', 0)} files"
    )
    posture_stmt = getattr(result, "risk_posture", "")
    if not posture_stmt and result.asm and getattr(result.asm, "posture", None):
        posture_stmt = result.asm.posture.risk_posture_statement
    if not posture_stmt:
        from vibesec.prioritizer import calculate_risk_posture
        posture_stmt, _ = calculate_risk_posture(result.findings, asm=result.asm, coverage=result.coverage)
    if posture_stmt:
        print(f"\nRisk Posture: {posture_stmt}")

    if result.asm:
        posture = result.asm.posture
        print(
            f"Counts: {len(result.findings)} findings ({posture.actionable_findings} actionable, "
            f"{posture.deprioritized_findings} deprioritized) | {posture.reachable_attack_paths} attack paths | "
            f"{posture.public_routes} public routes"
        )
        if result.asm.attack_paths:
            print("\nTop Attack Paths:")
            for idx, p in enumerate(result.asm.attack_paths[:3], start=1):
                print(f"  {idx}. [{p.sink_class.upper()}] {p.method} {p.route} (Auth: {p.auth_state}, Score: {p.score:.1f})")
                print(f"     Source: {p.source} -> Sink: {p.sink}")
                if p.poc_curl:
                    print(f"     PoC: {p.poc_curl[:100]}...")

    if getattr(result, "tool_statuses", None):
        print("\nTool Status:")
        print(f"  {'Tool':<12} {'Version':<10} {'Status':<10} {'Reason'}")
        print("  " + "-" * 55)
        for ts in result.tool_statuses:
            ver = ts.version or "-"
            st_val = ts.state.value if hasattr(ts.state, "value") else str(ts.state)
            print(f"  {ts.name:<12} {ver:<10} {st_val:<10} {ts.reason}")
    elif result.warnings:
        for w in result.warnings:
            print(f"  warning: {w}")

    # FixAction summary
    if result.fix_actions:
        actionable_actions = [a for a in result.fix_actions if (a.exposure_class or "").startswith("RUNTIME") or a.reachability in ("CALLED", "IMPORTED", "TRANSITIVE_OF_RUNTIME")]
        print(f"\nDependency Fix Plan ({len(actionable_actions)} actionable runtime package upgrades):")
        for idx, act in enumerate((actionable_actions or result.fix_actions)[:5], start=1):
            print(f"  {idx}. {act.summary()}")

    # Output exports
    if args.sarif:
        from vibesec.sarif import export_sarif
        export_sarif(result.findings, args.sarif, attack_paths=result.asm.attack_paths if result.asm else None)
        print(f"SARIF: {args.sarif}")

    asm_dict = result.asm.to_dict() if result.asm else None
    export_meta = {"offline": result.offline, "warnings": result.warnings}

    if args.markdown:
        from vibesec.exports import export_markdown
        export_markdown(
            result.findings, result.profile, result.target_name, args.markdown,
            fix_actions=result.fix_actions, metadata=export_meta, asm=asm_dict,
        )
        print(f"Markdown: {args.markdown}")

    if args.sbom and result.sbom:
        args.sbom.parent.mkdir(parents=True, exist_ok=True)
        args.sbom.write_text(json.dumps(result.sbom, indent=2), encoding="utf-8")
        print(f"SBOM (CycloneDX): {args.sbom}")

    if args.json:
        print(json.dumps([f.to_dict() for f in result.findings], indent=2))
    elif not args.fix_plan:
        print("\nTop Code & Config Findings:")
        top_code = [f for f in result.findings if f.category in ("code", "config", "secret")][:10]
        for f in top_code:
            owasp_str = ",".join(f.owasp_categories) if f.owasp_categories else ""
            print(
                f"  [{f.risk_bucket.value}] {f.rule_id} {f.location.file}:{f.location.start_line} "
                f"({f.cwe}{' ' + owasp_str if owasp_str else ''}) score={f.risk_score}"
            )

    # CI Gate check
    if args.fail_on:
        crit_sinks = {"command_execution", "code_execution", "sql_injection"}
        if args.fail_on.lower() in ("critical_path", "path"):
            unauth_crit_paths = [
                p for p in (result.asm.attack_paths if result.asm else [])
                if p.auth_state == "PUBLIC" and p.sink_class in crit_sinks
            ]
            if unauth_crit_paths:
                print(
                    f"\nCI GATE FAILED: {len(unauth_crit_paths)} unauthenticated attack path(s) reach critical sinks!",
                    file=sys.stderr,
                )
                return 1
        elif args.fail_on.upper() in Severity.__members__:
            threshold = Severity(args.fail_on.upper())
            failing = [f for f in result.findings if f.risk_bucket.rank >= threshold.rank and not f.suppressed]
            if failing:
                print(
                    f"\nCI GATE FAILED: {len(failing)} unsuppressed finding(s) at or above {args.fail_on.upper()}",
                    file=sys.stderr,
                )
                return 1

    return 0


def _handle_asm(args, paths_only: bool) -> int:
    asm_data: dict = {}
    if args.dir:
        try:
            result = pipeline.run_pipeline(dir_path=args.dir)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        asm_data = result.asm.to_dict() if result.asm else {}
    else:
        scan_id = args.scan
        if scan_id is None:
            scans = storage.list_scans()
            if not scans:
                print("No stored scans. Run `vibesec scan --dir <path>` first.", file=sys.stderr)
                return 1
            scan_id = scans[0]["id"]
        loaded = storage.load_scan(scan_id)
        if loaded is None:
            print(f"Scan #{scan_id} not found", file=sys.stderr)
            return 1
        asm_data = loaded.get("asm") or {}

    payload = asm_data.get("attack_paths", []) if paths_only else asm_data
    print(json.dumps(payload, indent=2))
    return 0


def _handle_bench() -> int:
    """Execute vibesec bench command."""
    print("Benchmark suite is not bundled in this production release.")
    return 0


def _handle_list() -> int:
    for s in storage.list_scans():
        print(f"{s['id']}\t{s['target_source']}\t{s['created_at']}")
    return 0


def _handle_clear(args) -> int:
    scans = storage.list_scans()
    if not scans:
        print("No scan history found in local storage.")
        return 0
    if not args.yes:
        try:
            resp = input(f"Are you sure you want to delete all {len(scans)} scan record(s) from local storage? (y/N): ")
            if resp.lower() not in ("y", "yes"):
                print("Operation cancelled.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return 0
    count = storage.clear_scans()
    print(f"Successfully cleared {count} scan record(s) from local storage.")
    return 0


def _handle_show(args) -> int:
    s = storage.load_scan(args.scan_id)
    if not s:
        print("Scan not found", file=sys.stderr)
        return 1
    print(json.dumps(s, indent=2))
    return 0


def main_argv(argv: list[str]) -> int:
    """Helper for testing or programmatic invocation with full command tokens."""
    if argv and (argv[0] == "vibesec" or argv[0].endswith(".py")):
        argv = argv[1:]
    return main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
