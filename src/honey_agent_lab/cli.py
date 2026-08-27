from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AppendOnlyAuditLedger
from .dashboard import render_static_dashboard
from .fuzz_report import render_fuzz_report
from .fuzzer import Fuzzer
from .orchestrator import run_scenario
from .risk import RiskScorer
from .rule_loader import load_rules
from .scenarios import list_scenarios


def _load_optional_rules(path: Path | None):
    return load_rules(path) if path is not None else None


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Honey Agent Lab defensive scenario runner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("list-scenarios", help="List available synthetic scenarios")

    run_parser = subcommands.add_parser("run-scenario", help="Run a synthetic scenario")
    run_parser.add_argument("name")
    run_parser.add_argument("--json", action="store_true")
    run_parser.add_argument("--verbose", action="store_true")
    run_parser.add_argument("--rules", type=Path)
    run_parser.add_argument("--export-audit", type=Path)
    run_parser.add_argument("--output-html", type=Path)

    verify_parser = subcommands.add_parser("verify-audit", help="Verify an exported audit JSONL file")
    verify_parser.add_argument("path", type=Path)

    fuzz_parser = subcommands.add_parser("fuzz", help="Run deterministic synthetic coverage fuzzing")
    fuzz_parser.add_argument("--limit", type=int, default=100)
    fuzz_parser.add_argument("--seed", type=int, default=42)
    fuzz_parser.add_argument("--max-fragments", type=int, default=3)
    fuzz_parser.add_argument("--obfuscation-prob", type=float, default=0.3)
    fuzz_parser.add_argument("--json", action="store_true")
    fuzz_parser.add_argument("--rules", type=Path)
    fuzz_parser.add_argument("--output-html", type=Path)

    serve_parser = subcommands.add_parser("serve", help="Start the optional local FastAPI service")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--allow-remote", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list-scenarios":
        for scenario in list_scenarios():
            print(f"{scenario.name}: {scenario.description}")
        return 0
    if args.command == "verify-audit":
        try:
            ledger = AppendOnlyAuditLedger.read_jsonl(args.path)
        except (OSError, ValueError) as exc:
            print(f"Audit verification failed: {exc}", file=sys.stderr)
            return 1
        ok = ledger.verify_integrity()
        print(f"Audit integrity: {ok}")
        return 0 if ok else 1
    if args.command == "run-scenario":
        try:
            result = run_scenario(args.name, scorer=RiskScorer(_load_optional_rules(args.rules)))
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.export_audit:
            print(f"Audit ledger written: {result.write_audit(args.export_audit)}", file=sys.stderr)
        if args.output_html:
            args.output_html.parent.mkdir(parents=True, exist_ok=True)
            args.output_html.write_text(render_static_dashboard(result), encoding="utf-8")
            print(f"Dashboard written: {args.output_html}", file=sys.stderr)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return 0
        assessment, decision = result.final_assessment, result.final_decision
        print(f"Scenario: {result.scenario.name}")
        print(f"Risk: {assessment.severity.value} / {assessment.total_score}")
        print(f"Action: {decision.action.value}")
        print(f"Reason: {decision.reason}")
        print("Controls:")
        for control in decision.controls:
            print(f"- {control}")
        if args.verbose:
            print("Findings:")
            for finding in assessment.findings:
                print(f"- {finding.code}: {finding.severity.value} +{finding.score} — {finding.evidence}")
        print(f"Audit integrity: {result.ledger.verify_integrity()}")
        return 0
    if args.command == "fuzz":
        try:
            summary = Fuzzer(
                args.seed,
                _load_optional_rules(args.rules),
                max_fragments=args.max_fragments,
                obfuscation_probability=args.obfuscation_prob,
            ).run(args.limit)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.output_html:
            args.output_html.parent.mkdir(parents=True, exist_ok=True)
            args.output_html.write_text(render_fuzz_report(summary), encoding="utf-8")
            print(f"Fuzz report written: {args.output_html}", file=sys.stderr)
        if args.json:
            print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
            return 0
        print(f"Synthetic messages: {summary.total_messages}")
        print(f"Obfuscated messages: {summary.obfuscated_messages}")
        print(f"Actions: {summary.action_counts}")
        print(f"Severities: {summary.severity_counts}")
        print(f"Signals: {summary.triggered_codes}")
        print(f"Potential false negatives: {len(summary.potential_false_negatives)}")
        return 0
    if args.command == "serve":
        if not _is_loopback(args.host) and not args.allow_remote:
            print("Refusing non-loopback bind without --allow-remote.", file=sys.stderr)
            return 2
        if not _is_loopback(args.host):
            print("WARNING: remote bind explicitly enabled; API has no authentication and must remain in a trusted lab network.", file=sys.stderr)
        try:
            import uvicorn
        except ImportError:
            print("API dependencies missing. Install with: pip install -e '.[api]'", file=sys.stderr)
            return 2
        uvicorn.run("honey_agent_lab.api:app", host=args.host, port=args.port)
        return 0
    return 2
