from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AppendOnlyAuditLedger
from .dashboard import render_static_dashboard
from .orchestrator import run_scenario
from .scenarios import list_scenarios


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Honey Agent Lab defensive scenario runner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("list-scenarios", help="List available synthetic scenarios")

    run_parser = subcommands.add_parser("run-scenario", help="Run a synthetic scenario")
    run_parser.add_argument("name", help="Scenario name, e.g. scenario_001")
    run_parser.add_argument("--json", action="store_true", help="Print full JSON result")
    run_parser.add_argument("--verbose", action="store_true", help="Print all triggered risk findings")
    run_parser.add_argument("--export-audit", type=Path, help="Write audit ledger as JSONL")
    run_parser.add_argument("--output-html", type=Path, help="Write a static local HTML dashboard")

    verify_parser = subcommands.add_parser("verify-audit", help="Verify a previously exported audit JSONL file")
    verify_parser.add_argument("path", type=Path)
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
            result = run_scenario(args.name)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.export_audit:
            path = result.write_audit(args.export_audit)
            print(f"Audit ledger written: {path}", file=sys.stderr)
        if args.output_html:
            args.output_html.parent.mkdir(parents=True, exist_ok=True)
            args.output_html.write_text(render_static_dashboard(result), encoding="utf-8")
            print(f"Dashboard written: {args.output_html}", file=sys.stderr)

        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
            return 0

        final = result.final_decision
        assessment = result.final_assessment
        print(f"Scenario: {result.scenario.name}")
        print(f"Risk: {assessment.severity.value} / {assessment.total_score}")
        print(f"Action: {final.action.value}")
        print(f"Reason: {final.reason}")
        print("Controls:")
        for control in final.controls:
            print(f"- {control}")
        if args.verbose:
            print("Findings:")
            for finding in assessment.findings:
                print(f"- {finding.code}: {finding.severity.value} +{finding.score} — {finding.evidence}")
        print(f"Audit integrity: {result.ledger.verify_integrity()}")
        return 0

    return 2
