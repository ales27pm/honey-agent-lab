from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .orchestrator import run_scenario
from .scenarios import list_scenarios


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Honey Agent Lab defensive scenario runner")
    subcommands = parser.add_subparsers(dest="command", required=True)

    subcommands.add_parser("list-scenarios", help="List available synthetic scenarios")

    run_parser = subcommands.add_parser("run-scenario", help="Run a synthetic scenario")
    run_parser.add_argument("name", help="Scenario name, e.g. scenario_001")
    run_parser.add_argument("--json", action="store_true", help="Print full JSON result")
    run_parser.add_argument("--export-audit", type=Path, help="Write append-only audit ledger as JSONL")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "list-scenarios":
        for scenario in list_scenarios():
            print(f"{scenario.name}: {scenario.description}")
        return 0

    if args.command == "run-scenario":
        result = run_scenario(args.name)
        if args.export_audit:
            path = result.write_audit(args.export_audit)
            print(f"Audit ledger written: {path}", file=sys.stderr)

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
        print(f"Audit integrity: {result.ledger.verify_integrity()}")
        return 0

    return 2
