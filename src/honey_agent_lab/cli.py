from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from . import __version__
from .audit import AppendOnlyAuditLedger
from .dashboard import render_static_dashboard
from .fuzzer import Fuzzer
from .orchestrator import run_scenario
from .risk import RiskScorer
from .rule_loader import load_rules
from .scenarios import list_scenarios

def _rules(path): return load_rules(path) if path else None

def build_parser():
    p=argparse.ArgumentParser(description="Honey Agent Lab defensive scenario runner");p.add_argument("--version",action="version",version=f"%(prog)s {__version__}");s=p.add_subparsers(dest="command",required=True)
    s.add_parser("list-scenarios")
    r=s.add_parser("run-scenario");r.add_argument("name");r.add_argument("--json",action="store_true");r.add_argument("--verbose",action="store_true");r.add_argument("--rules",type=Path);r.add_argument("--export-audit",type=Path);r.add_argument("--output-html",type=Path)
    v=s.add_parser("verify-audit");v.add_argument("path",type=Path)
    f=s.add_parser("fuzz");f.add_argument("--limit",type=int,default=100);f.add_argument("--seed",type=int,default=42);f.add_argument("--json",action="store_true");f.add_argument("--rules",type=Path)
    return p

def main(argv=None):
    args=build_parser().parse_args(argv)
    if args.command=="list-scenarios":
        for x in list_scenarios(): print(f"{x.name}: {x.description}")
        return 0
    if args.command=="verify-audit":
        try:l=AppendOnlyAuditLedger.read_jsonl(args.path)
        except (OSError,ValueError) as exc:print(f"Audit verification failed: {exc}",file=sys.stderr);return 1
        ok=l.verify_integrity();print(f"Audit integrity: {ok}");return 0 if ok else 1
    if args.command=="run-scenario":
        try: result=run_scenario(args.name,scorer=RiskScorer(_rules(args.rules)))
        except (ValueError,OSError) as exc:print(str(exc),file=sys.stderr);return 2
        if args.export_audit: print(f"Audit ledger written: {result.write_audit(args.export_audit)}",file=sys.stderr)
        if args.output_html: args.output_html.parent.mkdir(parents=True,exist_ok=True);args.output_html.write_text(render_static_dashboard(result),encoding="utf-8");print(f"Dashboard written: {args.output_html}",file=sys.stderr)
        if args.json: print(json.dumps(result.to_dict(),indent=2,sort_keys=True));return 0
        a=result.final_assessment;d=result.final_decision;print(f"Scenario: {result.scenario.name}\nRisk: {a.severity.value} / {a.total_score}\nAction: {d.action.value}\nReason: {d.reason}\nControls:")
        for c in d.controls: print(f"- {c}")
        if args.verbose:
            print("Findings:")
            for f in a.findings: print(f"- {f.code}: {f.severity.value} +{f.score} — {f.evidence}")
        print(f"Audit integrity: {result.ledger.verify_integrity()}");return 0
    if args.command=="fuzz":
        try: summary=Fuzzer(args.seed,_rules(args.rules)).run(args.limit)
        except ValueError as exc: print(str(exc),file=sys.stderr);return 2
        if args.json: print(json.dumps(summary.to_dict(),indent=2,sort_keys=True));return 0
        print(f"Synthetic messages: {summary.total_messages}\nActions: {summary.action_counts}\nSeverities: {summary.severity_counts}\nSignals: {summary.triggered_codes}\nPotential false negatives: {len(summary.potential_false_negatives)}");return 0
    return 2
