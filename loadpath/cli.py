"""Command-line entry points."""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .inspect import inspect_artifact
from .inventory import scan
from .receipts import coverage_summary, join, load_receipts
from .report import html_report, terminal
from .rules import RULES, SEVERITIES
from .sarif import to_sarif


def main(argv=None):
    parser = argparse.ArgumentParser(prog="loadpath", description="Audit model loader paths and scanner evidence without loading models.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Inventory Python source and join scanner receipts")
    scan_parser.add_argument("target", type=Path)
    scan_parser.add_argument("--receipts", type=Path)
    scan_parser.add_argument("--artifact-base", type=Path, help="Base for literal paths (default: target directory or file parent)")
    output = scan_parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true")
    output.add_argument("--sarif", action="store_true")
    scan_parser.add_argument("--html", type=Path, help="Also write a self-contained HTML report")
    scan_parser.add_argument("--fail-on", choices=list(SEVERITIES) + ["none"], default="none")
    inspect_parser = sub.add_parser("inspect", help="Inspect format headers and pickle opcodes, never deserialize")
    inspect_parser.add_argument("artifact", type=Path)
    sub.add_parser("rules", help="List loader rules")
    args = parser.parse_args(argv)
    try:
        if args.command == "rules":
            table = Table("Rule", "Name", "Severity", "Summary")
            for rule in RULES.values():
                table.add_row(rule.id, rule.name, rule.severity, rule.summary)
            Console().print(table)
            return 0
        if args.command == "inspect":
            result = inspect_artifact(args.artifact)
            print(json.dumps(result, indent=2))
            return 2 if result["errors"] else 0
        findings, errors = scan(args.target)
        receipts = load_receipts(args.receipts) if args.receipts else []
        base = args.artifact_base or (args.target if args.target.is_dir() else args.target.parent)
        join(findings, receipts, base)
        if args.html:
            args.html.write_text(html_report(findings, errors), encoding="utf-8")
        if args.json:
            print(json.dumps({"findings": [f.to_dict() for f in findings], "coverage": coverage_summary(findings), "errors": errors}, indent=2))
        elif args.sarif:
            print(json.dumps(to_sarif(findings, errors), indent=2))
        else:
            terminal(findings, errors)
        if errors:
            return 2
        return int(args.fail_on != "none" and any(SEVERITIES[f.severity] >= SEVERITIES[args.fail_on] for f in findings))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"loadpath: {exc}", file=sys.stderr)
        return 2
