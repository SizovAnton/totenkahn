from handlers.cli_help import HelpfulParser
from displaying.results import emit_result
import argparse
import json
from pathlib import Path
from handlers.case_cli import resolve_case
from handlers.case_store import load_case
from handlers.finding_store import create_finding
from handlers.finding_suite import export_suite, load_evidence_suite


def dispatch(project, arguments):
    if not arguments or arguments[0] != "finding":
        return None

    parser = HelpfulParser(
        prog="totenkahn finding",
        description="Reviewed evidence findings and portable regression bundles",
    )
    commands = parser.add_subparsers(dest="action", required=True)
    add = commands.add_parser("add")
    add.add_argument("case")

    for name in ("name", "title", "author", "reason"):
        add.add_argument("--" + name, required=True)

    add.add_argument("--expect", choices=("match", "no-match"), required=True)
    source = add.add_mutually_exclusive_group(required=True)
    source.add_argument("--attachment")
    source.add_argument("--hunt-report", type=Path)
    add.add_argument("--row", action="append", type=int)
    add.add_argument("--result", action="append", type=int)
    add.add_argument("--json", action="store_true")

    for action in ("list", "show", "export"):
        sub = commands.add_parser(action)
        sub.add_argument("case")
        sub.add_argument("--json", action="store_true")

        if action == "show":
            sub.add_argument("--name", required=True)

        if action == "export":
            sub.add_argument("--name", action="append", required=True)
            sub.add_argument("--baseline", type=Path, required=True)
            sub.add_argument("--candidate", type=Path, required=True)
            sub.add_argument("--mapping", type=Path)
            sub.add_argument("--output-dir", type=Path, required=True)

    verify = commands.add_parser("verify-bundle")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--json", action="store_true")
    args = parser.parse_args(arguments[1:])

    if args.action == "add":
        finding = create_finding(
            resolve_case(args.case),
            args.name,
            args.title,
            args.author,
            args.reason,
            args.expect == "match",
            attachment=args.attachment,
            rows=args.row,
            hunt_report=args.hunt_report,
            results=args.result,
        )
        result = {"status": "passed", "finding": finding}
    elif args.action == "export":
        result = export_suite(
            project,
            resolve_case(args.case),
            args.name,
            args.baseline,
            args.candidate,
            args.output_dir,
            args.mapping,
        )
    elif args.action == "verify-bundle":
        suite, _, case, findings, _, _, verification, _ = load_evidence_suite(
            args.bundle / "suite.json"
        )
        result = {
            "status": "passed",
            "suite_id": suite["suite_id"],
            "case_id": case["case_id"],
            "findings": len(findings),
            "limitations": verification["limitations"],
            "scope": "Pinned evidence integrity only; run ci to evaluate rule expectations",
        }
    else:
        findings = load_case(resolve_case(args.case)).get("findings", [])

        if args.action == "show":
            findings = [finding for finding in findings if finding["name"] == args.name]

            if not findings:
                raise ValueError("Unknown finding name")

        result = {"status": "passed", "findings": findings}

    emit_result(result, "Findings / " + args.action, json_output=args.json)

    return 0
