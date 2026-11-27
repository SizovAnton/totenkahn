from handlers.cli_help import HelpfulParser
from displaying.results import emit_result
import argparse
import json
from pathlib import Path
import re
import sys
from uuid import uuid4
from handlers.case_store import (
    create_case,
    load_case,
    add_dataset,
    add_note,
    verify_case,
    export_case,
    set_state,
)
from handlers.case_timeline import build_timeline
from handlers.dump_cli import resolve_dataset, resolve_selection
from handlers.runtime_paths import data_root
from handlers.cli_result import status_code


def resolve_case(value):
    path = Path(value)

    if path.is_dir():
        return path

    if not re.fullmatch("[A-Za-z0-9_-]{1,80}", value):
        raise ValueError("Use a case directory or case name")

    return data_root() / "cases" / value


def dispatch(arguments):
    if not arguments or arguments[0] != "case":
        return None

    parser = HelpfulParser(
        prog="totenkahn case",
        description="Local evidence cases, annotations and timelines",
    )
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("create")
    create.add_argument("--title", required=True)
    create.add_argument("--description", default="")
    destination = create.add_mutually_exclusive_group()
    destination.add_argument("--name")
    destination.add_argument("--output-dir", type=Path)
    create.add_argument("--json", action="store_true")
    commands.add_parser("list").add_argument("--json", action="store_true")

    for action in ("show", "verify", "add", "note", "timeline", "export", "status"):
        sub = commands.add_parser(action)
        sub.add_argument("case")
        sub.add_argument("--json", action="store_true")

        if action == "status":
            sub.add_argument("--set", dest="state", choices=("open", "closed"), required=True)
            sub.add_argument("--author", required=True)
            sub.add_argument("--reason", required=True)
        elif action == "add":
            sub.add_argument("--dataset", required=True)
            sub.add_argument("--selection")
            sub.add_argument("--label")
        elif action == "note":
            sub.add_argument("--text", required=True)
            sub.add_argument("--author", required=True)
            sub.add_argument("--attachment")
            sub.add_argument("--row", type=int)
            sub.add_argument("--tag", action="append", default=[])
        elif action == "timeline":
            sub.add_argument("--output-dir", type=Path)

            for key in ("host", "user", "process-id", "start", "end"):
                sub.add_argument("--" + key)
        elif action == "export":
            sub.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(arguments[1:])
    report = {}

    if args.action == "create":
        name = args.name or "case-" + uuid4().hex[:12]

        if not re.fullmatch("[A-Za-z0-9_-]{1,80}", name):
            raise ValueError("Invalid case name")

        path = args.output_dir or data_root() / "cases" / name
        value = create_case(path, args.title, args.description)
        result = {"status": "passed", "case_id": value["case_id"], "case": str(path.resolve())}
    elif args.action == "list":
        items = []

        for path in sorted((data_root() / "cases").glob("*/case.json")):
            try:
                value = load_case(path.parent)
                items.append(
                    {
                        "name": path.parent.name,
                        "title": value["title"],
                        "path": str(path.parent),
                        "case_id": value["case_id"],
                    },
                )
            except (OSError, ValueError, KeyError) as exc:
                items.append({"path": str(path.parent), "status": "error", "reason": str(exc)})

        result = {"status": "passed", "cases": items}
    else:
        root = resolve_case(args.case)

        if args.action == "status":
            result = set_state(root, args.state, args.author, args.reason)
        elif args.action == "show":
            result = {
                "status": "passed",
                "case": load_case(root),
                "integrity": "metadata_only_use_case_verify",
            }
        elif args.action == "verify":
            result = verify_case(root)
        elif args.action == "add":
            print("Copying and verifying evidence snapshot", file=sys.stderr, flush=True)
            entry = add_dataset(
                root,
                resolve_dataset(args.dataset),
                resolve_selection(args.selection) if args.selection else None,
                args.label,
            )
            result = {"status": "passed", "attachment": entry}
        elif args.action == "note":
            result = {
                "status": "passed",
                "note": add_note(root, args.text, args.author, args.attachment, args.row, args.tag),
            }
        elif args.action == "export":
            result = export_case(root, args.output)
        else:
            output = args.output_dir or data_root() / "reports" / ("timeline-" + uuid4().hex[:12])
            filters = {
                key: getattr(args, key) for key in ("host", "user", "process_id", "start", "end")
            }
            report = build_timeline(
                root,
                output,
                filters,
                progress=lambda message: print(message, file=sys.stderr, flush=True),
            )
            result = {
                "status": report["status"],
                "events": report["events"],
                "unknown_time": report["unknown_time"],
                "report": str(output.resolve() / "report.json"),
                "html": str(output.resolve() / "report.html"),
            }

    human_result = result

    if args.action == "timeline":
        human_result = {
            **result,
            "excluded": report["excluded"],
            "filters": report["filters"],
            "limitations": report["limitations"],
        }

    emit_result(result, "Case / " + args.action, json_output=args.json, human_payload=human_result)

    return status_code(result["status"])
