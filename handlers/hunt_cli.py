from handlers.cli_help import HelpfulParser
from displaying.results import emit_result
import argparse
import json
from pathlib import Path
import sys
from uuid import uuid4
from handlers.case_cli import resolve_case
from handlers.case_store import load_case
from handlers.cli_result import status_code
from handlers.dump_readers import DECODER
from handlers.hunt_definition import OPERATIONS, validate_saved
from handlers.hunt_store import define_hunt, get_hunt
from handlers.hunt_runner import run_hunt, inspect_scope, DIMENSIONS
from handlers.runtime_paths import data_root


def dispatch(arguments):
    if not arguments or arguments[0] != "hunt":
        return None

    parser = HelpfulParser(
        prog="totenkahn hunt",
        description="Saved hypotheses and evidence scope; offline case data only",
    )
    commands = parser.add_subparsers(dest="action", required=True)
    define = commands.add_parser("define")
    define.add_argument("case")
    define.add_argument("--name", required=True)
    define.add_argument("--author", required=True)
    definition = define.add_mutually_exclusive_group(required=True)
    definition.add_argument("--spec", type=Path)
    definition.add_argument("--field")
    define.add_argument("--hypothesis")
    define.add_argument("--op", choices=sorted(OPERATIONS))
    values = define.add_mutually_exclusive_group()
    values.add_argument("--value")
    values.add_argument("--value-json")
    define.add_argument(
        "--values", choices=("any", "all"), help="Explicit quantifier for an array-valued field"
    )
    define.add_argument("--ignore-case", action="store_true")
    define.add_argument("--json", action="store_true")

    for action in ("list", "show", "run"):
        sub = commands.add_parser(action)
        sub.add_argument("case")
        sub.add_argument("--json", action="store_true")

        if action != "list":
            sub.add_argument("--name", required=True)

        if action == "run":
            sub.add_argument("--output-dir", type=Path)

            for key in ("host", "user", "start", "end"):
                sub.add_argument("--" + key)

    scope = commands.add_parser("scope")
    scope.add_argument("report", type=Path)
    scope.add_argument("--by", choices=DIMENSIONS, required=True)
    values = scope.add_mutually_exclusive_group()
    values.add_argument("--value")
    values.add_argument("--value-json")
    scope.add_argument("--limit", type=int, default=50)
    scope.add_argument("--after", type=int, default=0)
    scope.add_argument("--json", action="store_true")
    args = parser.parse_args(arguments[1:])

    if args.action == "scope":
        value = DECODER.decode(args.value_json) if args.value_json is not None else args.value
        result = inspect_scope(
            args.report,
            args.by,
            value,
            args.value is not None or args.value_json is not None,
            args.limit,
            args.after,
        )
    elif args.action == "define":
        if args.spec:
            if (
                args.field
                or args.op
                or args.hypothesis
                or (args.value is not None)
                or (args.value_json is not None)
                or args.values
                or args.ignore_case
            ):
                raise ValueError("--spec cannot be combined with inline predicate arguments")

            definition = DECODER.decode(args.spec.read_text(encoding="utf-8-sig"))
        else:
            if (
                not args.op
                or not args.hypothesis
                or (args.value is None and args.value_json is None)
            ):
                raise ValueError(
                    "Inline definition requires --field, --op, --value/--value-json and --hypothesis",
                )

            value = DECODER.decode(args.value_json) if args.value_json is not None else args.value
            predicate = {"field": args.field, "op": args.op, "value": value}

            if args.values:
                predicate["values"] = args.values

            if args.ignore_case:
                predicate["case_sensitive"] = False

            definition = {
                "schema_version": 1,
                "hypothesis": args.hypothesis,
                "condition": predicate,
            }

        result = {
            "status": "passed",
            "hunt": define_hunt(resolve_case(args.case), args.name, definition, args.author),
        }
    elif args.action == "run":
        output = args.output_dir or data_root() / "reports" / ("hunt-" + uuid4().hex[:12])
        filters = {key: getattr(args, key) for key in ("host", "user", "start", "end")}
        report = run_hunt(
            resolve_case(args.case),
            args.name,
            output,
            filters,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
        result = {
            "status": report["status"],
            "hypothesis_result": report.get("hypothesis_result"),
            "scope_status": report.get("scope_status"),
            "counts": report["counts"],
            "report": str(output.resolve() / "report.json"),
            "html": str(output.resolve() / "report.html"),
        }
    else:
        case = load_case(resolve_case(args.case))
        validate_saved(case.get("hunts", []))
        result = (
            {"status": "passed", "hunts": case.get("hunts", [])}
            if args.action == "list"
            else {"status": "passed", "hunt": get_hunt(case, args.name)}
        )

    emit_result(result, "Hunting / " + args.action, json_output=args.json)

    return status_code(result["status"])
