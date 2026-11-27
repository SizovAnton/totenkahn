from handlers.cli_help import HelpfulParser
from displaying.results import emit_result
from handlers.tabular_input import ENCODINGS
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from uuid import uuid4
from handlers.evidence import (
    PROFILES,
    preview_source,
    import_dump,
    inspect_dataset,
    verify_dataset,
    list_issues,
)
from handlers.runtime_paths import data_root
from handlers.evidence_selection import create_selection, validate_filters
from handlers.dump_analysis import analyze_dump
from handlers.dump_readers import DECODER


def resolve_dataset(value):
    path = Path(value)

    if path.exists():
        return path

    if not re.fullmatch("[A-Za-z0-9_-]{1,80}", value):
        raise ValueError("Use an existing dataset path or a dataset name from dump list")

    return data_root() / "evidence" / value


def resolve_selection(value):
    path = Path(value)

    if path.is_dir():
        return path

    if not re.fullmatch("[A-Za-z0-9_-]{1,80}", value):
        raise ValueError("Use a saved selection path or name")

    return data_root() / "selections" / value


def add_analysis_filters(parser):
    for name in ("host", "event-type", "channel", "provider", "source", "text", "start", "end"):
        parser.add_argument("--" + name)

    parser.add_argument("--row", type=int, action="append", default=[])
    parser.add_argument("--field", action="append", default=[], metavar="/PATH=VALUE")
    parser.add_argument(
        "--filters",
        type=Path,
        help="JSON filter object; paths are JSON pointers",
    )


def analysis_filters(args):
    value = DECODER.decode(args.filters.read_text(encoding="utf-8-sig")) if args.filters else {}

    if not isinstance(value, dict):
        raise ValueError("Filters must be a JSON object")

    for key in ("host", "event_type", "channel", "provider", "source", "text", "start", "end"):
        item = getattr(args, key)

        if item is not None:
            if key in value:
                raise ValueError("Filter specified both in JSON and CLI: " + key)

            value[key] = item

    if args.row:
        if "rows" in value:
            raise ValueError("rows specified twice")

        value["rows"] = args.row

    if args.field:
        if "fields" in value:
            raise ValueError("fields specified twice")

        fields = []

        for expression in args.field:
            path, separator, expected = expression.partition("=")

            if not separator:
                raise ValueError("--field requires /PATH=VALUE")

            fields.append({"path": path, "op": "text_equals", "value": expected})

        value["fields"] = fields

    return validate_filters(value)


def dispatch(project, arguments):
    if not arguments or arguments[0] != "dump":
        return None

    parser = HelpfulParser(
        prog="totenkahn dump",
        description="Import and inspect saved evidence without Atomic or SIEM access",
    )
    commands = parser.add_subparsers(dest="action", required=True)
    preview = commands.add_parser("preview")
    preview.add_argument("source", type=Path)
    preview.add_argument("--profile")
    preview.add_argument("--limit", type=int, default=5)
    preview.add_argument("--json", action="store_true")
    incoming = commands.add_parser("import")
    incoming.add_argument("source", type=Path)
    incoming.add_argument(
        "--profile",
        help="generic-v1, splunk-v1, elastic-discover-v1, or explicit mapping JSON",
    )
    incoming.add_argument(
        "--name",
        help="Dataset name under the private evidence directory",
    )
    incoming.add_argument("--output-dir", type=Path, help="New external dataset directory")
    incoming.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="EVTX decoding timeout per file in seconds",
    )
    incoming.add_argument("--json", action="store_true")

    for input_parser in (incoming, preview):
        input_parser.add_argument("--encoding", choices=ENCODINGS, default="utf-8-sig")
        input_parser.add_argument("--delimiter")
        input_parser.add_argument("--null-value")
        input_parser.add_argument("--max-expanded-mib", type=int, default=1024)

    recover = commands.add_parser(
        "recover", help="Reindex verified retained originals into a new dataset"
    )
    recover.add_argument("dataset")
    recover.add_argument("--output-dir", type=Path, required=True)
    recover.add_argument("--timeout", type=int, default=600)
    recover.add_argument("--json", action="store_true")

    commands.add_parser("profiles").add_argument("--json", action="store_true")
    commands.add_parser("list").add_argument("--json", action="store_true")

    for action in ("summary", "search", "show", "verify", "issues"):
        sub = commands.add_parser(action)
        sub.add_argument("dataset")
        sub.add_argument("--json", action="store_true")

        if action == "show":
            sub.add_argument("--row", type=int, required=True)

        if action == "issues":
            sub.add_argument("--limit", type=int, default=50)
            sub.add_argument("--after", type=int, default=0)

        if action == "search":
            sub.add_argument("--host")
            sub.add_argument("--event-type")
            sub.add_argument("--text")
            sub.add_argument("--start")
            sub.add_argument("--end")
            sub.add_argument("--limit", type=int, default=50)
            sub.add_argument("--after", type=int, default=0)

    select = commands.add_parser("select")
    select.add_argument("dataset")
    select.add_argument("--name")
    select.add_argument("--output-dir", type=Path)
    select.add_argument("--json", action="store_true")
    add_analysis_filters(select)
    commands.add_parser("selections").add_argument("--json", action="store_true")
    analyze = commands.add_parser("analyze")
    analyze.add_argument("dataset")
    rules = analyze.add_mutually_exclusive_group(required=True)
    rules.add_argument("--rule", type=Path)
    rules.add_argument("--rules-dir", type=Path)
    analyze.add_argument(
        "--preflight",
        action="store_true",
        help="Check source and field suitability without evaluating matches",
    )
    analyze.add_argument("--selection")
    analyze.add_argument("--mapping", type=Path)
    analyze.add_argument("--output-dir", type=Path)
    analyze.add_argument("--json", action="store_true")
    add_analysis_filters(analyze)
    args = parser.parse_args(arguments[1:])
    report = {}
    reader_options = (
        {
            key: getattr(args, key)
            for key in ("encoding", "delimiter", "null_value", "max_expanded_mib")
        }
        if args.action in {"import", "preview"}
        else {}
    )

    if args.action == "recover":
        from handlers.evidence_recovery import recover_dump

        if not 1 <= args.timeout <= 86400:
            parser.error("timeout must be between 1 and 86400")

        report = recover_dump(
            project,
            resolve_dataset(args.dataset),
            args.output_dir,
            timeout=args.timeout,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
        result = {
            key: report[key]
            for key in (
                "status",
                "counts",
                "recovery",
                "limitations",
                "reason",
                "errors",
                "persistence_error",
            )
            if key in report
        }
        result["dataset"] = str(args.output_dir.resolve())
        result["report"] = str(args.output_dir.resolve() / "report.html")
    elif args.action == "preview":
        result = preview_source(
            args.source, profile=args.profile, limit=args.limit, reader_options=reader_options
        )
    elif args.action == "select":
        if args.name and args.output_dir:
            parser.error("--name and --output-dir are mutually exclusive")

        name = args.name or "selection-" + uuid4().hex[:12]

        if not re.fullmatch("[A-Za-z0-9_-]{1,80}", name):
            parser.error("Invalid selection name")

        output = args.output_dir or data_root() / "selections" / name
        result = create_selection(resolve_dataset(args.dataset), output, analysis_filters(args))
        result["selection_directory"] = str(output.resolve())
    elif args.action == "selections":
        items = []

        for path in sorted((data_root() / "selections").glob("*/selection.json")):
            item = DECODER.decode(path.read_text(encoding="utf-8"))
            items.append(
                {
                    "name": path.parent.name,
                    "path": str(path.parent),
                    "count": item["count"],
                    "dataset_id": item["dataset_id"],
                    "status": item["status"],
                },
            )

        result = {"status": "passed", "selections": items}
    elif args.action == "analyze":
        output = args.output_dir or data_root() / "reports" / ("dump-" + uuid4().hex[:12])
        report = analyze_dump(
            project,
            resolve_dataset(args.dataset),
            output,
            rule=args.rule,
            rules_dir=args.rules_dir,
            selection=resolve_selection(args.selection) if args.selection else None,
            filters=analysis_filters(args),
            mapping_path=args.mapping,
            preflight_only=args.preflight,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
        result = {
            "status": report["status"],
            "report": str(output.resolve() / "report.json"),
            "html": str(output.resolve() / "report.html"),
            "rules": len(report["rules"]),
            "reason": report.get("reason"),
        }
    elif args.action == "import":
        if args.timeout <= 0 or args.timeout > 86400:
            parser.error("timeout must be between 1 and 86400")

        if args.name and args.output_dir:
            parser.error("--name and --output-dir are mutually exclusive")

        name = args.name or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8]

        if not re.fullmatch("[A-Za-z0-9_-]{1,80}", name):
            parser.error("Dataset name must contain 1..80 letters, digits, underscores or hyphens")

        output = args.output_dir or data_root() / "evidence" / name
        report = import_dump(
            project,
            args.source,
            output,
            profile=args.profile,
            reader_options=reader_options,
            timeout=args.timeout,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
        result = {
            key: report[key]
            for key in (
                "status",
                "dataset_id",
                "counts",
                "quality",
                "reason",
                "errors",
                "persistence_error",
            )
            if key in report
        }
        result["dataset"] = str(output.resolve())
        result["manifest"] = str(output.resolve() / "manifest.json")
        result["report"] = str(output.resolve() / "report.html")
    elif args.action == "profiles":
        result = {"status": "passed", "profiles": PROFILES}
    elif args.action == "list":
        items = []

        for path in sorted((data_root() / "evidence").glob("*/manifest.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
                items.append(
                    {
                        "name": path.parent.name,
                        "path": str(path.parent),
                        "status": manifest["status"],
                        "created_at": manifest["created_at"],
                        "counts": manifest["counts"],
                    },
                )
            except (OSError, ValueError, KeyError) as exc:
                items.append({"path": str(path.parent), "status": "error", "reason": str(exc)})

        result = {"status": "passed", "datasets": items}
    else:
        dataset = resolve_dataset(args.dataset)

        if args.action == "summary":
            result = json.loads((dataset / "manifest.json").read_text(encoding="utf-8"))
        elif args.action == "issues":
            result = list_issues(dataset, after=args.after, limit=args.limit)
        elif args.action == "verify":
            result = verify_dataset(dataset)
        elif args.action == "show":
            if args.row <= 0:
                parser.error("row must be positive")

            result = inspect_dataset(dataset, row_id=args.row)

            if not result["items"]:
                result.update(status="error", reason="No such row in dataset")
        else:
            result = inspect_dataset(
                dataset,
                host=args.host,
                event_type=args.event_type,
                text=args.text,
                start=args.start,
                end=args.end,
                limit=args.limit,
                after=args.after,
            )

    human_result = result

    if args.action == "summary":
        human_result = {
            key: result[key]
            for key in ("status", "dataset_id", "created_at", "counts", "quality")
            if key in result
        }
        human_result["files"] = [
            {
                **{
                    key: item[key]
                    for key in (
                        "name",
                        "status",
                        "format",
                        "size",
                        "read",
                        "accepted",
                        "rejected",
                        "sha256",
                        "error",
                    )
                    if key in item
                },
                "profile": (
                    item.get("profile", {}).get("id")
                    if isinstance(item.get("profile"), dict)
                    else item.get("profile")
                ),
            }
            for item in result.get("files", [])
        ]
        human_result["details"] = (
            "Use dump show --row N for event values; dump summary --json for the complete manifest."
        )
    elif args.action == "analyze":
        human_result = {
            **result,
            "rules": [
                {
                    key: item[key]
                    for key in ("path", "status", "counts", "reason", "readiness")
                    if key in item
                }
                for item in report["rules"]
            ],
            "limitations": report.get("limitations", []),
        }

    emit_result(
        result, "Evidence / " + args.action, json_output=args.json, human_payload=human_result
    )

    return {
        "passed": 0,
        "passed_with_warnings": 0,
        "partial": 3,
        "needs_verification": 3,
        "interrupted": 130,
    }.get(
        result["status"],
        2,
    )
