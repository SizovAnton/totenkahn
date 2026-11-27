from handlers.cli_help import HelpfulParser
from displaying.results import emit_result
import argparse
from contextlib import redirect_stdout
import json
from pathlib import Path
import subprocess
import sys
from handlers import telemetry
from handlers.dependency_cli import confirm, CODES
from handlers.runtime_paths import runtime_config
from handlers.file_handlers import load_sigma_rule


def dispatch(project, argv):
    if not argv or argv[0] != "telemetry":
        return None

    parser = HelpfulParser(prog="totenkahn telemetry")
    parser.add_argument("action", choices=["plan", "check", "prepare", "restore"])
    parser.add_argument("--rule", type=Path)
    parser.add_argument("-y", "--yes", action="store_true", help="Approve requested telemetry preparation or restoration without prompting; dry-run stays read-only and Sysmon EULA acceptance remains separate")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--accept-sysmon-eula", action="store_true")
    parser.add_argument(
        "--sysmon-archive",
        type=Path,
        help="Optional offline official Sysmon ZIP; signature is still required",
    )
    args = parser.parse_args(argv[1:])

    if args.action != "restore" and args.rule is None:
        parser.error("--rule is required for this action")

    with redirect_stdout(sys.stderr if args.json else sys.stdout):
        try:
            if args.action == "restore":
                plan = telemetry.restore(project, dry_run=True)
                emit_result(plan, "Review plan", json_output=args.json)

                if args.dry_run:
                    report = plan
                elif confirm("Restore only unchanged, confirmed TOTENKAHN host changes?", args.yes):
                    report = telemetry.restore(project, approved=True)
                else:
                    report = {"status": "blocked", "reason": "Restore cancelled"}
            else:
                req = telemetry.requirements(load_sigma_rule(args.rule), runtime_config(project))
                proposal = telemetry.inspect(project, req)

                if (
                    (args.action in {"plan", "check"})
                    or args.dry_run
                    or (proposal["status"] in {"passed", "blocked"})
                ):
                    report = proposal
                else:
                    emit_result(proposal, "Review plan", json_output=args.json)

                    if confirm("Apply these host-wide telemetry changes?", args.yes):
                        report = telemetry.prepare(
                            project,
                            proposal,
                            approved=True,
                            accept_eula=args.accept_sysmon_eula,
                            archive=args.sysmon_archive,
                        )
                    else:
                        report = {"status": "blocked", "reason": "Host preparation cancelled"}
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ) as exc:
            report = {"status": "blocked", "reason": str(exc), "error_type": type(exc).__name__}

    emit_result(report, "Telemetry", json_output=args.json)

    return 3 if report["status"] == "needs_action" else CODES.get(report["status"], 2)
