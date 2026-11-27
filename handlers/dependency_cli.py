from handlers.cli_help import HelpfulParser
from displaying.results import emit_result, interactive
from displaying.preflight import emit_preflight
from contextlib import redirect_stdout
import argparse
import json
import os
from pathlib import Path
import sys
import subprocess
from handlers import dependencies
from handlers.runtime_paths import data_root, runtime_config
from handlers.environment_check import check_environment, SUPPORTED_MODES
from handlers.cli_result import STATUS_CODES as CODES


def confirm(message, yes=False):
    if yes:
        return True

    return bool(
        (
            sys.stdin
            and sys.stdin.isatty()
            and (input(message + " [y/N] ").strip().lower() in {"y", "yes"})
        ),
    )


def print_plan(plan, *, verbosity=None):
    if verbosity is not None:
        emit_preflight(plan, "Dependency preparation plan", verbosity=verbosity)

        return

    if interactive(sys.stdout):
        emit_result(plan, "Dependency preparation plan")

        return

    print("TOTENKAHN first-run dependency preparation")
    print("Data directory:", plan["data_directory"])
    print("Python and application libraries are included in the executable bundle.")

    for key, paths in plan["discovery"]["candidates"].items():
        print(f"{key}: " + (", ".join(paths) if paths else "no existing candidate found"))

    for package in plan["packages"]:
        print(
            f"Pinned package: {package['component_id']} {package['version']} ({package['size']} bytes); {package['url']}",
        )

    for action in plan["actions"]:
        print(" - " + action)

    print(plan["system_changes"])
    print(plan["separate"])


def ensure_ready(project, *, yes=False, offline=False, cache=None, atomic_dir=None, verbosity=0):
    current = dependencies.status(project)

    if current["status"] == "passed":
        return current

    proposal = dependencies.plan(project, atomic_dir=atomic_dir)
    print_plan(proposal, verbosity=verbosity)

    if not confirm("Prepare all base dependencies now?", yes):
        return {
            "status": "blocked",
            "reason": "Preparation declined or confirmation unavailable. Use dependencies prepare --yes for automation.",
        }

    return dependencies.prepare(
        project,
        approved=True,
        offline=offline,
        cache=cache,
        atomic_dir=atomic_dir,
    )


def dispatch(project, argv):
    if not argv or argv[0] not in {"dependencies", "doctor", "reports"}:
        return None

    parser = HelpfulParser(prog="totenkahn " + argv[0])
    command = argv[0]
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write only the structured result to stdout",
    )

    if command == "dependencies":
        parser.add_argument(
            "action",
            choices=("plan", "status", "prepare", "remove", "plan-test", "prepare-test"),
            nargs="?",
            default="status",
        )
        parser.add_argument("-y", "--yes", action="store_true", help="Approve preparation or removal requested by this command without prompting; plan/dry-run remain read-only")
        parser.add_argument("--offline", action="store_true")
        parser.add_argument("--cache", type=Path)
        parser.add_argument(
            "--atomic-dir",
            type=Path,
            help="Optional custom existing Atomic location",
        )
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument(
            "--technique",
            nargs=2,
            metavar=("ID", "NUMBER"),
            help="Technique and test number together, e.g. T1033 8",
        )
        parser.add_argument("--input", action="append", default=[])
        parser.add_argument(
            "--asset-file",
            action="append",
            default=[],
            help="Exact additional reviewed path inside the Atomic archive",
        )
        parser.add_argument(
            "--asset-technique",
            action="append",
            default=[],
            help="Additional reviewed technique folder required by dynamic paths",
        )
    elif command == "doctor":
        parser.add_argument("--mode", choices=sorted(SUPPORTED_MODES), default="auto")
    else:
        parser.add_argument("--open", action="store_true")

    argv = list(argv)

    if "--test-number" in argv and "--technique" in argv:
        old = argv.index("--test-number")

        if old + 1 >= len(argv):
            parser.error("Use --technique ID NUMBER, e.g. --technique T1033 8")

        number = argv[old + 1]
        del argv[old : old + 2]
        index = argv.index("--technique")
        argv.insert(index + 2, number)

    args = parser.parse_args(argv[1:])

    with redirect_stdout(sys.stderr if args.json else sys.stdout):
        try:
            if command == "dependencies":
                if args.action in {"plan-test", "prepare-test"}:
                    from handlers.atomic_resources import resource_plan, prepare_resources
                    from handlers.atomic_lifecycle import parse_inputs

                    if args.technique is None:
                        raise ValueError(
                            "--technique ID NUMBER is required, e.g. --technique T1033 8"
                        )

                    proposal = resource_plan(
                        project,
                        args.technique[0],
                        int(args.technique[1]),
                        cache=args.cache,
                        offline=args.offline,
                        inputs=parse_inputs(args.input),
                        asset_techniques=args.asset_technique,
                        asset_files=args.asset_file,
                    )

                    if (
                        args.action == "plan-test"
                        or args.dry_run
                        or proposal["status"] != "planned"
                    ):
                        report = proposal
                    else:
                        emit_result(proposal, "Review plan", json_output=args.json)
                        report = (
                            prepare_resources(project, proposal, approved=True)
                            if confirm(
                                "Prepare the listed selected Atomic resources without executing commands?",
                                args.yes,
                            )
                            else {
                                "status": "blocked",
                                "reason": "Selected resource preparation declined",
                            }
                        )
                elif args.action == "plan":
                    report = dependencies.plan(project, atomic_dir=args.atomic_dir)
                elif args.action == "status":
                    report = dependencies.status(project)
                elif args.action == "prepare":
                    print_plan(dependencies.plan(project, atomic_dir=args.atomic_dir))

                    if not confirm("Prepare all base dependencies now?", args.yes):
                        report = {"status": "blocked", "reason": "Preparation not authorized"}
                    else:
                        report = dependencies.prepare(
                            project,
                            approved=True,
                            offline=args.offline,
                            cache=args.cache,
                            atomic_dir=args.atomic_dir,
                        )
                else:
                    preview = dependencies.remove(dry_run=True)

                    if args.dry_run:
                        report = preview
                    else:
                        emit_result(preview, "Review plan", json_output=args.json)
                        report = (
                            dependencies.remove(approved=True)
                            if confirm("Remove TOTENKAHN-owned unchanged dependencies?", args.yes)
                            else {"status": "blocked", "reason": "Removal cancelled"}
                        )
            elif command == "doctor":
                deps = dependencies.status(project, runtime=args.mode == "auto")
                env = check_environment(project, runtime_config(project), mode=args.mode)
                report = {
                    "status": (
                        env["status"]
                        if args.mode in {"replay", "regression", "manual"}
                        or deps["status"] == "passed"
                        else deps["status"]
                    ),
                    "dependencies": deps,
                    "environment": env,
                }
            else:
                folder = data_root() / "reports"
                report = {
                    "status": "passed",
                    "reports_directory": str(folder),
                    "exists": folder.is_dir(),
                }

                if args.open:
                    if sys.platform != "win32" or not folder.is_dir():
                        raise ValueError("The reports directory is not available to open")

                    os.startfile(str(folder))
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ) as exc:
            report = {"status": "error", "reason": str(exc), "error_type": type(exc).__name__}

    emit_result(report, "Dependency", json_output=args.json)

    return (
        0
        if (
            (report["status"] == "planned")
            and (command == "dependencies")
            and (args.action in {"plan-test", "prepare-test"})
        )
        else CODES.get(report["status"], 2)
    )
