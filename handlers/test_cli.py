from pathlib import Path
import re
import subprocess
import sys

from displaying.preflight import emit_preflight as emit_result
from handlers.cli_help import HelpfulParser
from handlers import dependencies, telemetry
from handlers.atomic_resources import resource_plan, prepare_resources
from handlers.atomic_lifecycle import parse_inputs, build_plan
from handlers.dependency_cli import confirm, ensure_ready
from handlers.file_handlers import load_sigma_rule, load_manual_test_context, load_test_case
from handlers.matching import validate_rule, validate_live_logsource
from handlers.runtime_paths import runtime_config


def parser_for_tests():
    parser = HelpfulParser(
        prog="totenkahn test",
        description="Run one engineering scenario. Readiness checks and preparation are built in.",
    )
    modes = parser.add_subparsers(dest="mode", required=True)

    for mode in ("auto", "manual", "replay"):
        child = modes.add_parser(
            mode,
            description={
                "auto": "Required: --rule and --technique ID NUMBER. Checks telemetry, prepares selected resources with consent, then asks to execute Atomic.",
                "manual": "Required: --rule. Checks telemetry, then collects until Enter while you perform the action. Atomic is not required.",
                "replay": "Required: --rule and --session. Evaluates saved evidence; no collection, Atomic installation or host changes.",
            }[mode],
        )
        child.epilog = (
            (child.epilog or "")
            + "\n\nWorkflow: validate inputs -> inspect readiness -> request scoped consent if needed -> run -> report.\nUse -y/--yes to approve all scenario confirmations, or scoped --approve-* flags for individual actions. No terminal input without approval: the action stops. Manual collection still waits for Enter to stop.\nWindows PowerShell: Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force\nThis session setting must comply with host policy; the platform does not override it."
        )
        child.add_argument(
            "-y", "--yes", action="store_true",
            help="Approve all confirmation prompts for this scenario: dependencies, telemetry changes and selected Atomic execution. Does not enable prerequisite installation, cleanup or accept the Sysmon EULA.",
        )
        child.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=0,
            help="-v: details; -vv: full preflight data, including inventory and hashes",
        )
        child.add_argument(
            "--rule",
            type=Path,
            required=True,
            help="Existing Sigma YAML; paths are relative to your terminal directory",
        )

        if mode == "replay":
            child.add_argument(
                "--session",
                type=Path,
                required=True,
                help="Saved session directory containing events.json",
            )
            child.add_argument(
                "--test-case", type=Path, help="Optional expected result JSON for replay"
            )
        else:
            child.add_argument(
                "--approve-telemetry",
                action="store_true",
                help="Explicitly approve displayed host-wide audit changes; does not approve Atomic",
            )
            child.add_argument(
                "--accept-sysmon-eula",
                action="store_true",
                help="Explicit Sysmon license acceptance if installation is required",
            )
            child.add_argument(
                "--sysmon-archive",
                type=Path,
                help="Official local Sysmon archive, required for offline installation if missing",
            )
            child.add_argument(
                "--offline",
                action="store_true",
                help="No package downloads; use verified cached/local packages only",
            )
            child.add_argument(
                "--plan",
                action="store_true",
                help="Inspect readiness only; no installation, audit changes or test execution",
            )

        if mode == "manual":
            child.add_argument(
                "--test-context",
                type=Path,
                help="Optional manual action description and expected result JSON",
            )

        if mode == "auto":
            child.add_argument(
                "--technique",
                nargs=2,
                required=True,
                metavar=("ID", "NUMBER"),
                help="Atomic technique AND test number, e.g. T1033 8",
            )
            child.add_argument(
                "--input",
                action="append",
                default=[],
                metavar="NAME=VALUE",
                help="Atomic input override; repeat for multiple inputs",
            )
            child.add_argument(
                "--timeout", type=int, default=120, help="Atomic command timeout in seconds, 1–3600"
            )
            child.add_argument(
                "--approve-dependencies",
                action="store_true",
                help="Approve base modules and selected resources only; does not approve execution",
            )
            child.add_argument(
                "--approve-atomic",
                action="store_true",
                help="Approve execution of the selected Atomic plan including prerequisite checks",
            )
            child.add_argument(
                "--prepare-prereqs",
                action="store_true",
                help="Allow selected test prerequisite installation code during Atomic execution",
            )
            child.add_argument(
                "--cleanup",
                action="store_true",
                help="Run selected definition cleanup; this is not a verified rollback",
            )
            child.add_argument(
                "--asset-file",
                action="append",
                default=[],
                help="Explicit additional reviewed resource path for dynamic references",
            )
            child.add_argument(
                "--asset-technique",
                action="append",
                default=[],
                help="Explicit additional resource folder for dynamic references",
            )

        child.add_argument(
            "--show-correlation",
            action="store_true",
            help="Show the evidence linking events to the action",
        )

    return parser


def require_passed(report, stage, *, verbosity=0):
    emit_result(report, stage, verbosity=verbosity)

    if report.get("status") != "passed":
        raise SystemExit(1)


def prepare_invocation(project, argv):
    parser = parser_for_tests()
    args = parser.parse_args(argv)

    if args.yes:
        if args.mode in {"auto", "manual"}:
            args.approve_telemetry = True

        if args.mode == "auto":
            args.approve_dependencies = True
            args.approve_atomic = True

    def display(report, stage):
        emit_result(report, stage, verbosity=args.verbose)

    def checked(report, stage):
        require_passed(report, stage, verbosity=args.verbose)

    technique, number = "", ""
    inputs = {}

    try:
        if not args.rule.is_file():
            parser.error(
                f"Sigma rule file not found: {args.rule}. Current directory: {Path.cwd()}. Supply an existing YAML path."
            )

        rule = load_sigma_rule(args.rule)

        if not isinstance(rule, dict):
            parser.error("Sigma rule must be a YAML object")

        validate_rule(rule)

        if args.mode == "replay":
            if not (args.session / "events.json").is_file():
                parser.error("--session must contain events.json from a saved session")

            if args.test_case:
                load_test_case(args.test_case)

            result = [
                "--rule",
                str(args.rule),
                "--session",
                str(args.session),
                "--skip-dependencies",
            ]

            if args.test_case:
                result += ["--test-case", str(args.test_case)]
        else:
            if sys.platform != "win32":
                parser.error(
                    "Live collection requires Windows. Use test replay or dump analysis for saved evidence."
                )

            config = runtime_config(project)

            try:
                validate_live_logsource(rule, config)
                requirements = telemetry.requirements(rule, config)
            except ValueError as exc:
                parser.error(
                    f'{exc}. Rule logsource: {rule.get("logsource")}. Live mode needs a supported Windows event source; use dump analysis for other exported sources.'
                )

            if args.mode == "auto":
                technique, number = args.technique

                if (
                    not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique.upper())
                    or not number.isdecimal()
                    or int(number) < 1
                ):
                    parser.error(
                        "--technique requires a valid ID and a positive number, e.g. T1033 8"
                    )

                if not 1 <= args.timeout <= 3600:
                    parser.error("--timeout must be between 1 and 3600 seconds")

                inputs = parse_inputs(args.input)
            elif args.test_context:
                load_manual_test_context(args.test_context)

            proposal = telemetry.inspect(project, requirements)

            if args.plan:
                report = {
                    "status": "planned",
                    "mode": args.mode,
                    "telemetry": proposal,
                    "base_dependencies": (
                        dependencies.status(project)
                        if args.mode == "auto"
                        else {"status": "not_required"}
                    ),
                    "scope": "readiness_only_no_selected_test_execution_or_installation",
                }
                display(report, "Readiness plan")

                raise SystemExit(0 if proposal["status"] != "blocked" else 1)

            if proposal["status"] == "blocked":
                checked(proposal, "Telemetry blocked")

            if args.mode == "auto":
                checked(
                    ensure_ready(
                        project,
                        yes=args.approve_dependencies,
                        offline=args.offline,
                        verbosity=args.verbose,
                    ),
                    "Base dependencies",
                )
                resources = resource_plan(
                    project,
                    technique.upper(),
                    int(number),
                    offline=args.offline,
                    inputs=inputs,
                    asset_files=args.asset_file,
                    asset_techniques=args.asset_technique,
                )

                if resources["status"] != "planned":
                    display(resources, "Selected resources")

                    raise SystemExit(1)

                ready = False

                try:
                    build_plan(
                        runtime_config(project),
                        technique.upper(),
                        int(number),
                        inputs=inputs,
                        timeout=args.timeout,
                        cleanup=args.cleanup,
                        prepare=args.prepare_prereqs,
                    )
                    ready = not (args.asset_file or args.asset_technique)
                except (OSError, ValueError, KeyError, TypeError):
                    pass

                display(
                    dict(
                        resources,
                        status="passed" if ready else resources["status"],
                        readiness="already verified" if ready else "preparation requires consent",
                    ),
                    "Selected resources",
                )

                if not ready:
                    if not confirm(
                        "Prepare these selected files? This does not execute Atomic.",
                        args.approve_dependencies,
                    ):
                        checked(
                            {
                                "status": "blocked",
                                "reason": "Selected preparation declined. Automation: --approve-dependencies",
                            },
                            "Preparation",
                        )

                    checked(
                        prepare_resources(project, resources, approved=True), "Selected resources"
                    )

            if proposal["status"] != "passed":
                display(proposal, "Host changes requiring consent")

                if (
                    args.offline
                    and any(a["key"] == "sysmon" for a in proposal.get("actions", []))
                    and args.sysmon_archive is None
                ):
                    checked(
                        {
                            "status": "blocked",
                            "reason": "Offline Sysmon installation requires --sysmon-archive",
                        },
                        "Telemetry",
                    )

                if not confirm(
                    "Apply the displayed host-wide telemetry changes?", args.approve_telemetry
                ):
                    checked(
                        {
                            "status": "blocked",
                            "reason": "Telemetry preparation declined. Automation: --approve-telemetry",
                        },
                        "Telemetry",
                    )

                checked(
                    telemetry.prepare(
                        project,
                        proposal,
                        approved=True,
                        accept_eula=args.accept_sysmon_eula,
                        archive=args.sysmon_archive,
                    ),
                    "Telemetry preparation",
                )

            checked(telemetry.inspect(project, requirements), "Telemetry readiness")
            result = ["--rule", str(args.rule), "--" + args.mode]

            if args.mode == "manual":
                if args.test_context:
                    result += ["--test-context", str(args.test_context)]
            else:
                result += [
                    "--atomic-test",
                    technique.upper(),
                    number,
                    "--atomic-timeout",
                    str(args.timeout),
                ]

                for value in args.input:
                    result += ["--input", value]

                for flag in ("approve_atomic", "prepare_prereqs", "cleanup", "offline"):
                    if getattr(args, flag):
                        result.append("--" + flag.replace("_", "-"))

        if args.verbose:
            result += ["-v"] * min(args.verbose, 2)

        if args.show_correlation:
            result.append("--show-correlation")

        return result
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.TimeoutExpired,
    ) as exc:
        parser.error(str(exc))
