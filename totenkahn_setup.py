from displaying.results import emit_result, interactive
import argparse
import json
import os
import subprocess
import zipfile
import sys
from displaying.console import configure_standard_streams, show_startup_banner
from pathlib import Path
from handlers.component_inventory import utc_now
from handlers.environment_check import check_environment, SUPPORTED_MODES
from handlers.file_handlers import load_configuration
from handlers.release_manifest import verify_release
from handlers.dependency_plan import (
    build_dependency_plan,
    load_component_catalog,
    validate_lock_coverage,
)
from handlers.package_cache import load_dependency_lock
from handlers.installation import (
    install_release,
    uninstall_release,
    inspect_installation,
    state_path,
)
from handlers.cli_result import STATUS_CODES as EXIT_CODES, run_cli


def default_project_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path(__file__).resolve().parent


def run_doctor(project_dir: Path, *, mode: str, release_dir: Path | None = None) -> dict:
    report = {
        "schema_version": 1,
        "command": "doctor",
        "checked_at": utc_now(),
        "project_dir": str(project_dir),
        "mode": mode,
        "status": "error",
        "release": None,
        "environment": None,
        "errors": [],
    }

    if release_dir is not None:
        try:
            report["release"] = verify_release(release_dir)
        except (OSError, ValueError) as exc:
            report["errors"].append({"stage": "release", "reason": str(exc)})

    try:
        config = load_configuration(
            project_dir / "config" / "default.config",
            project_dir / "config" / "config.json",
        )
        report["environment"] = check_environment(project_dir, config, mode=mode)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report["errors"].append({"stage": "environment", "reason": str(exc)})

    try:
        if state_path(project_dir).is_file():
            report["installation"] = inspect_installation(project_dir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report["errors"].append({"stage": "installation", "reason": str(exc)})

    release = report["release"]
    environment = report["environment"]
    installation = report.get("installation", {})

    if report["errors"]:
        report["status"] = "error"
    elif (
        (release is not None and release["status"] == "failed")
        or (environment is not None and environment["status"] == "blocked")
        or (installation.get("status") == "blocked")
        or (installation.get("installation_status") in {"removed", "removing", "partial"})
    ):
        report["status"] = "blocked"
    elif (environment is not None and environment["status"] == "needs_verification") or (
        installation and installation.get("installation_status") != "installed"
    ):
        report["status"] = "needs_verification"
    else:
        report["status"] = "passed"

    return report


def print_summary(report: dict) -> None:
    print(f"TOTENKAHN environment preflight: {report['status']}")
    print(f"Mode: {report['mode']}")
    print(f"Project directory: {report['project_dir']}")
    release = report["release"]

    if release is None:
        print("Release integrity: not completed or not requested")
    else:
        print(f"Release integrity: {release['status']}")

        for category in ("missing", "unexpected"):
            for path in release[category]:
                print(f"  {category}: {path}")

        for item in release["changed"]:
            print(f"  changed: {item['path']}")

        for item in release["errors"]:
            print(f"  error: {item['path']}: {item['reason']}")

    environment = report["environment"]

    if environment is not None:
        for check in environment["checks"]:
            print(f"[{check['status']}] {check['id']}: {check['reason']}")

            if check["details"] is not None:
                print("  " + json.dumps(check["details"], ensure_ascii=False, sort_keys=True))

    installation = report.get("installation")

    if installation is not None:
        print(f"Installed files: {installation['status']}")
        print(f"Installation state: {installation['installation_status']}")

        for issue in installation["issues"]:
            print(f"  {issue['path']}: {issue['reason']}")

    plan = report.get("dependency_plan")

    if plan is not None:
        print(f"Dependency preparation plan: {plan['status']}")
        print("This plan does not execute installation commands.")

        for item in plan["items"]:
            print(f"  [{item['action']}] {item['component_id']}: {item['reason']}")

        for check in plan["unresolved_checks"]:
            print(f"  [unresolved] {check['id']}: {check['reason']}")

    for error in report["errors"]:
        print(f"[error] {error['stage']}: {error['reason']}")

    print(
        "Scope: environment preflight only; this is not a detection result or full readiness certification.",
    )


def save_report(path: Path, report: dict) -> None:
    payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(payload)


def run_setup_command(args) -> int:
    target = args.target_dir.absolute()

    try:
        if args.command == "install":
            if sys.platform != "win32":
                raise ValueError("Installing the Windows release requires Windows")

            if args.timeout <= 0:
                raise ValueError("timeout must be positive")

            cache = args.cache or target.parent / f".{target.name}.totenkahn-package-cache"
            report = install_release(
                args.release_dir,
                target,
                cache,
                offline=args.offline,
                external_yaml=args.external_yaml,
                external_art=args.external_art,
                timeout=args.timeout,
            )
        else:
            preview = uninstall_release(target, dry_run=True)

            if args.dry_run:
                report = preview
            else:
                if getattr(sys, "frozen", False) and (
                    target.resolve() in Path(sys.executable).resolve().parents
                ):
                    raise ValueError(
                        "Run uninstall using totenkahn-setup.exe from the original release, outside the target",
                    )

                if not args.yes:
                    if args.json or not sys.stdin.isatty():
                        raise ValueError(
                            "Non-interactive removal requires --yes; inspect --dry-run first"
                        )

                    emit_result(
                        preview, "Setup / removal plan", json_output=args.json, stream=sys.stderr
                    )

                    if input("Remove the listed owned files? [y/N] ").strip().lower() != "y":
                        report = {"command": "uninstall", "status": "passed", "cancelled": True}
                    else:
                        report = uninstall_release(target)
                else:
                    report = uninstall_release(target)
    except KeyboardInterrupt:
        report = {
            "command": args.command,
            "status": "error",
            "reason": "Operation interrupted; inspect the installation journal before retrying",
        }
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        zipfile.BadZipFile,
        subprocess.TimeoutExpired,
    ) as exc:
        report = {
            "command": args.command,
            "status": "error",
            "target": str(target),
            "reason": str(exc),
            "error_type": type(exc).__name__,
        }

        if getattr(exc, "winerror", None) in {225, 226}:
            report.update(status="blocked", category="security_product_blocked")

    if args.output is not None:
        try:
            save_report(args.output, report)
        except (OSError, ValueError) as exc:
            report["status"] = "error"
            report["output_error"] = str(exc)

    emit_result(report, "Setup / " + args.command, json_output=args.json)

    return EXIT_CODES[report["status"]]


def main(argv=None) -> int:
    configure_standard_streams()
    show_startup_banner(sys.argv[1:] if argv is None else argv)
    arguments = sys.argv[1:] if argv is None else argv

    if arguments[:1] == ["delivery"]:
        from handlers.delivery_cli import main as delivery_main
        return delivery_main(arguments[1:])

    parser = argparse.ArgumentParser(description="TOTENKAHN setup and environment diagnostics")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("delivery", help="Verified version delivery, acceptance, activation and rollback")
    doctor = commands.add_parser(
        "doctor",
        help="Inspect the environment without installing components",
    )
    doctor.add_argument(
        "--mode",
        choices=sorted(SUPPORTED_MODES),
        required=True,
        help="Execution mode to inspect",
    )
    doctor.add_argument(
        "--project-dir",
        type=Path,
        default=default_project_dir(),
        help="Directory containing TOTENKAHN configuration and scripts",
    )
    doctor.add_argument(
        "--release-dir",
        type=Path,
        help="Optional pristine release directory to verify against its manifest",
    )
    doctor.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    doctor.add_argument(
        "--output",
        type=Path,
        help="Save a new JSON report; existing files are not overwritten",
    )
    doctor.add_argument(
        "--plan",
        action="store_true",
        help="Include a non-executable dependency preparation plan",
    )
    install = commands.add_parser(
        "install",
        help="Install a verified release and private ART modules",
    )
    install.add_argument("--release-dir", type=Path, default=default_project_dir())
    install.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "totenkahn",
    )
    install.add_argument("--cache", type=Path)
    install.add_argument("--offline", action="store_true")
    install.add_argument("--external-yaml", type=Path)
    install.add_argument("--external-art", type=Path)
    install.add_argument("--timeout", type=int, default=180)
    uninstall = commands.add_parser(
        "uninstall", help="Remove owned unchanged files; preserve evidence"
    )
    uninstall.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "totenkahn",
    )
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Confirm removal without prompting",
    )

    for subparser in (install, uninstall):
        subparser.add_argument("--json", action="store_true")
        subparser.add_argument("--output", type=Path)

    args = parser.parse_args(argv)

    if args.command in {"install", "uninstall"}:
        return run_setup_command(args)

    project_dir = args.project_dir.absolute()
    release_dir = args.release_dir.absolute() if args.release_dir is not None else None
    report = run_doctor(project_dir, mode=args.mode, release_dir=release_dir)

    if args.plan:
        try:
            catalog = load_component_catalog(project_dir / "config" / "components.json")
            lock = load_dependency_lock(project_dir / "config" / "dependencies.lock.json")
            validate_lock_coverage(catalog, lock)

            if report["environment"] is None:
                raise ValueError("A dependency plan requires an environment report")

            report["dependency_plan"] = build_dependency_plan(report["environment"], catalog)

            if (
                report["status"] == "passed"
                and report["dependency_plan"]["status"] == "needs_action"
            ):
                report["status"] = "needs_verification"
        except (OSError, ValueError) as exc:
            report["errors"].append({"stage": "dependency_plan", "reason": str(exc)})
            report["status"] = "error"

    if args.output is not None:
        try:
            save_report(args.output, report)
        except (OSError, ValueError) as exc:
            report["errors"].append({"stage": "report_output", "reason": str(exc)})
            report["status"] = "error"

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False))
    else:
        print_summary(report)

    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
