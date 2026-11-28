import argparse
from pathlib import Path

from handlers import delivery
from handlers.cli_result import emit_result, status_code


def main(argv):
    parser = argparse.ArgumentParser(
        prog="totenkahn-setup delivery",
        description="Stage -> test -> review -> activate. Rollback selects the previous accepted executable; evidence and host settings are not reverted.",
        epilog="Use the complete release directory. Obtain --expected-sha256 from the reviewed build's RELEASE_SHA256SUMS. SHA-256 verifies bytes, not publisher identity.",
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    for name, help_text in (
        ("inspect", "Verify source files against a reviewed manifest hash; no installation"),
        ("stage", "Copy a verified release alongside existing versions; do not activate"),
        ("test", "Run both startup checks and all five offline stages in isolated data"),
        ("activate", "Explicitly approve a tested release after reviewing build/live limitations"),
        ("rollback", "Select the previous approved release after rechecking its integrity"),
        ("status", "Show active/previous versions and approval history"),
        ("run", "Launch the verified active version; place its arguments after --"),
    ):
        command = commands.add_parser(name, help=help_text, description=help_text)
        command.add_argument("--root", type=Path, default=delivery.default_root(), help="Version store; defaults to the current user's totenkahn-delivery directory")

        if name != "run":
            command.add_argument("--json", action="store_true", help="Machine-readable result")

        if name in ("inspect", "stage"):
            command.add_argument("--release-dir", type=Path, required=True)
            command.add_argument("--expected-sha256", required=True, help="Reviewed release-manifest.json SHA-256, not the ZIP hash")

        if name in ("test", "activate"):
            command.add_argument("--release", required=True, help="Release ID printed by stage")

        if name == "rollback":
            command.add_argument("--release", help="Optional expected previous release ID; reject a different target")

        if name in ("activate", "rollback"):
            command.add_argument("-y", "--yes", action="store_true", help="Explicit approval of activation/rollback and reviewed limitations")
            command.add_argument("--reviewer", required=True)
            command.add_argument("--reason", required=True, help="Review outcome, acknowledged limitations and approval reason")

        if name == "test":
            command.add_argument("--timeout", type=int, default=600, help="Maximum seconds for the five-stage subprocess (1..3600)")

        if name == "run":
            command.add_argument("arguments", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)

    if args.operation == "run":
        arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
        return delivery.run_active(args.root, arguments)

    if args.operation == "inspect":
        result = delivery.inspect_release(args.release_dir, args.expected_sha256)
    elif args.operation == "stage":
        result = delivery.stage(args.root, args.release_dir, args.expected_sha256)
    elif args.operation == "test":
        if not 1 <= args.timeout <= 3600:
            parser.error("--timeout must be between 1 and 3600")

        result = delivery.test_release(args.root, args.release, args.timeout)
    elif args.operation in ("activate", "rollback"):
        result = delivery.promote(
            args.root, getattr(args, "release", None), reviewer=args.reviewer, reason=args.reason,
            approved=args.yes, rollback=args.operation == "rollback",
        )
    else:
        result = delivery.status(args.root)

    emit_result(result, "Delivery / " + args.operation, json_output=args.json)

    return status_code(result["status"])
