import os
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_evidence import EvidenceTests
from check_dump_analysis import DumpAnalysisTests
from check_cases import CaseTests
from check_hunts import HuntTests
from check_findings import FindingTests
from check_terminal import TerminalTests
from check_source_depth import SourceDepthTests
from check_input_values import InputValueTests
from check_ci import CITests
from check_rule_revisions import RuleRevisionTests
from check_elastic_ci import ElasticCIContractTests
from check_dependencies import DependencyTests
from check_atomic_resources import ResourceTests
from check_test_cli import TestWorkflowTests
from check_preflight_display import PreflightDisplayTests
from check_offline_acceptance import OfflineAcceptanceTests
from check_operations import OperationsTests
from check_atomic_lifecycle import AtomicLifecycleTests
from check_telemetry import TelemetryTests
from check_stability import StabilityTests
from check_installation import InstallationTests
from check_explanations import ExplanationTests
from check_detection_context import ContextTests
from check_release_acceptance import AcceptanceTests
from release_acceptance import run_application_reports, verify_preserved
from handlers.atomic_bundle_check import check_atomic_bundle
from handlers.component_inventory import utc_now
from handlers.cli_result import run_cli, status_code, STATUS_CODES
from handlers.release_manifest import verify_release


def acceptance(release, cache, work, timeout):
    release = release.resolve(strict=True)
    integrity = verify_release(release)

    if integrity["status"] != "passed":
        raise ValueError("Release integrity failed: " + json.dumps(integrity))

    setup_exe = release / "totenkahn-setup.exe"
    target = work / "installed"
    steps = []

    def invoke(name, arguments, expected=0):
        print(f"Checking release lifecycle: {name}", flush=True)
        completed = subprocess.run(
            [str(setup_exe), *arguments, "--json"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
        )
        (work / (name + ".stdout.txt")).write_bytes(completed.stdout)
        (work / (name + ".stderr.txt")).write_bytes(completed.stderr)
        report = json.loads(completed.stdout.decode("utf-8-sig"))
        steps.append({"step": name, "exit_code": completed.returncode, "report": report})

        if completed.returncode != expected:
            raise ValueError(
                f"{name}: expected exit {expected}, got {completed.returncode}; see {work}"
            )

        return report

    install_args = [
        "install",
        "--release-dir",
        str(release),
        "--target-dir",
        str(target),
        "--cache",
        str(cache),
        "--offline",
    ]

    try:
        result = invoke("install", install_args)

        if result.get("installation_status") != "installed":
            raise ValueError("Installation did not reach installed state")

        result = invoke("repeat", install_args)

        if not result.get("repeated"):
            raise ValueError("Repeat was not recognized")

        invoke("doctor", ["doctor", "--project-dir", str(target), "--mode", "replay"])
        application = run_application_reports(target, work, timeout)
        invoke(
            "doctor-after-reports",
            ["doctor", "--project-dir", str(target), "--mode", "replay"],
        )
        evidence = target / "runs" / "acceptance-evidence.txt"
        evidence.parent.mkdir(exist_ok=True)
        evidence.write_text("preserve acceptance evidence", encoding="utf-8")
        state_path = target / ".totenkahn-state/installation.json"
        before = state_path.read_bytes()
        invoke("dry-run", ["uninstall", "--target-dir", str(target), "--dry-run"])

        if before != state_path.read_bytes() or not (target / "totenkahn.exe").is_file():
            raise ValueError("Dry run modified the installation")

        invoke("uninstall", ["uninstall", "--target-dir", str(target), "--yes"])

        if (target / "totenkahn.exe").exists() or (
            evidence.read_text(encoding="utf-8") != "preserve acceptance evidence"
        ):
            raise ValueError("Removal or evidence preservation failed")

        invoke("repeat-uninstall", ["uninstall", "--target-dir", str(target), "--yes"])
        verify_preserved(target / "reports", application["report_fingerprints"])

        return {
            "status": "passed",
            "steps": steps,
            "application_reports": application,
            "generated_reports_preserved": True,
        }
    finally:
        (work / "release-steps.json").write_text(
            json.dumps(steps, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def portable_acceptance(release, cache, work, timeout):
    release = release.resolve(strict=True)

    if verify_release(release)["status"] != "passed":
        raise ValueError("Portable release integrity failed")

    home = work / "user-data"
    env = dict(os.environ, TOTENKAHN_HOME=str(home), PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    steps = []
    limitations = []

    def invoke(name, arguments, *, required=True):
        print(f"Checking portable lifecycle: {name}", flush=True)
        completed = subprocess.run(
            [str(release / "totenkahn.exe"), *arguments, "--json"],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
        )
        (work / (name + ".stdout.txt")).write_bytes(completed.stdout)
        (work / (name + ".stderr.txt")).write_bytes(completed.stderr)
        result = json.loads(completed.stdout.decode("utf-8-sig"))
        steps.append({"step": name, "exit_code": completed.returncode, "report": result})

        if (result.get("status") not in STATUS_CODES) or (
            completed.returncode != status_code(result["status"])
        ):
            raise ValueError("Invalid CLI status/exit-code contract: " + name)

        if result["status"] == "interrupted":
            raise KeyboardInterrupt()

        if result["status"] != "passed":
            if required:
                raise ValueError(name + " did not pass; inspect " + str(work))

            limitations.append({"step": name, "status": result["status"], "report": result})

        return result

    try:
        previous = os.environ.get("TOTENKAHN_HOME")
        os.environ["TOTENKAHN_HOME"] = str(home)

        try:
            reports = run_application_reports(
                release,
                work,
                timeout,
                skip_dependencies=True,
                reports_directory=home / "reports",
            )
        finally:
            if previous is None:
                os.environ.pop("TOTENKAHN_HOME", None)
            else:
                os.environ["TOTENKAHN_HOME"] = previous

        prepared = invoke(
            "prepare",
            ["dependencies", "prepare", "--yes", "--offline", "--cache", str(cache)],
            required=False,
        )

        if prepared["status"] == "passed":
            if prepared.get("atomic_profile") != "modules_only":
                raise ValueError("Fresh setup did not use modules-only profile")

            generation = Path(prepared["generation"])

            if (generation / "managed/atomics").exists() or (
                generation / "managed/selected"
            ).exists():
                raise ValueError(
                    "Base setup unexpectedly materialized Atomic definitions/resources"
                )

            invoke(
                "repeat-prepare",
                ["dependencies", "prepare", "--yes", "--offline", "--cache", str(cache)],
            )
        else:
            steps.append(
                {
                    "step": "repeat-prepare",
                    "status": "skipped",
                    "reason": "Base preparation was incomplete",
                },
            )

        invoke("doctor", ["doctor", "--mode", "replay"])
        invoke("dry-run", ["dependencies", "remove", "--dry-run"])
        invoke("remove", ["dependencies", "remove", "--yes"], required=False)
        invoke("repeat-remove", ["dependencies", "remove", "--yes"], required=False)
        verify_preserved(home / "reports", reports["report_fingerprints"])

        if verify_release(release)["status"] != "passed":
            raise ValueError("Portable preparation modified the release")

        return {
            "status": "passed_with_warnings" if limitations else "passed",
            "core_status": "passed",
            "steps": steps,
            "application_reports": reports,
            "limitations": limitations,
            "atomic_readiness": {
                "status": "not_tested",
                "reason": "Definitions, resources and execution are selected-test operations",
            },
            "scope": "portable_core_with_separate_module_readiness",
            "release_unchanged": True,
        }
    finally:
        (work / "portable-steps.json").write_text(
            json.dumps(steps, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def main():
    parser = argparse.ArgumentParser(
        description="Run source regression checks and optional real Windows release acceptance.\n\nNo Atomic tests are executed. Only a newly created temporary target is removed.\n"
    )
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="Run inert source tests only; do not probe or install real components",
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Verify first-run dependency lifecycle without installing the application",
    )
    parser.add_argument("--cache", type=Path, default=ROOT / ".totenkahn-package-cache")
    parser.add_argument("--release-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="New persistent directory for logs and reports",
    )
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    if args.output_dir is None:
        work = Path(tempfile.mkdtemp(prefix="totenkahn-stage-acceptance-"))
    else:
        work = args.output_dir.resolve()
        work.mkdir(parents=True, exist_ok=False)

    report = {
        "checked_at": utc_now(),
        "status": "error",
        "platform": sys.platform,
        "artifacts": str(work),
        "atomic_tests_executed": 0,
        "checks": {},
        "scope": (
            "portable_dependencies_and_synthetic_executable_reports"
            if args.portable
            else "installer_and_synthetic_executable_reports"
        ),
        "not_tested": ["live_collection", "atomic_execution", "clean_machine_online_bootstrap"],
    }

    try:
        with (work / "regression.txt").open("w", encoding="utf-8") as log:
            suite = unittest.TestSuite(
                (
                    unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                    for cls in (
                        InstallationTests,
                        ExplanationTests,
                        ContextTests,
                        AcceptanceTests,
                        DependencyTests,
                        AtomicLifecycleTests,
                        TelemetryTests,
                        EvidenceTests,
                        DumpAnalysisTests,
                        CaseTests,
                        HuntTests,
                        FindingTests,
                        TerminalTests,
                        SourceDepthTests,
                        InputValueTests,
                        StabilityTests,
                        ResourceTests,
                        TestWorkflowTests,
                        PreflightDisplayTests,
                        OfflineAcceptanceTests,
                        OperationsTests,
                        CITests,
                        RuleRevisionTests,
                        ElasticCIContractTests,
                    )
                ),
            )
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)

        report["checks"]["regression"] = {
            "status": "passed" if result.wasSuccessful() else "failed",
            "tests": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        }

        if not result.wasSuccessful():
            raise ValueError("Lifecycle regression failed; see regression.txt")

        print(
            f"Source tests: {result.testsRun - len(result.skipped)} passed, {len(result.skipped)} skipped, {result.testsRun} total",
            flush=True,
        )

        if args.source_only:
            report["scope"] = "source_regression_only"
            report["status"] = "needs_verification" if result.skipped else "passed"
        elif sys.platform != "win32":
            report["status"] = "needs_verification"
            report["pending"] = ["Real module probe and executable acceptance require Windows"]
        else:
            try:
                probe = check_atomic_bundle(
                    ROOT / "config/dependencies.lock.json",
                    args.cache.resolve(),
                    offline=True,
                    timeout_seconds=args.timeout,
                )
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                probe = {"status": "error", "reason": str(exc), "error_type": type(exc).__name__}

            report["checks"]["windows_modules"] = probe

            if args.release_dir is None:
                report["status"] = "needs_verification"
                report["pending"] = ["Supply --release-dir for executable acceptance"]
            elif args.portable:
                release_result = portable_acceptance(
                    args.release_dir, args.cache.resolve(), work, args.timeout
                )
                report["checks"]["windows_release"] = release_result
                report["limitations"] = list(release_result["limitations"])

                if probe["status"] != "passed":
                    report["limitations"].append({"step": "windows_modules", "report": probe})

                report["status"] = (
                    "needs_verification"
                    if result.skipped
                    else "passed_with_warnings" if report["limitations"] else "passed"
                )
            elif probe["status"] != "passed":
                report["status"] = "blocked" if probe["status"] == "blocked" else "error"
            else:
                report["checks"]["windows_release"] = acceptance(
                    args.release_dir, args.cache.resolve(), work, args.timeout
                )
                report["status"] = "needs_verification" if result.skipped else "passed"

            if result.skipped:
                report["pending"] = ["Resolve or review skipped platform-specific regression tests"]
    except KeyboardInterrupt:
        report.update(
            status="interrupted",
            reason="Source/acceptance checks interrupted; available logs retained",
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        subprocess.TimeoutExpired,
    ) as exc:
        report.update(status="error", reason=str(exc), error_type=type(exc).__name__)

    destination = work / "report.json"
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "artifacts": str(work),
                "reason": report.get("reason"),
                "pending": report.get("pending", []),
                "checks": {key: value["status"] for key, value in report["checks"].items()},
            },
            ensure_ascii=False,
            indent=2,
        ),
    )
    print(f"Report: {destination}")

    return status_code(report["status"])


if __name__ == "__main__":
    raise SystemExit(run_cli(main))
