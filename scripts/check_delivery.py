import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers import delivery
from handlers.offline_acceptance import STAGES
from handlers.release_manifest import REQUIRED_FILES, build_manifest, write_manifest, describe_file


def offline_report():
    return {
        "status": "passed", "scope": "five_stage_synthetic_offline_acceptance",
        "selected_stages": [1, 2, 3, 4, 5], "atomic_tests_executed": 0,
        "external_services_used": [], "host_configuration_changes": False,
        "stages": [
            {"id": identity, "status": "passed", "checks": [{"name": name, "status": "passed"} for name in checks]}
            for identity, _, checks in STAGES
        ],
    }


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-delivery-test-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / "delivery"
        self.source, self.first = self.release("one")
        self.other, self.second = self.release("two")

    def release(self, name):
        release = self.home / name

        for relative in sorted(REQUIRED_FILES | {"examples/inert.json"}):
            path = release / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding="utf-8")

        write_manifest(release, build_manifest(release, version=name, source_commit="a" * 40))
        return release, describe_file(release / "release-manifest.json")["sha256"]

    def execute(self, arguments, work, name, environment, timeout):
        self.assertEqual(environment["TOTENKAHN_HOME"], str(work / "isolated-data"))
        self.assertGreater(timeout, 0)
        (work / (name + ".stdout.txt")).write_text("inert test adapter", encoding="utf-8")
        (work / (name + ".stderr.txt")).write_text("", encoding="utf-8")

        if name == "offline":
            self.assertIn("self-test", arguments)
            directory = work / "offline"
            directory.mkdir()
            (directory / "report.json").write_text(json.dumps(offline_report()), encoding="utf-8")

    def accept(self, source=None, release_id=None):
        source, release_id = source or self.source, release_id or self.first
        delivery.stage(self.root, source, release_id)

        with patch.object(delivery.sys, "platform", "win32"), patch.object(delivery, "execute", side_effect=self.execute):
            result = delivery.test_release(self.root, release_id)

        self.assertEqual(result["status"], "passed", result)
        return result

    def activate(self, release_id=None, **extra):
        return delivery.promote(self.root, release_id or self.first, reviewer="Engineer", reason="Reviewed candidate limitations", approved=True, **extra)

    def test_cli_help_and_explicit_approval(self):
        from handlers.delivery_cli import main

        with patch("handlers.delivery_cli.emit_result"):
            result = main(["stage", "--root", str(self.root), "--release-dir", str(self.source), "--expected-sha256", self.first])
            self.assertEqual(result, 0)
            self.accept()

            with self.assertRaises(ValueError):
                main(["activate", "--root", str(self.root), "--release", self.first, "--reviewer", "Engineer", "--reason", "Reviewed"])

            self.assertEqual(main(["activate", "--root", str(self.root), "--release", self.first, "--reviewer", "Engineer", "--reason", "Reviewed", "-y"]), 0)

        with patch.object(delivery, "run_active", return_value=7) as execute:
            self.assertEqual(main(["run", "--root", str(self.root), "--", "dump", "profiles", "--json"]), 7)
            execute.assert_called_once_with(self.root, ["dump", "profiles", "--json"])

    def test_retest_failure_invalidates_pending_but_not_active_acceptance(self):
        self.accept()
        self.activate()

        with patch.object(delivery.sys, "platform", "win32"), patch.object(delivery, "execute", side_effect=ValueError("new test failed")):
            self.assertEqual(delivery.test_release(self.root, self.first)["status"], "error")

        self.assertEqual(delivery.status(self.root)["active"], self.first)

        with self.assertRaises(FileNotFoundError):
            self.activate()

    def test_reapproval_binds_latest_receipt_without_losing_previous(self):
        first_receipt = self.accept()
        self.activate()
        self.accept(self.other, self.second)
        self.activate(self.second)
        replacement = self.accept(self.other, self.second)
        self.activate(self.second)
        state = delivery.read_state(self.root)
        self.assertEqual(state["previous"], self.first)
        self.assertEqual(state["history"][-1]["acceptance"]["receipt"], Path(replacement["report"]).relative_to(self.root).as_posix())
        self.assertTrue(Path(first_receipt["report"]).is_file())

    def test_wrong_rollback_target_rejected(self):
        self.accept()
        self.activate()
        self.accept(self.other, self.second)
        self.activate(self.second)

        with self.assertRaises(ValueError):
            delivery.promote(self.root, self.second, rollback=True, reviewer="Engineer", reason="Reviewed", approved=True)

        self.assertEqual(delivery.read_state(self.root)["active"], self.second)

    def test_packaging_exports_reviewed_release_identity(self):
        from scripts.package_ci_release import package

        build = self.home / "build"
        build.mkdir()
        import shutil
        shutil.copytree(self.source, build / "release")

        for relative, value in (
            ("build-report.json", {"status": "passed_with_warnings", "build_status": "passed", "acceptance_status": "passed_with_warnings", "limitations": ["Live test pending"]}),
            ("acceptance/report.json", {"status": "passed_with_warnings"}),
            ("ci/report.json", {"status": "passed"}),
        ):
            path = build / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")

        output = self.home / "export"
        package(build, output)
        review = delivery.read_json(output / "delivery-review.json")
        self.assertEqual(review["release_id"], self.first)
        self.assertEqual(review["acceptance_status"], "passed_with_warnings")
        self.assertEqual(review["limitations"], ["Live test pending"])
        self.assertEqual((output / "RELEASE_SHA256SUMS").read_text().split()[0], self.first)

    def test_delivery_workflow_is_manual_and_has_no_secret_access(self):
        import yaml

        workflow = yaml.load((ROOT / "examples/ci-workflows/controlled-delivery.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(list(workflow["on"]), ["workflow_dispatch"])
        self.assertEqual(workflow["concurrency"]["cancel-in-progress"], "false")
        step = workflow["jobs"]["delivery"]["steps"][0]
        self.assertNotIn("secrets.", json.dumps(workflow))
        self.assertNotIn("${{", step["run"])
        self.assertIn("'--release', $env:DELIVERY_RELEASE", step["run"])
        self.assertNotIn("--insecure", step["run"])

    def test_stage_does_not_activate_and_repeat_verifies(self):
        delivery.stage(self.root, self.source, self.first)
        self.assertIsNone(delivery.read_state(self.root)["active"])
        self.assertTrue(delivery.stage(self.root, self.source, self.first)["repeated"])
        (delivery.slot(self.root, self.first) / "totenkahn.exe").write_text("changed")

        with self.assertRaises(ValueError):
            delivery.stage(self.root, self.source, self.first)

    def test_wrong_reviewed_hash_and_changed_source_rejected(self):
        with self.assertRaises(ValueError):
            delivery.stage(self.root, self.source, "0" * 64)

        (self.source / "README.md").write_text("changed")

        with self.assertRaises(ValueError):
            delivery.stage(self.root, self.source, self.first)

        self.assertFalse(self.root.exists())

    def test_stage_failure_keeps_active(self):
        self.accept()
        self.activate()
        original = delivery.read_state(self.root)

        with patch.object(delivery.shutil, "copytree", side_effect=OSError("copy denied")):
            with self.assertRaises(OSError):
                delivery.stage(self.root, self.other, self.second)

        self.assertEqual(delivery.read_state(self.root), original)

    def test_activation_requires_test_and_explicit_approval(self):
        delivery.stage(self.root, self.source, self.first)

        with self.assertRaises(FileNotFoundError):
            self.activate()

        self.accept()

        with self.assertRaises(ValueError):
            delivery.promote(self.root, self.first, reviewer="Engineer", reason="Review")

        self.assertIsNone(delivery.read_state(self.root)["active"])

    def test_full_lifecycle_preserves_external_evidence(self):
        evidence = self.home / "evidence.json"
        evidence.write_text("original evidence")
        self.accept()
        self.activate()
        self.accept(self.other, self.second)
        self.activate(self.second)
        result = delivery.promote(self.root, rollback=True, approved=True, reviewer="Engineer", reason="Return to previous accepted version")
        self.assertEqual(result["active"], self.first)
        self.assertEqual(result["previous"], self.second)
        self.assertEqual(evidence.read_text(), "original evidence")
        self.assertTrue(delivery.slot(self.root, self.second).is_dir())
        self.assertEqual(delivery.status(self.root)["status"], "passed")

    def test_tampered_receipt_or_report_blocks_activation(self):
        result = self.accept()
        receipt = Path(result["report"])
        report = receipt.parent / "offline/report.json"
        report.write_text("{}")

        with self.assertRaises(ValueError):
            self.activate()

        result = self.accept()
        Path(result["report"]).write_text("{}")

        with self.assertRaises(ValueError):
            self.activate()

    def test_failed_execution_and_timeout_never_record_acceptance(self):
        delivery.stage(self.root, self.source, self.first)

        for exception in (ValueError("subprocess failed"), subprocess.TimeoutExpired("inert", 1)):
            with patch.object(delivery.sys, "platform", "win32"), patch.object(delivery, "execute", side_effect=exception):
                result = delivery.test_release(self.root, self.first)

            self.assertEqual(result["status"], "error")
            self.assertTrue(Path(result["report"]).is_file())
            self.assertFalse((self.root / "tested" / (self.first + ".json")).exists())

    def test_partial_or_duplicate_stage_checks_rejected(self):
        for mutation in ("missing", "duplicate", "failed", "atomic", "subset"):
            report = offline_report()

            if mutation == "missing":
                report["stages"].pop()
            elif mutation == "duplicate":
                report["stages"][0]["checks"][1] = report["stages"][0]["checks"][0]
            elif mutation == "failed":
                report["stages"][2]["checks"][0]["status"] = "failed"
            elif mutation == "atomic":
                report["atomic_tests_executed"] = 1
            else:
                report["selected_stages"] = [1]

            with self.assertRaises(ValueError, msg=mutation):
                delivery.validate_offline(report)

    def test_changed_previous_release_blocks_rollback(self):
        self.accept()
        self.activate()
        self.accept(self.other, self.second)
        self.activate(self.second)
        (delivery.slot(self.root, self.first) / "totenkahn.exe").write_text("changed")

        with self.assertRaises(ValueError):
            delivery.promote(self.root, rollback=True, approved=True, reviewer="Engineer", reason="Review")

        self.assertEqual(delivery.read_state(self.root)["active"], self.second)

    def test_failed_state_replace_preserves_previous_pointer(self):
        self.accept()
        self.activate()
        self.accept(self.other, self.second)

        with patch.object(delivery.os, "replace", side_effect=OSError("denied")):
            with self.assertRaises(OSError):
                self.activate(self.second)

        self.assertEqual(delivery.read_state(self.root)["active"], self.first)

    def test_first_version_has_no_rollback(self):
        self.accept()
        self.activate()

        with self.assertRaises(ValueError):
            delivery.promote(self.root, rollback=True, approved=True, reviewer="Engineer", reason="Review")

    def test_invalid_ids_and_linked_store_rejected(self):
        with self.assertRaises(ValueError):
            delivery.slot(self.root, "../../elsewhere")

        with self.assertRaises(ValueError):
            delivery.stage(self.source / "nested", self.source, self.first)

        try:
            self.root.symlink_to(self.other, target_is_directory=True)
        except OSError as exc:
            self.skipTest("Symlinks unavailable: " + str(exc))

        with self.assertRaises(ValueError):
            delivery.stage(self.root, self.source, self.first)

    def test_lock_blocks_concurrent_mutation(self):
        delivery.stage(self.root, self.source, self.first)

        with delivery.installation_lock(self.root):
            with self.assertRaises(RuntimeError):
                delivery.stage(self.root, self.other, self.second)

    def test_non_windows_execution_is_rejected(self):
        with patch.object(delivery.sys, "platform", "linux"):
            with self.assertRaises(ValueError):
                delivery.test_release(self.root, self.first)

    def test_run_uses_verified_active_binary_and_separate_data(self):
        self.accept()
        self.activate()

        with patch.object(delivery.sys, "platform", "win32"), patch.object(delivery.subprocess, "call", return_value=0) as child:
            self.assertEqual(delivery.run_active(self.root, ["--help"]), 0)

        self.assertEqual(child.call_args.args[0], [str(delivery.slot(self.root, self.first) / "totenkahn.exe"), "--help"])
        self.assertIn("TOTENKAHN_HOME", child.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
