import io
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers import test_cli


class TestWorkflowTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.rule = self.root / "rule.yaml"
        self.rule.write_text(
            "title: fixture\nlogsource: {product: windows, category: process_creation}\ndetection:\n  selection: {Image: fixture}\n  condition: selection\n"
        )
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.mocks = {}

        for name, value in {
            "runtime_config": {},
            "validate_live_logsource": None,
            "telemetry.requirements": {"channels": ["Security"]},
            "telemetry.inspect": {"status": "passed"},
            "telemetry.prepare": {"status": "passed"},
            "dependencies.status": {"status": "passed"},
            "ensure_ready": {"status": "passed"},
            "resource_plan": {"status": "planned", "files": {}, "reason": None},
            "prepare_resources": {"status": "passed"},
            "build_plan": {},
            "confirm": True,
            "emit_result": None,
        }.items():
            self.mocks[name] = self.stack.enter_context(
                patch("handlers.test_cli." + name, return_value=value)
            )

        self.stack.enter_context(patch.object(test_cli.sys, "platform", "win32"))

    def invoke(self, *extra, mode="auto"):
        args = [mode, "--rule", str(self.rule)]

        if mode == "auto":
            args += ["--technique", "T1033", "8"]

        return test_cli.prepare_invocation(self.root, args + list(extra))

    def test_yes_aliases_approve_scenario_without_enabling_extra_operations(self):
        for flag in ("-y", "--yes"):
            with self.subTest(flag=flag):
                self.mocks["build_plan"].side_effect = ValueError("not installed")
                self.mocks["telemetry.inspect"].side_effect = [
                    {"status": "needs_action", "actions": []},
                    {"status": "passed"},
                ]
                self.mocks["confirm"].reset_mock()
                args = self.invoke(flag)
                self.assertTrue(self.mocks["ensure_ready"].call_args.kwargs["yes"])
                self.assertTrue(all(call.args[1] for call in self.mocks["confirm"].call_args_list))
                self.assertIn("--approve-atomic", args)
                self.assertNotIn("--prepare-prereqs", args)
                self.assertNotIn("--cleanup", args)
                self.assertFalse(self.mocks["telemetry.prepare"].call_args.kwargs["accept_eula"])

    def test_yes_manual_approves_only_telemetry(self):
        self.mocks["telemetry.inspect"].side_effect = [
            {"status": "needs_action", "actions": []}, {"status": "passed"}
        ]
        args = self.invoke("-y", mode="manual")
        self.assertTrue(self.mocks["confirm"].call_args.args[1])
        self.assertNotIn("--approve-atomic", args)
        self.mocks["ensure_ready"].assert_not_called()
        self.mocks["resource_plan"].assert_not_called()

    def test_yes_plan_still_does_not_execute(self):
        with self.assertRaises(SystemExit) as stopped:
            self.invoke("--yes", "--plan")
        self.assertEqual(stopped.exception.code, 0)
        for name in ("ensure_ready", "prepare_resources", "telemetry.prepare", "confirm"):
            self.mocks[name].assert_not_called()

    def test_yes_does_not_override_blocked_readiness(self):
        self.mocks["telemetry.inspect"].return_value = {"status": "blocked"}
        with self.assertRaises(SystemExit):
            self.invoke("--yes")
        self.mocks["ensure_ready"].assert_not_called()
        self.mocks["prepare_resources"].assert_not_called()
        self.mocks["telemetry.prepare"].assert_not_called()

    def test_yes_replay_adds_no_host_operations(self):
        session = self.root / "session"
        session.mkdir()
        (session / "events.json").write_text("[]")
        args = self.invoke("-y", "--session", str(session), mode="replay")
        self.assertNotIn("--approve-atomic", args)
        self.mocks["ensure_ready"].assert_not_called()
        self.mocks["telemetry.inspect"].assert_not_called()

    def test_verbosity_survives_translation_without_approving_execution(self):
        args = self.invoke("-vv")
        self.assertEqual(args.count("-v"), 2)
        self.assertNotIn("--approve-atomic", args)

    def test_ready_auto_returns_legacy_execution_without_install(self):
        args = self.invoke("--input", "whoami_args=/all")
        self.assertIn("--auto", args)
        self.assertEqual(
            args[args.index("--atomic-test") + 1 : args.index("--atomic-test") + 3], ["T1033", "8"]
        )
        self.mocks["prepare_resources"].assert_not_called()
        self.mocks["telemetry.prepare"].assert_not_called()
        self.mocks["confirm"].assert_not_called()
        self.assertNotIn("--approve-atomic", args)

    def test_first_run_prepares_selected_files_then_rechecks_host(self):
        self.mocks["build_plan"].side_effect = ValueError("not installed")
        self.mocks["telemetry.inspect"].side_effect = [
            {"status": "needs_action", "actions": []},
            {"status": "passed"},
        ]
        args = self.invoke("--approve-dependencies", "--approve-telemetry")
        self.mocks["prepare_resources"].assert_called_once()
        self.mocks["telemetry.prepare"].assert_called_once()
        self.assertEqual(self.mocks["telemetry.inspect"].call_count, 2)
        self.assertNotIn("--approve-atomic", args)

    def test_declined_resource_preparation_stops_before_host_changes(self):
        self.mocks["build_plan"].side_effect = ValueError("not installed")
        self.mocks["confirm"].return_value = False

        with self.assertRaises(SystemExit):
            self.invoke()

        self.mocks["prepare_resources"].assert_not_called()
        self.mocks["telemetry.prepare"].assert_not_called()

    def test_manual_never_requests_atomic(self):
        args = self.invoke(mode="manual")
        self.assertIn("--manual", args)
        self.mocks["ensure_ready"].assert_not_called()
        self.mocks["resource_plan"].assert_not_called()

    def test_replay_has_no_host_or_dependency_operations(self):
        session = self.root / "session"
        session.mkdir()
        (session / "events.json").write_text("[]")
        args = self.invoke("--session", str(session), mode="replay")
        self.assertIn("--skip-dependencies", args)
        self.mocks["ensure_ready"].assert_not_called()
        self.mocks["telemetry.inspect"].assert_not_called()

    def test_plan_is_inspection_only(self):
        with self.assertRaises(SystemExit) as stopped:
            self.invoke("--plan")

        self.assertEqual(stopped.exception.code, 0)

        for name in (
            "ensure_ready",
            "resource_plan",
            "prepare_resources",
            "telemetry.prepare",
            "confirm",
        ):
            self.mocks[name].assert_not_called()

    def test_invalid_number_stops_before_actions(self):
        out = io.StringIO()

        with redirect_stderr(out), self.assertRaises(SystemExit):
            test_cli.prepare_invocation(
                self.root, ["auto", "--rule", str(self.rule), "--technique", "T1033", "wrong"]
            )

        self.assertIn("T1033 8", out.getvalue())
        self.assertNotIn("usage:", out.getvalue())
        self.mocks["ensure_ready"].assert_not_called()

    def test_missing_rule_error_has_path_and_example(self):
        self.rule.unlink()
        out = io.StringIO()

        with redirect_stderr(out), self.assertRaises(SystemExit):
            self.invoke()

        self.assertIn(str(self.rule), out.getvalue())
        self.assertIn("Examples", out.getvalue())
        self.mocks["telemetry.inspect"].assert_not_called()

    def test_missing_technique_number_is_actionable(self):
        out = io.StringIO()

        with redirect_stderr(out), self.assertRaises(SystemExit):
            test_cli.prepare_invocation(
                self.root, ["auto", "--rule", str(self.rule), "--technique", "T1033"]
            )

        self.assertIn("TWO values", out.getvalue())

    def test_manual_rejects_atomic_options(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.invoke("--technique", "T1033", "8", mode="manual")

        self.mocks["telemetry.inspect"].assert_not_called()

    def test_offline_passes_to_module_and_selected_preparation(self):
        self.invoke("--offline")
        self.assertTrue(self.mocks["ensure_ready"].call_args.kwargs["offline"])
        self.assertTrue(self.mocks["resource_plan"].call_args.kwargs["offline"])

    def test_blocked_telemetry_stops_before_install(self):
        self.mocks["telemetry.inspect"].return_value = {
            "status": "blocked",
            "reason": "insufficient rights",
        }

        with self.assertRaises(SystemExit):
            self.invoke()

        self.mocks["ensure_ready"].assert_not_called()

    def test_no_atomic_approval_inferred_from_host_approval(self):
        args = self.invoke("--approve-telemetry", "--approve-dependencies")
        self.assertNotIn("--approve-atomic", args)
        args = self.invoke("--approve-atomic")
        self.assertIn("--approve-atomic", args)

    def test_failed_preparation_does_not_proceed(self):
        self.mocks["build_plan"].side_effect = ValueError("missing")
        self.mocks["prepare_resources"].return_value = {"status": "error"}

        with self.assertRaises(SystemExit):
            self.invoke()

        self.mocks["telemetry.prepare"].assert_not_called()

    def test_offline_sysmon_does_not_download(self):
        self.mocks["telemetry.inspect"].return_value = {
            "status": "needs_action",
            "actions": [{"key": "sysmon"}],
        }

        with self.assertRaises(SystemExit):
            self.invoke("--offline", mode="manual")

        self.mocks["telemetry.prepare"].assert_not_called()

    def test_declined_telemetry_stops(self):
        self.mocks["telemetry.inspect"].return_value = {"status": "needs_action", "actions": []}
        self.mocks["confirm"].return_value = False

        with self.assertRaises(SystemExit):
            self.invoke(mode="manual")

        self.mocks["telemetry.prepare"].assert_not_called()

    def test_post_preparation_readiness_failure_stops(self):
        self.mocks["telemetry.inspect"].side_effect = [
            {"status": "needs_action", "actions": []},
            {"status": "blocked"},
        ]

        with self.assertRaises(SystemExit):
            self.invoke(mode="manual")

    def test_missing_replay_evidence_is_not_installed_around(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.invoke("--session", str(self.root / "absent"), mode="replay")

        self.mocks["ensure_ready"].assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
