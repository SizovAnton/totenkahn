import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.atomic_lifecycle import (
    build_plan,
    parse_inputs,
    verify_plan,
    AtomicLifecycle,
    LifecycleError,
    run_command,
)
from scripts import check_live_run as live


class AtomicLifecycleTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="totenkahn-atomic-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = self.root / "atomics"
        self.definition = self.catalog / "T0001/T0001.yaml"
        self.definition.parent.mkdir(parents=True)
        self.test = {
            "name": "Inert fixture",
            "auto_generated_guid": "11111111-1111-4111-8111-111111111111",
            "supported_platforms": ["windows"],
            "input_arguments": {"marker": {"type": "string", "default": "fixture"}},
            "executor": {
                "name": "powershell",
                "command": 'Write-Output "#{marker}"',
                "cleanup_command": "Write-Output cleanup",
            },
            "dependencies": [
                {
                    "description": "fixture dependency",
                    "prereq_command": "exit 0",
                    "get_prereq_command": "Write-Output prepared",
                },
            ],
        }
        self.write_definition()
        self.config = json.loads((ROOT / "config/default.config").read_text())

        for folder, name in [
            ("yaml", "powershell-yaml.psd1"),
            ("art", "Invoke-AtomicRedTeam.psd1"),
        ]:
            path = self.root / folder / name
            path.parent.mkdir()
            path.write_text("inert module")

        self.config["atomic"] = {
            "atomics_path": str(self.catalog),
            "module_path": str(self.root / "art/Invoke-AtomicRedTeam.psd1"),
            "yaml_module_path": str(self.root / "yaml/powershell-yaml.psd1"),
        }
        self.config["paths"]["runs_dir"] = str(self.root / "runs")
        self.config["events"]["channels"] = ["Fixture"]
        self.calls = []

    def write_definition(self):
        self.definition.write_text(
            yaml.safe_dump({"attack_technique": "T0001", "atomic_tests": [self.test]}),
        )

    def plan(self, **kwargs):
        return build_plan(self.config, "T0001", 1, **kwargs)

    def lifecycle(self, statuses, **kwargs):
        sequence = iter(statuses)

        def runner(project, plan, command, executor, directory, cancel):
            self.calls.append(command)
            status = next(sequence)

            return {
                "status": status,
                "exit_code": 0 if status == "passed" else 1,
                "process_id": 123,
            }

        return AtomicLifecycle(ROOT, self.plan(**kwargs), self.root / "lifecycle", runner=runner)

    def test_preparation_records_new_resource_files(self):
        from handlers.atomic_lifecycle import record_prepared_additions

        plan = self.plan()
        new = self.definition.parent / "downloaded.txt"
        new.write_text("inert fixture")
        added = record_prepared_additions(plan)
        self.assertIn(str(new), added)
        verify_plan(plan)

    def test_preparation_cannot_replace_approved_code(self):
        from handlers.atomic_lifecycle import record_prepared_additions

        plan = self.plan()
        self.definition.write_text("changed")

        with self.assertRaises(ValueError):
            record_prepared_additions(plan)

    def test_preparation_cannot_add_module_code(self):
        from handlers.atomic_lifecycle import record_prepared_additions

        plan = self.plan()
        (self.root / "art/new.ps1").write_text("# inert")

        with self.assertRaises(ValueError):
            record_prepared_additions(plan)

    def test_plan_is_read_only_and_resolves_inputs(self):
        before = set(self.root.rglob("*"))
        plan = self.plan(inputs={"marker": "space & literal"})
        self.assertEqual(plan["command"], 'Write-Output "space & literal"')
        self.assertEqual(before, set(self.root.rglob("*")))

    def test_selection_validation(self):
        for technique, number in [
            ("../T0001", 1),
            ("ALL", 1),
            ("T0001", 0),
            ("T0001", 2),
            ("T0001", True),
        ]:
            with self.assertRaises(ValueError):
                build_plan(self.config, technique, number)

    def test_unknown_inputs_and_duplicates_rejected(self):
        with self.assertRaises(ValueError):
            self.plan(inputs={"typo": "x"})

        with self.assertRaises(ValueError):
            parse_inputs(["a=1", "a=2"])

        with self.assertRaises(ValueError):
            parse_inputs(["oops"])

        self.assertEqual(parse_inputs(["a=b=c"]), {"a": "b=c"})

    def test_nonwindows_and_manual_tests_rejected(self):
        self.test["supported_platforms"] = ["linux"]
        self.write_definition()

        with self.assertRaises(ValueError):
            self.plan()

        self.test["supported_platforms"] = ["windows"]
        self.test["executor"]["name"] = "manual"
        self.write_definition()

        with self.assertRaises(ValueError):
            self.plan()

    def test_changed_definition_blocks_before_command(self):
        life = self.lifecycle(["passed"])
        self.definition.write_text("changed")

        with self.assertRaises(ValueError):
            life.prepare()

        self.assertEqual(self.calls, [])

    def test_external_private_config_rejected(self):
        plan = self.plan()
        (self.root / "privateConfig.ps1").write_text("fixture")

        with self.assertRaises(ValueError):
            verify_plan(plan)

    def test_preexisting_dependency_is_not_prepared(self):
        life = self.lifecycle(["passed"])
        life.prepare()
        self.assertEqual(life.report["prerequisites"][0]["origin"], "preexisting")
        self.assertEqual(self.calls, ["exit 0"])

    def test_missing_dependency_requires_explicit_prepare(self):
        life = self.lifecycle(["failed"])

        with self.assertRaises(LifecycleError):
            life.prepare()

        self.assertEqual(life.report["status"], "blocked")
        self.assertEqual(len(self.calls), 1)

    def test_prepare_rechecks_before_ready(self):
        life = self.lifecycle(["failed", "passed", "passed"], prepare=True)
        life.prepare()
        self.assertEqual(life.report["status"], "ready")
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(life.report["residuals"][0]["status"], "manual_review")

    def test_failed_recheck_prevents_execution(self):
        life = self.lifecycle(["failed", "passed", "failed"], prepare=True)

        with self.assertRaises(LifecycleError):
            life.prepare()

        self.assertFalse(life.execution_started)

    def test_check_timeout_does_not_trigger_install(self):
        life = self.lifecycle(["timeout"], prepare=True)

        with self.assertRaises(LifecycleError):
            life.prepare()

        self.assertEqual(len(self.calls), 1)

    def test_execution_csv_supports_correlation(self):
        life = self.lifecycle(["passed", "passed"], cleanup=False)
        life.prepare()
        result = life.execute()
        life.cleanup()
        from handlers.file_handlers import load_csv_file
        from handlers.correlation import correlate_processes

        row = load_csv_file(Path(result["execution_log"]))[0]
        correlate_processes(row, [])
        self.assertEqual(life.report["execution"]["status"], "passed")
        self.assertEqual(life.report["cleanup"]["status"], "not_requested")

    def test_cleanup_after_failed_execution_does_not_hide_failure(self):
        life = self.lifecycle(["passed", "failed", "passed"], cleanup=True)
        life.prepare()

        with self.assertRaises(LifecycleError):
            life.execute()

        life.cleanup()
        self.assertEqual(life.report["status"], "failed")
        self.assertEqual(life.report["cleanup"]["status"], "passed")

    def test_cleanup_failure_is_not_success(self):
        life = self.lifecycle(["passed", "passed", "failed"], cleanup=True)
        life.prepare()
        life.execute()
        life.cleanup()
        self.assertEqual(life.report["status"], "needs_verification")
        self.assertEqual(life.report["execution"]["status"], "passed")

    def test_no_cleanup_before_test_execution(self):
        life = self.lifecycle(["passed"], cleanup=True)
        life.prepare()
        life.cleanup()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(life.report["cleanup"]["status"], "not_started")

    def test_html_escapes_untrusted_command(self):
        self.test["name"] = "<script>alert(1)</script>"
        self.write_definition()
        life = self.lifecycle([])
        content = (life.directory / "lifecycle.html").read_text()
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_interrupted_execution_is_recorded_and_cleanup_still_available(self):
        life = self.lifecycle(["passed"], cleanup=True)
        life.prepare()

        def interrupt(*args):
            raise KeyboardInterrupt()

        life.runner = interrupt

        with self.assertRaises(KeyboardInterrupt):
            life.execute()

        self.assertEqual(life.report["execution"]["status"], "interrupted")
        life.runner = lambda *args: {"status": "passed", "exit_code": 0, "process_id": 123}
        life.cleanup()
        self.assertEqual(life.report["cleanup"]["status"], "passed")
        self.assertEqual(life.report["status"], "interrupted")

    def test_auto_requires_approved_plan(self):
        with (
            patch.object(live.sys, "platform", "win32"),
            patch.object(live, "runtime_config", return_value=self.config),
        ):
            with self.assertRaises(ValueError):
                live.run_live_session("T0001", 1)

        self.assertFalse((self.root / "runs").exists())

    def live_fixture(self, execution="passed", ready=True, cleanup=True):
        calls = self.calls

        class Collector:

            def __init__(self, command, **kwargs):
                self.stop = Path(command[command.index("-StopFile") + 1])
                self.done = False
                self.stdout = self.lines()

            def lines(self):
                if ready:
                    calls.append("collector-ready")
                    yield (json.dumps({"type": "ready", "channels": ["Fixture"]}) + "\n")
                    end = time.monotonic() + 5

                    while not self.stop.exists() and time.monotonic() < end:
                        time.sleep(0.01)

                self.done = True

            def poll(self):
                return 0 if self.done else None

            def wait(self, **kwargs):
                self.done = True

                return 0

            def communicate(self, **kwargs):
                self.done = True

                return ("", "")

            def kill(self):
                self.done = True

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.done = True

        def runner(project, plan, command, executor, directory, cancel):
            calls.append(command)
            status = execution if command.startswith('Write-Output "') else "passed"

            return {
                "status": status,
                "exit_code": 0 if status == "passed" else 1,
                "process_id": 123,
            }

        with (
            patch.object(live.sys, "platform", "win32"),
            patch.object(live, "runtime_config", return_value=self.config),
            patch.object(live.subprocess, "Popen", Collector),
            patch("handlers.atomic_lifecycle.run_command", runner),
            patch.object(
                live,
                "inspect_telemetry",
                return_value={"status": "passed", "scope": "fixture"},
            ),
        ):
            return live.run_live_session(
                "T0001",
                1,
                atomic_plan=self.plan(cleanup=cleanup),
                approved=True,
                host_requirements={"channels": ["Fixture"]},
            )

    def test_full_lifecycle_orders_collection_execution_cleanup(self):
        result = self.live_fixture()
        self.assertEqual(
            self.calls,
            ["exit 0", "collector-ready", 'Write-Output "fixture"', "Write-Output cleanup"],
        )
        self.assertEqual(result["session_metadata"]["collection"]["status"], "completed")
        self.assertTrue((result["session_dir"] / "atomic/lifecycle.json").is_file())
        report = result["scenario"]["atomic_lifecycle"]
        self.assertLessEqual(
            report["collection"]["finished_at"],
            report["steps"][-1]["started_at"],
        )
        from reporting.atomic_view import lifecycle_summary

        text, chain = lifecycle_summary(report)
        self.assertIn(
            "Collector ready -> Execute test: passed -> Collection stopped -> Cleanup: passed",
            chain,
        )
        self.assertIn("Rule result: not_evaluated", text)

    def test_missing_collector_readiness_prevents_atomic(self):
        with self.assertRaises(LifecycleError):
            self.live_fixture(ready=False)

        self.assertEqual(self.calls, ["exit 0"])
        session = next((self.root / "runs").iterdir())
        self.assertEqual(
            json.loads((session / "session.json").read_text())["collection"]["status"],
            "incomplete",
        )
        self.assertTrue((session / "events.json").exists())

    def test_execution_failure_preserves_partial_session_and_cleans(self):
        with self.assertRaises(LifecycleError):
            self.live_fixture(execution="failed")

        session = next((self.root / "runs").iterdir())
        report = json.loads((session / "atomic/lifecycle.json").read_text())
        self.assertEqual(report["execution"]["status"], "failed")
        self.assertEqual(report["cleanup"]["status"], "passed")
        self.assertTrue((session / "scenario.json").is_file())

    def test_added_module_file_invalidates_approval(self):
        plan = self.plan()
        (self.root / "art/unexpected.ps1").write_text("fixture")

        with self.assertRaises(ValueError):
            verify_plan(plan)

    def test_detection_distinguishes_missing_evidence_and_negative(self):
        from handlers.atomic_lifecycle import detection_outcome

        correlation = {
            "correlation_status": "candidates_collected",
            "process_candidates": [{"record_id": "a"}],
        }
        self.assertEqual(
            detection_outcome(correlation, [], "completed")["status"],
            "insufficient_data",
        )
        self.assertEqual(
            detection_outcome(
                correlation,
                [{"Log Record ID": "a", "Selection": False}],
                "completed",
            )["status"],
            "no_match",
        )
        self.assertEqual(
            detection_outcome(
                correlation, [{"Log Record ID": "a", "Selection": True}], "completed"
            )["status"],
            "match",
        )
        self.assertEqual(
            detection_outcome(
                correlation,
                [{"Log Record ID": "a", "Selection": True}],
                "incomplete",
            )["status"],
            "insufficient_data",
        )

    def test_atomic_plan_cli_needs_no_rule_or_execution_consent(self):
        import runpy
        from contextlib import redirect_stdout

        output = io.StringIO()

        with (
            patch("handlers.runtime_paths.runtime_config", return_value=self.config),
            patch.object(
                sys,
                "argv",
                ["main.py", "--auto", "--atomic-test", "T0001", "1", "--atomic-plan"],
            ),
            redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as stop:
                runpy.run_path(str(ROOT / "main.py"), run_name="__main__")

            self.assertEqual(stop.exception.code, 0)

        self.assertEqual(json.loads(output.getvalue())["test_number"], 1)
        self.assertFalse((self.root / "runs").exists())

    def test_powershell_adapter_inert_engine_contract(self):
        import shutil, subprocess

        shell = shutil.which("pwsh") or shutil.which("powershell.exe")

        if shell is None:
            self.skipTest("PowerShell unavailable for inert adapter test")

        folder = self.root / "adapter"
        folder.mkdir()
        module = folder / "FixtureART.psm1"
        module.write_text(
            """function Invoke-ExecuteCommand {
            param($command,$executor,$platform,$timeout,$session,$interactive)
            [Console]::Out.WriteLine('USER INFORMATION - fixture noise')
            $code = 0; $expired = $false
            if ($command -eq \'fixture-fail\') { $code = 7 }
            if ($command -eq \'fixture-timeout\') { $code = -1; $expired = $true }
            [pscustomobject]@{ExitCode=$code; ProcessId=123; IsTimeout=$expired; StandardOutput=\'inert\'; ErrorOutput=\'\'}
        }
        Export-ModuleMember -Function Invoke-ExecuteCommand
        """,
        )
        yaml_module = folder / "FixtureYaml.psm1"
        yaml_module.write_text("# inert")
        request = folder / "request.json"

        for command, status, code in [
            ("fixture-pass", "passed", 0),
            ("fixture-fail", "failed", 1),
            ("fixture-timeout", "timeout", 1),
        ]:
            request.write_text(
                json.dumps(
                    {
                        "command": command,
                        "executor": "powershell",
                        "timeout_seconds": 2,
                        "module_path": str(module),
                        "yaml_module_path": str(yaml_module),
                        "elevation_required": False,
                    },
                ),
            )
            response = folder / (command + ".response.json")
            result = subprocess.run(
                [
                    shell,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    str(ROOT / "scripts/atomic_step.ps1"),
                    "-RequestPath",
                    str(request),
                    "-ResponsePath",
                    str(response),
                ],
                cwd=folder,
                capture_output=True,
                timeout=30,
            )
            self.assertIn(b"USER INFORMATION", result.stdout)
            self.assertTrue(response.is_file(), result.stderr.decode("utf-8", errors="replace"))
            data = json.loads(response.read_text(encoding="utf-8-sig"))
            self.assertEqual(data["status"], status, data)
            self.assertEqual(result.returncode, code, data)

    def test_step_response_is_separate_from_command_output(self):
        from unittest.mock import MagicMock

        for name, response, expected in [
            ("valid", '{"status":"passed","exit_code":0}', "passed"),
            ("missing", None, "error"),
            ("invalid", "not json", "error"),
        ]:
            directory = self.root / name
            directory.mkdir()

            def start(args, **kwargs):
                kwargs["stdout"].write(b'USER INFORMATION\n{"status":"passed","exit_code":0}\n')

                if response is not None:
                    Path(args[args.index("-ResponsePath") + 1]).write_bytes(
                        response.encode("utf-8")
                    )

                process = MagicMock()
                process.poll.return_value = 0
                process.returncode = 0

                return process

            with (
                patch("handlers.atomic_lifecycle.subprocess.Popen", side_effect=start),
                patch("handlers.atomic_lifecycle.terminate_process"),
            ):
                result = run_command(ROOT, self.plan(), "inert", "powershell", directory)

            self.assertEqual(result["status"], expected)

    def test_cancelled_command_is_terminated_and_journaled(self):
        cancel = threading.Event()
        cancel.set()

        class Process:
            pid = 123
            done = False

            def poll(self):
                return -9 if self.done else None

            def kill(self):
                self.done = True

            def wait(self, **kwargs):
                return -9

        process = Process()
        directory = self.root / "step"
        directory.mkdir()

        with (
            patch("handlers.atomic_lifecycle.subprocess.Popen", return_value=process),
            patch(
                "handlers.atomic_lifecycle.terminate_process",
                side_effect=lambda proc: proc.kill(),
            ),
        ):
            result = run_command(ROOT, self.plan(), "inert", "powershell", directory, cancel)

        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(process.done)
        self.assertTrue((directory / "request.json").is_file())


if __name__ == "__main__":
    unittest.main()
