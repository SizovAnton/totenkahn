import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers import dump_analysis, case_timeline, hunt_runner
from handlers.case_store import create_case, add_dataset
from handlers.hunt_store import define_hunt
from handlers.cli_help import HelpfulParser, show_overview
from handlers.evidence import import_dump, verify_dataset, save_import_manifest
from handlers.dump_cli import dispatch as dump_dispatch
from handlers.evidence_recovery import recover_dump
from handlers.offline_acceptance import fixture_files, OfflineAcceptance
from handlers.operations_acceptance import run_operations


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixtures = self.root / "fixtures"
        fixture_files(self.fixtures)
        self.dataset = self.root / "dataset"
        import_dump(ROOT, self.fixtures / "events.jsonl", self.dataset, profile="generic-v1")
        self.manifest = json.loads((self.dataset / "manifest.json").read_text(encoding="utf-8"))

    def rewrite(self):
        (self.dataset / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    @staticmethod
    def windows_denied():
        error = PermissionError(13, "Controlled Windows replace denial")
        setattr(error, "winerror", 5)
        return error

    def test_manifest_transient_denial_preserves_atomic_replace(self):
        folder = self.root / "manifest-check"
        folder.mkdir()
        target = folder / "manifest.json"
        target.write_bytes(b'{"old":true}')
        replace = os.replace
        attempts = []

        def transient(source, destination):
            attempts.append(Path(source))
            if len(attempts) < 3:
                self.assertEqual(target.read_bytes(), b'{"old":true}')
                raise self.windows_denied()
            return replace(source, destination)

        with (
            patch("handlers.evidence.os.replace", side_effect=transient),
            patch("handlers.evidence.time.sleep") as sleep,
        ):
            save_import_manifest(folder, {"new": True})
        self.assertEqual(json.loads(target.read_text()), {"new": True})
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(len(set(attempts)), 1)
        self.assertEqual(list(folder.glob("*.tmp")), [])

    def test_manifest_permanent_denial_is_bounded_and_preserves_old(self):
        folder = self.root / "manifest-check"
        folder.mkdir()
        target = folder / "manifest.json"
        target.write_bytes(b'{"old":true}')
        with (
            patch("handlers.evidence.os.replace", side_effect=self.windows_denied()) as replace,
            patch("handlers.evidence.time.sleep") as sleep,
        ):
            with self.assertRaises(PermissionError):
                save_import_manifest(folder, {"new": True})
        self.assertEqual(replace.call_count, 7)
        self.assertEqual(sleep.call_count, 6)
        self.assertEqual(target.read_bytes(), b'{"old":true}')

    def test_non_windows_permission_error_is_not_retried(self):
        with (
            patch("handlers.evidence.os.replace", side_effect=PermissionError("Denied")) as replace,
            patch("handlers.evidence.time.sleep") as sleep,
        ):
            with self.assertRaises(PermissionError):
                save_import_manifest(self.root, {})
        self.assertEqual(replace.call_count, 1)
        sleep.assert_not_called()

    def test_import_recovers_checkpoint_sharing_denial(self):
        replace = os.replace
        calls = 0

        def transient(source, destination):
            nonlocal calls
            calls += 1
            if calls in (3, 4):
                raise self.windows_denied()
            return replace(source, destination)

        with (
            patch("handlers.evidence.os.replace", side_effect=transient),
            patch("handlers.evidence.time.sleep"),
        ):
            report = import_dump(
                ROOT, self.fixtures / "events.jsonl", self.root / "checkpoint", profile="generic-v1"
            )
        self.assertEqual(report["counts"]["accepted"], 3)
        self.assertIn(report["status"], ("passed", "passed_with_warnings"))
        self.assertEqual(verify_dataset(self.root / "checkpoint")["status"], "passed")

    def test_persistent_manifest_denial_never_reports_success(self):
        with (
            patch("handlers.evidence.os.replace", side_effect=self.windows_denied()),
            patch("handlers.evidence.time.sleep"),
        ):
            report = import_dump(
                ROOT, self.fixtures / "events.jsonl", self.root / "denied", profile="generic-v1"
            )
        self.assertEqual(report["status"], "error")
        self.assertIn("Could not persist", report["reason"])
        self.assertTrue(report["persistence_error"])
        self.assertTrue((self.root / "denied/report.html").is_file())

    def test_cli_includes_file_error_without_reading_manifest(self):
        output = io.StringIO()
        with (
            patch("handlers.evidence.snapshot_file", side_effect=self.windows_denied()),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = dump_dispatch(
                ROOT,
                [
                    "dump",
                    "import",
                    str(self.fixtures / "events.jsonl"),
                    "--profile",
                    "generic-v1",
                    "--output-dir",
                    str(self.root / "cli-error"),
                    "--json",
                ],
            )
        report = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report["errors"][0]["winerror"], 5)
        self.assertIn("Controlled Windows replace denial", report["reason"])

    def test_acceptance_propagates_child_failure_reason(self):
        runner = OfflineAcceptance(ROOT, self.root / "unused", command=["fixture"])
        runner.output = self.root
        runner.folder = self.root
        runner.stage = {"commands": []}

        def fail(command, **kwargs):
            kwargs["stdout"].write(b'{"status":"error","reason":"Manifest replacement denied"}')
            return SimpleNamespace(returncode=2)

        with patch("handlers.offline_acceptance.subprocess.run", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "Manifest replacement denied"):
                runner.cli("dump", "import")

    def test_recovery_reindexes_without_trusting_old_index(self):
        self.manifest["status"] = "importing"
        self.manifest.pop("index_sha256")
        self.rewrite()
        (self.dataset / "index.sqlite").write_bytes(b"unfinished database")
        old = (self.dataset / "manifest.json").read_bytes()
        result = recover_dump(ROOT, self.dataset, self.root / "recovered")
        self.assertEqual(result["counts"]["accepted"], 3)
        self.assertEqual(result["status"], "passed_with_warnings")
        self.assertEqual(verify_dataset(self.root / "recovered")["status"], "passed")
        self.assertEqual((self.dataset / "manifest.json").read_bytes(), old)
        self.assertEqual((self.dataset / "index.sqlite").read_bytes(), b"unfinished database")
        self.assertEqual(result["recovery"]["previous_status"], "importing")

    def test_changed_original_is_rejected_before_new_output(self):
        (self.dataset / self.manifest["files"][0]["stored"]).write_bytes(b"changed")

        with self.assertRaisesRegex(ValueError, "missing, incomplete or changed"):
            recover_dump(ROOT, self.dataset, self.root / "new")

        self.assertFalse((self.root / "new").exists())

    def test_incomplete_snapshot_cannot_be_recovered(self):
        self.manifest["files"][0].pop("sha256")
        self.rewrite()

        with self.assertRaises(ValueError):
            recover_dump(ROOT, self.dataset, self.root / "new")

    def test_recovery_refuses_existing_destination(self):
        with self.assertRaises(FileExistsError):
            recover_dump(ROOT, self.dataset, self.dataset)

        self.assertEqual(verify_dataset(self.dataset)["status"], "passed")

    def test_recovery_rejects_path_traversal(self):
        for value in ("../escape.jsonl", "/escape.jsonl", "C:/escape.jsonl", "a\\escape.jsonl"):
            self.manifest["files"][0]["name"] = value
            self.rewrite()

            with self.assertRaisesRegex(ValueError, "Unsafe"):
                recover_dump(ROOT, self.dataset, self.root / "new")

    def test_recovery_rejects_original_outside_dataset(self):
        self.manifest["files"][0]["stored"] = "../fixtures/events.jsonl"
        self.rewrite()

        with self.assertRaisesRegex(ValueError, "outside"):
            recover_dump(ROOT, self.dataset, self.root / "new")

    def test_profile_snapshot_changes_are_rejected(self):
        self.manifest["files"][0]["profile"]["time_format"] = "unix_seconds"
        self.rewrite()

        with self.assertRaisesRegex(ValueError, "saved profile"):
            recover_dump(ROOT, self.dataset, self.root / "new")

    def test_recovery_detects_source_change_during_copy(self):
        with patch("handlers.evidence_recovery.snapshot_file", return_value=("0" * 64, 1)):
            with self.assertRaisesRegex(ValueError, "changed while copying"):
                recover_dump(ROOT, self.dataset, self.root / "new")

        self.assertFalse((self.root / "new").exists())

    def test_copy_checkpoint_survives_interruption_before_first_record(self):
        with patch("handlers.evidence.json_records", side_effect=KeyboardInterrupt):
            result = import_dump(
                ROOT, self.fixtures / "events.jsonl", self.root / "stopped", profile="generic-v1"
            )

        self.assertEqual(result["status"], "interrupted")
        result = recover_dump(ROOT, self.root / "stopped", self.root / "new")
        self.assertEqual(result["counts"]["accepted"], 3)

    def test_cancelled_analysis_keeps_partial_artifacts(self):
        actual = dump_analysis.evaluate_row
        called = 0

        def interrupt(*args, **kwargs):
            nonlocal called
            called += 1

            if called == 2:
                raise KeyboardInterrupt

            return actual(*args, **kwargs)

        with patch("handlers.dump_analysis.evaluate_row", side_effect=interrupt):
            report = dump_analysis.analyze_dump(
                ROOT,
                self.dataset,
                self.root / "analysis",
                rule=self.fixtures / "baseline.yaml",
                mapping_path=self.fixtures / "mapping.json",
            )

        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(sum(report["rules"][0]["counts"].values()), 1)
        self.assertTrue(
            (self.root / "analysis/rule-0001/events-0001.html")
            .read_text()
            .endswith("</body></html>")
        )
        self.assertEqual(verify_dataset(self.dataset)["status"], "passed")

    def interrupted_rows(self, original):
        def rows(*args, **kwargs):
            for index, row in enumerate(original(*args, **kwargs)):
                if index == 1:
                    raise KeyboardInterrupt

                yield row

        return rows

    def make_case(self):
        case = self.root / "case"
        create_case(case, "Interrupted operation fixture")
        add_dataset(case, self.dataset, label="fixture")

        return case

    def test_interrupted_timeline_keeps_one_record(self):
        case = self.make_case()

        with patch(
            "handlers.case_timeline.selected_rows",
            self.interrupted_rows(case_timeline.selected_rows),
        ):
            report = case_timeline.build_timeline(case, self.root / "timeline")

        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(report["events"], 1)
        self.assertEqual(len((self.root / "timeline/events.jsonl").read_text().splitlines()), 1)
        self.assertTrue((self.root / "timeline/report.html").is_file())

    def test_interrupted_hunt_keeps_unknown_scope(self):
        case = self.make_case()
        define_hunt(
            case, "review", json.loads((self.fixtures / "hunt.json").read_text()), "fixture"
        )

        with patch(
            "handlers.hunt_runner.selected_rows", self.interrupted_rows(hunt_runner.selected_rows)
        ):
            report = hunt_runner.run_hunt(case, "review", self.root / "hunt")

        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(report["hypothesis_result"], "undetermined")
        self.assertEqual(sum(report["counts"].values()), 1)
        self.assertTrue((self.root / "hunt/report.html").is_file())

    def test_invalid_scale_budget_does_not_create_output(self):
        for events, budget in [
            (0, 256),
            (999, 256),
            (1000001, 256),
            (1000, 0),
            (1000, float("nan")),
        ]:
            with self.assertRaises(ValueError):
                run_operations(ROOT, self.root / "operations", events=events, max_peak_mib=budget)

        self.assertFalse((self.root / "operations").exists())

    def test_help_and_error_are_english(self):
        out, err = io.StringIO(), io.StringIO()

        with contextlib.redirect_stdout(out):
            show_overview()
            HelpfulParser(prog="totenkahn test").print_help()

        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            HelpfulParser(prog="totenkahn test").error("Missing rule")

        self.assertNotRegex(out.getvalue() + err.getvalue(), "[А-Яа-яІіЇїЄєҐґ]")
        self.assertIn("Command error", err.getvalue())

    def test_product_literals_are_english_but_input_is_preserved(self):
        for folder in ("handlers", "displaying", "reporting"):
            for path in (ROOT / folder).glob("*.py"):
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        self.assertIsNone(
                            re.search("[А-Яа-яІіЇїЄєҐґ]", node.value), (path, node.lineno)
                        )

        source = self.root / "ukrainian.jsonl"
        source.write_text(
            json.dumps(
                {
                    "host": "сервер",
                    "command_line": "приклад",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "event_id": "1",
                },
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        result = import_dump(ROOT, source, self.root / "uk", profile="generic-v1")
        self.assertEqual(
            (self.root / "uk" / result["files"][0]["stored"]).read_bytes(), source.read_bytes()
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
