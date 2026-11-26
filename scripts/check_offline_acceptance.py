import json
from html.parser import HTMLParser
from pathlib import PureWindowsPath
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.offline_acceptance import OfflineAcceptance, fixture_files
from reporting.offline_report import explain_check, link, render_stage


class OfflineAcceptanceTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fake_stages(self, runner, fail_first=False):
        def success():
            for item in runner.stage["checks"]:
                runner.check(item["name"], True, True)

        def fail():
            raise RuntimeError("deliberate stage failure")

        for index, name in enumerate(
            ("stage_import", "stage_sigma", "stage_case", "stage_hunt", "stage_regression")
        ):
            setattr(runner, name, fail if fail_first and index == 0 else success)

    def test_failure_does_not_skip_other_stages(self):
        runner = OfflineAcceptance(ROOT, self.root / "run")
        self.fake_stages(runner, fail_first=True)
        report = runner.run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(
            [s["status"] for s in report["stages"]],
            ["error", "passed", "passed", "passed", "passed"],
        )
        self.assertTrue(
            all((runner.output / s["id"] / "report.json").is_file() for s in report["stages"])
        )
        self.assertTrue(all(c["status"] == "not_run" for c in report["stages"][0]["checks"]))

    def test_selected_stage_not_claimed_as_all_five(self):
        runner = OfflineAcceptance(ROOT, self.root / "run", stages=[3])
        self.fake_stages(runner)
        report = runner.run()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["selected_stages"], [3])
        self.assertEqual(
            [s["status"] for s in report["stages"]],
            ["not_requested", "not_requested", "passed", "not_requested", "not_requested"],
        )

    def test_existing_directory_never_modified(self):
        directory = self.root / "existing"
        directory.mkdir()
        marker = directory / "keep.txt"
        marker.write_bytes(b"keep")

        with self.assertRaises(FileExistsError):
            OfflineAcceptance(ROOT, directory).run()

        self.assertEqual(list(directory.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_negative_control_requires_exact_observation(self):
        runner = OfflineAcceptance(ROOT, self.root / "run", stages=[1])
        self.fake_stages(runner)

        def control():
            runner.check(
                "formats",
                {"status": "failed", "reason": "tampered"},
                {"status": "failed", "reason": "unrelated"},
            )
            runner.check("malformed", True, True)
            runner.check("integrity", True, True)

        runner.stage_import = control
        report = runner.run()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["stages"][0]["checks"][0]["status"], "failed")

    def test_network_and_host_action_commands_are_rejected(self):
        runner = OfflineAcceptance(ROOT, self.root / "run")
        runner.output.mkdir()
        runner.stage = {"commands": []}

        with patch("handlers.offline_acceptance.subprocess.run") as launch:
            for command in ("dependencies", "telemetry", "test", "--auto"):
                with self.assertRaises(ValueError):
                    runner.cli(command, "prepare")

        launch.assert_not_called()

    def test_fixture_bytes_stable_and_synthetic(self):
        a, b = self.root / "a", self.root / "b"
        fixture_files(a)
        fixture_files(b)

        for path in a.iterdir():
            self.assertEqual(path.read_bytes(), (b / path.name).read_bytes())

        events = [json.loads(line) for line in (a / "events.jsonl").read_text().splitlines()]
        self.assertEqual(len(events), 3)
        self.assertNotIn("command_line", events[2])

    def test_missing_evidence_cannot_pass(self):
        runner = OfflineAcceptance(ROOT, self.root / "run")
        runner.stage = {"checks": [{"name": "fixture", "status": "not_run"}]}

        with self.assertRaisesRegex(ValueError, "Missing acceptance evidence"):
            runner.check("fixture", True, True, self.root / "absent")

    def test_html_escapes_failure_text(self):
        runner = OfflineAcceptance(ROOT, self.root / "run")
        self.fake_stages(runner)

        def failure():
            raise ValueError("<script>fixture</script>")

        runner.stage_import = failure
        runner.run()
        html = (runner.output / "index.html").read_text()
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_windows_evidence_links_use_url_separators(self):
        rendered = link(PureWindowsPath("02-sigma/analysis/events.html"), "../")
        self.assertIn('href="../02-sigma/analysis/events.html"', rendered)
        self.assertNotIn("\\", rendered)

    def test_failed_control_never_gets_success_narrative(self):
        text = explain_check("negative", {"status": "passed"}, False)
        self.assertIn("check failed", text)
        self.assertNotIn("makes the acceptance control pass", text)

    def test_negative_and_unknown_semantics_are_explicit(self):
        self.assertIn("CI FAILED", explain_check("negative", {}, True))
        self.assertIn("cannot establish NO MATCH", explain_check("insufficient", {}, True))
        self.assertIn("NEEDS_VERIFICATION", explain_check("decisions", {}, True))

    def test_expanded_fixture_has_exclusion_and_missing_time(self):
        folder = self.root / "fixtures"
        fixture_files(folder)
        records = OfflineAcceptance.event_rows(folder / "investigation.jsonl")
        self.assertEqual({r["host"] for r in records}, {"lab-a", "lab-b"})
        self.assertEqual({r["user"] for r in records}, {"alice", "bob"})
        self.assertIn("--excluded", records[2]["command_line"])
        self.assertNotIn("command_line", records[3])
        self.assertNotIn("timestamp", OfflineAcceptance.event_rows(folder / "secondary.jsonl")[1])

    def test_report_exposes_all_requirements_and_scope_limits(self):
        runner = OfflineAcceptance(ROOT, self.root / "run")
        self.fake_stages(runner)
        report = runner.run()
        self.assertEqual(sum(len(s["checks"]) for s in report["stages"]), 20)
        html = (runner.output / "index.html").read_text()
        self.assertEqual(html.count("Requirement → scenario → result → evidence"), 5)
        self.assertIn("not full Sigma certification", html)
        self.assertIn("Unselected stages are not tested", html)
        self.assertIn("Expected values and machine-readable check", html)

    def test_story_values_and_links_are_escaped(self):
        stage = {
            "id": "02-sigma",
            "name": "Sigma",
            "status": "passed",
            "checks": [
                {
                    "name": "trace",
                    "status": "passed",
                    "observed": {"value": "<script>alert(1)</script>"},
                    "evidence": ['x" onclick="bad.html'],
                    "stories": [
                        {
                            "title": "<script>",
                            "explanation": "<img src=x>",
                            "chain": ["<svg onload=x>"],
                        }
                    ],
                }
            ],
        }
        text = render_stage(stage)
        self.assertNotIn("<script>", text)
        self.assertNotIn("<img", text)
        self.assertNotIn("<svg", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertNotIn('href="x" onclick=', text)

    def test_unselected_stage_does_not_display_completed_explanation(self):
        stage = {"id": "02-sigma", "name": "Sigma", "status": "not_requested", "checks": []}
        self.assertIn("No result is claimed", render_stage(stage))
        self.assertNotIn("Recorded observations", render_stage(stage))

    def test_nested_hunt_chain_preserves_unknown_and_negation(self):
        node = {
            "operator": "not",
            "result": None,
            "children": [
                {
                    "field": "/command_line",
                    "present": False,
                    "actual": None,
                    "op": "contains",
                    "expected": "--review",
                    "result": None,
                }
            ],
        }
        chain = OfflineAcceptance.predicate_chain(node)
        self.assertIn("present=False", chain[0])
        self.assertIn("not: None", chain[1])
        self.assertNotIn("not: True", chain[1])

    def test_generated_navigation_targets_exist(self):
        class Links(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []

            def handle_starttag(self, tag, attrs):
                if tag == "a":
                    self.links.extend(v for k, v in attrs if k == "href")

        runner = OfflineAcceptance(ROOT, self.root / "run")
        self.fake_stages(runner)
        runner.run()

        for page in runner.output.rglob("*.html"):
            parser = Links()
            parser.feed(page.read_text())

            for target in parser.links:
                if not target.startswith("#"):
                    self.assertTrue((page.parent / target).is_file(), (page, target))


if __name__ == "__main__":
    unittest.main(verbosity=2)
