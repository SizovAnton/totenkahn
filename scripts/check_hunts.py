import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.case_store import (
    create_case,
    add_dataset,
    load_case,
    export_case,
    set_state,
    verify_case,
)
from handlers.evidence import import_dump, file_hash
from handlers.evidence_selection import create_selection
from handlers.hunt_definition import evaluate, validate_definition, validate_expression
from handlers.hunt_store import define_hunt
from handlers.hunt_runner import run_hunt, inspect_scope


class HuntTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-hunt-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = self.root / "case"
        create_case(self.case, "Synthetic hunt")
        self.dataset = self.root / "dataset"
        self.source = self.root / "events.jsonl"
        self.definition = {
            "schema_version": 1,
            "hypothesis": "Demo process appears in observed evidence",
            "condition": {"field": "/command_line", "op": "contains", "value": "--demo"},
        }

    def event(self, command: str | None = "example.exe --demo", host="host-a") -> dict[str, object]:
        return {
            "timestamp": "2026-11-19T10:00:00Z",
            "host": host,
            "user": "lab-user",
            "process_id": "42",
            "event_id": "process",
            "command_line": command,
        }

    def attach(self, events=None):
        self.source.write_text(
            "\n".join(
                (
                    json.dumps(e)
                    for e in (
                        events if events is not None else [self.event(), self.event("other.exe")]
                    )
                ),
            )
            + "\n",
        )
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")

        return add_dataset(self.case, self.dataset)

    def define(self, definition=None, name="demo"):
        return define_hunt(self.case, name, definition or self.definition, "test-engineer")

    def run_hunt(self, **kwargs):
        output = self.root / ("report-" + str(len(list(self.root.glob("report-*")))))
        report = run_hunt(self.case, "demo", output, **kwargs)
        rows = (
            [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
            if (output / "events.jsonl").exists()
            else []
        )

        return (report, rows, output)

    def test_match_no_match_and_provenance(self):
        self.attach()
        self.define()
        before = file_hash(self.case / "case.json")
        report, rows, output = self.run_hunt()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"], {"match": 1, "no_match": 1})
        self.assertEqual(report["hypothesis_result"], "observed_in_evidence")
        self.assertEqual(report["entities"]["host"]["distinct_observed"], 1)
        self.assertEqual(rows[0]["locator"], {"line": 1})
        self.assertEqual(rows[0]["source"]["sha256"], file_hash(self.source))
        self.assertEqual(rows[0]["evaluation"]["actual"], "example.exe --demo")
        self.assertEqual(before, file_hash(self.case / "case.json"))
        self.assertIn("contains", (output / "events-0001.html").read_text())

    def test_missing_field_under_not_stays_unknown(self):
        event = self.event()
        del event["command_line"]
        self.attach([event])
        self.definition["condition"] = {"not": self.definition["condition"]}
        self.define()
        report, rows, _ = self.run_hunt()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows[0]["decision"], "insufficient_data")
        self.assertIsNone(rows[0]["evaluation"]["result"])
        self.assertEqual(report["hypothesis_result"], "undetermined")

    def test_explicit_exists_distinguishes_absence_and_null(self):
        missing = self.event()
        del missing["command_line"]
        self.attach([missing, self.event(None)])
        self.definition["condition"] = {"field": "/command_line", "op": "exists", "value": False}
        self.define()
        report, rows, _ = self.run_hunt()
        self.assertEqual(report["counts"], {"match": 1, "no_match": 1})
        self.assertFalse(rows[0]["evaluation"]["present"])
        self.assertTrue(rows[1]["evaluation"]["present"])

    def test_three_valued_all_any(self):
        unknown = {"field": "/missing", "op": "equals", "value": "a"}
        yes = {"field": "/x", "op": "equals", "value": "yes"}
        no = {"field": "/x", "op": "equals", "value": "no"}
        self.assertTrue(evaluate({"any": [unknown, yes]}, {"x": "yes"}, {})["result"])
        self.assertFalse(evaluate({"all": [unknown, no]}, {"x": "yes"}, {})["result"])
        self.assertIsNone(evaluate({"all": [unknown, yes]}, {"x": "yes"}, {})["result"])
        self.assertIsNone(evaluate({"any": [unknown, no]}, {"x": "yes"}, {})["result"])

    def test_typed_equality_case_and_list_values(self):
        event = {"x": 7, "text": "ÄBC", "list": ["abc"]}
        self.assertFalse(
            evaluate({"field": "/x", "op": "equals", "value": "7"}, event, {})["result"],
        )
        self.assertTrue(
            evaluate({"field": "/x", "op": "in", "value": [1, 7]}, event, {})["result"],
        )
        self.assertTrue(
            evaluate(
                {"field": "/text", "op": "contains", "value": "äb", "case_sensitive": False},
                event,
                {},
            )["result"],
        )
        self.assertIsNone(
            evaluate({"field": "/list", "op": "contains", "value": "abc"}, event, {})["result"],
        )

    def test_empty_known_evidence_not_observed_not_refuted(self):
        self.attach([self.event("benign")])
        self.define()
        report, _, _ = self.run_hunt()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["hypothesis_result"], "not_observed_in_evaluated_records")
        self.assertEqual(report["matched_unique_evidence_records"], 0)

    def test_empty_case_is_undetermined(self):
        self.define()
        report, _, _ = self.run_hunt()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(report["hypothesis_result"], "undetermined")

    def test_scope_excluded_and_unknown_distinguished(self):
        missing = self.event()
        del missing["event_id"]
        other = self.event()
        other["event_id"] = "network"
        self.attach([missing, other, self.event()])
        self.definition["scope"] = {"field": "/event_id", "op": "equals", "value": "process"}
        self.define()
        report, rows, _ = self.run_hunt()
        self.assertEqual(
            [r["decision"] for r in rows],
            ["insufficient_scope", "out_of_scope", "match"],
        )
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(report["hypothesis_result"], "observed_in_evidence")

    def test_runtime_time_unknown_not_silently_filtered(self):
        event = self.event()
        event["timestamp"] = None
        self.attach([event, self.event()])
        self.define()
        report, rows, _ = self.run_hunt(filters={"start": "2026-11-19T09:00:00Z"})
        self.assertEqual(report["counts"]["insufficient_scope"], 1)
        self.assertIsNone(rows[0]["scope_evaluation"]["result"])

    def test_unknown_entities_reduce_scope_not_proven_match(self):
        event = self.event()
        del event["host"]
        del event["user"]
        self.attach([event])
        self.define()
        report, _, output = self.run_hunt()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope_status"], "incomplete")
        self.assertEqual(report["entities"]["host"]["missing_in_matches"], 1)
        self.assertEqual(len(inspect_scope(output, "host", None, True)["items"]), 1)

    def test_scope_pivot_links_back_to_exact_records(self):
        self.attach(
            [self.event(host="host-a"), self.event(host="host-b"), self.event(host="host-a")],
        )
        self.define()
        _, _, output = self.run_hunt()
        groups = inspect_scope(output, "host", limit=1)
        self.assertEqual(len(groups["items"]), 1)
        self.assertEqual(groups["next_after"], 1)
        first = inspect_scope(output, "host", "host-a", True, limit=1)
        self.assertEqual(first["items"][0]["row_id"], 1)
        second = inspect_scope(output, "host", "host-a", True, after=first["next_after"])
        self.assertEqual(second["items"][0]["row_id"], 3)
        self.assertIn("#event-3", second["items"][0]["evidence_page"])

    def test_duplicate_occurrences_and_unique_evidence_count(self):
        self.attach([self.event()])
        other = self.root / "other"
        import_dump(ROOT, self.source, other, profile="generic-v1")
        add_dataset(self.case, other)
        self.define()
        report, _, _ = self.run_hunt()
        self.assertEqual(report["counts"]["match"], 2)
        self.assertEqual(report["matched_unique_evidence_records"], 1)
        self.assertEqual(report["entities"]["host"]["top"][0]["unique_evidence_records"], 1)

    def test_process_grouping_uses_host_and_does_not_claim_pid_identity(self):
        self.attach([self.event(host="a"), self.event(host="b")])
        self.define()
        report, _, output = self.run_hunt()
        self.assertEqual(report["entities"]["process"]["distinct_observed"], 2)
        entity = report["entities"]["process"]["top"][0]["value"]
        self.assertEqual(entity["basis"], "pid_observations_not_unique_process_instance")
        self.assertEqual(len(inspect_scope(output, "process", entity, True)["items"]), 1)

    def test_definition_export_and_run_closed_relocated_case(self):
        self.attach()
        self.define()
        set_state(self.case, "closed", "analyst", "reviewed")
        archive = self.root / "case.zip"
        export_case(self.case, archive)
        moved = self.root / "received"

        with ZipFile(archive) as zipfile:
            zipfile.extractall(moved)

        shutil.rmtree(self.case)
        shutil.rmtree(self.dataset)
        self.assertEqual(verify_case(moved)["status"], "passed")
        self.assertEqual(
            run_hunt(moved, "demo", self.root / "moved-report")["status"],
            "passed",
        )

        with self.assertRaisesRegex(ValueError, "closed"):
            define_hunt(moved, "new", self.definition, "analyst")

    def test_definition_names_immutable(self):
        self.define()

        with self.assertRaisesRegex(ValueError, "already exists"):
            self.define()

        self.assertEqual(load_case(self.case)["history"][-1]["action"], "hunt_defined")

    def test_definition_validation_and_limits(self):
        invalid = [
            {"all": []},
            {"not": {}},
            {"field": "x", "op": "equals", "value": 1},
            {"field": "/x", "op": "re", "value": ".*"},
            {"field": "/x", "op": "exists", "value": "false"},
            {"field": "/x", "op": "contains", "value": ""},
        ]

        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError):
                validate_expression(item)

        node = self.definition["condition"]

        for _ in range(18):
            node = {"not": node}

        with self.assertRaises(ValueError):
            validate_expression(node)

        with self.assertRaises(ValueError):
            validate_expression({"any": [self.definition["condition"]] * 129})

        with self.assertRaises(ValueError):
            validate_definition(
                {
                    "schema_version": True,
                    "hypothesis": "test",
                    "condition": self.definition["condition"],
                },
            )

    def test_corrupt_index_prevents_scope_pivot(self):
        self.attach()
        self.define()
        _, _, output = self.run_hunt()

        with (output / "results.sqlite").open("ab") as stream:
            stream.write(b"tampered")

        with self.assertRaisesRegex(ValueError, "changed"):
            inspect_scope(output, "host")

    def test_changed_metadata_and_evidence_page_rejected(self):
        self.attach()
        self.define()
        _, _, output = self.run_hunt()
        page = output / "events-0001.html"
        original = page.read_bytes()
        page.write_text("changed")

        with self.assertRaisesRegex(ValueError, "page changed"):
            inspect_scope(output, "host", "host-a", True)

        page.write_bytes(original)
        manifest = output / "report.json"
        value = json.loads(manifest.read_text())
        value["counts"]["match"] = 999
        manifest.write_text(json.dumps(value))

        with self.assertRaisesRegex(ValueError, "metadata changed"):
            inspect_scope(output, "host")

    def test_selected_rows_only(self):
        self.source.write_text(
            "\n".join((json.dumps(e) for e in [self.event(), self.event("other")])),
        )
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        selection = self.root / "selection"
        create_selection(self.dataset, selection, {"rows": [2]})
        add_dataset(self.case, self.dataset, selection)
        self.define()
        report, rows, _ = self.run_hunt()
        self.assertEqual(report["counts"], {"no_match": 1})
        self.assertEqual(rows[0]["row_id"], 2)

    def test_partial_import_preserves_uncertainty(self):
        self.source.write_text(json.dumps(self.event()) + """
invalid""")
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        add_dataset(self.case, self.dataset)
        self.define()
        report, _, _ = self.run_hunt()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(report["limitations"][0]["dataset_status"], "partial")

    def test_html_escaping_and_top_limit(self):
        self.attach(
            [self.event("<script>alert(1)</script> --demo", host=str(i)) for i in range(101)],
        )
        self.define()
        report, _, output = self.run_hunt()
        self.assertEqual(len(report["pages"]), 2)
        self.assertTrue(report["entities"]["host"]["truncated"])
        self.assertEqual(report["entities"]["host"]["distinct_observed"], 101)
        html = (output / "events-0001.html").read_text()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertEqual(len(inspect_scope(output, "host", limit=500)["items"]), 101)

    def test_interruption_retains_explicit_incomplete_report(self):
        self.attach()
        self.define()

        with patch("handlers.hunt_runner.evaluate", side_effect=KeyboardInterrupt):
            report, _, output = self.run_hunt()

        self.assertEqual(report["status"], "interrupted")
        self.assertTrue((output / "report.json").is_file())

        with self.assertRaises(ValueError):
            inspect_scope(output, "host")

    def test_runtime_filters_recorded_and_no_overwrite(self):
        self.attach()
        self.define()
        report, rows, output = self.run_hunt(filters={"host": "absent"})
        self.assertEqual(report["counts"], {"out_of_scope": 2})
        self.assertEqual(report["hypothesis_result"], "undetermined")

        with self.assertRaises(FileExistsError):
            run_hunt(self.case, "demo", output)

        with self.assertRaises(ValueError):
            run_hunt(self.case, "demo", self.case / "report")

    def test_cli_define_and_run_json_without_bootstrap(self):
        self.attach()
        command = [
            sys.executable,
            "-B",
            str(ROOT / "main.py"),
            "hunt",
            "define",
            str(self.case),
            "--name",
            "demo",
            "--author",
            "analyst",
            "--hypothesis",
            "Demo observation",
            "--field",
            "/command_line",
            "--op",
            "contains",
            "--value=--demo",
            "--json",
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stderr)
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "main.py"),
                "hunt",
                "run",
                str(self.case),
                "--name",
                "demo",
                "--output-dir",
                str(self.root / "cli-report"),
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["counts"]["match"], 1)


if __name__ == "__main__":
    unittest.main()
