import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.evidence import import_dump, file_hash
from handlers.evidence_selection import (
    create_selection,
    load_selection,
    validate_filters,
    pointer,
)
from handlers.dump_analysis import analyze_dump
from reporting.html_report import render_value


class DumpAnalysisTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-analysis-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dataset = self.root / "dataset"
        self.source = self.root / "events.jsonl"
        self.rule = self.root / "rule.yaml"
        self.mapping = self.root / "mapping.json"
        self.mapping.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "test",
                    "logsource": {"product": "windows", "service": "demo"},
                    "fields": {},
                },
            ),
        )
        self.rule.write_text(
            """title: Test
logsource:
  product: windows
  service: demo
detection:
  selection:
    CommandLine|contains: demo
  condition: selection
""",
        )
        self.events = [self.event("demo.exe"), self.event("other.exe")]

    def event(self, command):
        return {
            "timestamp": "2026-11-18T10:00:00Z",
            "host": "host-a",
            "event_id": "process",
            "channel": "test",
            "provider": "fixture",
            "command_line": command,
            "nested": {"n": 7, "a/b": "yes"},
        }

    def ingest(self, events=None):
        self.source.write_text(
            "\n".join((json.dumps(e) for e in (events if events is not None else self.events))),
            encoding="utf-8",
        )

        return import_dump(ROOT, self.source, self.dataset, profile="generic-v1")

    def analyze(self, **kwargs):
        output = self.root / ("report-" + str(len(list(self.root.glob("report-*")))))
        arguments: dict[str, Any] = {"rule": self.rule, "mapping_path": self.mapping}
        arguments.update(kwargs)
        report = analyze_dump(ROOT, self.dataset, output, **arguments)
        rows = []

        if (output / "rule-0001/events.jsonl").is_file():
            rows = [
                json.loads(line)
                for line in (output / "rule-0001/events.jsonl").read_text().splitlines()
            ]

        return (report, rows, output)

    def test_rule_summary_explains_missing_field_in_html_and_json(self):
        missing = self.event("unused")
        del missing["command_line"]
        self.ingest([*self.events, missing])
        report, rows, output = self.analyze()
        reason = report["rules"][0]["reason"]
        self.assertIn("CommandLine: missing in 1 event(s)", reason)
        self.assertIn("INSUFFICIENT DATA: 1", reason)
        self.assertIn(reason, (output / "report.html").read_text())
        self.assertEqual(
            [row["status"] for row in rows], ["match", "no_match", "insufficient_data"]
        )

    def test_preflight_reason_does_not_claim_matching(self):
        self.ingest()
        report, rows, _ = self.analyze(preflight_only=True)
        self.assertIn("matching was not executed", report["rules"][0]["reason"])
        self.assertEqual(rows, [])

    def test_single_value_list_has_no_decorative_number(self):
        html = render_value(["timestamp"])
        self.assertNotIn("<ol", html)
        self.assertIn("list-style:none", html)
        self.assertIn("timestamp", html)
        self.assertIn("<ol", render_value(["first", "second"]))
        self.assertIn("&lt;script&gt;", render_value(["<script>"]))

    def test_match_no_match_explanation_and_provenance(self):
        original = self.ingest()
        before = file_hash(self.dataset / "index.sqlite")
        report, rows, output = self.analyze()
        self.assertEqual(report["status"], "passed")
        self.assertEqual([r["status"] for r in rows], ["match", "no_match"])
        self.assertTrue(rows[0]["engine_evaluation"]["Selection"])
        self.assertFalse(rows[1]["engine_evaluation"]["Selection"])
        self.assertEqual(rows[0]["locator"], {"line": 1})
        self.assertEqual(rows[0]["source"]["sha256"], original["files"][0]["sha256"])
        self.assertEqual(
            rows[0]["compatibility"]["fields"]["CommandLine"]["path"],
            "/command_line",
        )
        self.assertIn("Condition", (output / "rule-0001/events-0001.html").read_text())
        self.assertEqual(before, file_hash(self.dataset / "index.sqlite"))

    def test_missing_field_under_negation_is_provisional(self):
        event = self.event("demo")
        del event["command_line"]
        self.ingest([event])
        self.rule.write_text(
            self.rule.read_text().replace("condition: selection", "condition: not selection"),
        )
        report, rows, _ = self.analyze()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows[0]["status"], "insufficient_data")
        self.assertTrue(rows[0]["engine_evaluation"]["Selection"])
        self.assertTrue(rows[0]["engine_result_provisional"])

    def test_exists_can_intentionally_match_absence(self):
        event = self.event("demo")
        del event["command_line"]
        self.ingest([event])
        self.rule.write_text(
            self.rule.read_text().replace(
                "CommandLine|contains: demo", "CommandLine|exists: false"
            ),
        )
        report, rows, _ = self.analyze()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(rows[0]["status"], "match")

    def test_null_is_insufficient_and_scalar_multivalue_matches(self):
        self.ingest([self.event(None), self.event(["demo", "other"])])
        report, rows, _ = self.analyze()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual([r["status"] for r in rows], ["insufficient_data", "match"])

    def test_unknown_logsource_not_inferred_from_rule(self):
        self.ingest()
        report, rows, _ = self.analyze(mapping_path=None)
        self.assertEqual(report["status"], "needs_verification")
        self.assertIsNone(rows[0]["engine_evaluation"])
        self.assertIn("service", rows[0]["compatibility"]["unknown_logsource"])

    def test_known_mismatch_not_applicable(self):
        self.ingest()
        self.rule.write_text(
            self.rule.read_text().replace("service: demo", "service: security"),
        )
        report, rows, _ = self.analyze()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows[0]["status"], "not_applicable")

    def test_unused_block_does_not_require_fields(self):
        self.ingest()
        self.rule.write_text(self.rule.read_text() + """  unused:
    Missing: value
""")
        report, _, _ = self.analyze()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["rules"][0]["required_fields"], ["CommandLine"])

    def test_integer_conversion_and_explicit_nested_mapping(self):
        self.ingest()
        mapping = json.loads(self.mapping.read_text())
        mapping["fields"] = {"CommandLine": "/fields/nested/n"}
        self.mapping.write_text(json.dumps(mapping))
        self.rule.write_text(
            self.rule.read_text().replace("CommandLine|contains: demo", "CommandLine: '7'"),
        )
        _, rows, _ = self.analyze()
        self.assertEqual(rows[0]["status"], "match")
        self.assertEqual(
            rows[0]["compatibility"]["fields"]["CommandLine"]["conversion"],
            "integer_to_decimal_string",
        )

    def test_combined_filters_and_saved_selection(self):
        self.ingest()
        selection = self.root / "selection"
        saved = create_selection(
            self.dataset,
            selection,
            {
                "host": "host-a",
                "event_type": "process",
                "channel": "test",
                "provider": "fixture",
                "source": "events.jsonl",
                "start": "2026-11-18T09:00:00Z",
                "end": "2026-11-18T11:00:00Z",
                "fields": [
                    {"path": "/command_line", "op": "contains", "value": "demo"},
                    {"path": "/fields/nested/n", "op": "equals", "value": 7},
                ],
            },
        )
        self.assertEqual(saved["count"], 1)
        report, rows, _ = self.analyze(selection=selection)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(rows), 1)

        with self.assertRaises(FileExistsError):
            create_selection(self.dataset, selection, {})

        with self.assertRaises(ValueError):
            self.analyze(selection=selection, filters={"host": "host-a"})

    def test_empty_selection_needs_verification(self):
        self.ingest()
        report, rows, _ = self.analyze(filters={"host": "absent"})
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows, [])

    def test_invalid_filters_rejected(self):
        for filters in (
            {"start": "2026-11-18"},
            {"rows": [True]},
            {"wrong": "value"},
            {"fields": [{"path": "bad", "op": "equals", "value": 1}]},
        ):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                validate_filters(filters)

        self.assertEqual(pointer({"a/b": {"~": 1}}, "/a~1b/~0"), (True, 1))

    def test_explicit_missing_row_is_error(self):
        self.ingest()
        report, _, _ = self.analyze(filters={"rows": [999]})
        self.assertEqual(report["status"], "error")

    def test_membership_tamper_rejected(self):
        self.ingest()
        selection = self.root / "selection"
        create_selection(self.dataset, selection, {})
        (selection / "members.jsonl").write_text("")

        with self.assertRaisesRegex(ValueError, "membership changed"):
            load_selection(self.dataset, selection)

    def test_selection_contract_tamper_rejected(self):
        self.ingest()
        selection = self.root / "selection"
        create_selection(self.dataset, selection, {})
        path = selection / "selection.json"
        value = json.loads(path.read_text())
        value["filters"] = {"host": "other"}
        path.write_text(json.dumps(value))

        with self.assertRaisesRegex(ValueError, "contract changed"):
            load_selection(self.dataset, selection)

    def test_original_tamper_rejected(self):
        manifest = self.ingest()
        (self.dataset / manifest["files"][0]["stored"]).write_text("changed")
        report, _, _ = self.analyze()
        self.assertEqual(report["status"], "error")
        self.assertIn("missing or changed", report["reason"])

    def test_index_tamper_rejected(self):
        self.ingest()

        with (self.dataset / "index.sqlite").open("ab") as stream:
            stream.write(b"changed")

        report, _, _ = self.analyze()
        self.assertEqual(report["status"], "error")
        self.assertIn("index changed", report["reason"])

    def test_partial_import_remains_incomplete(self):
        self.source.write_text(json.dumps(self.events[0]) + """
invalid""")
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        report, rows, _ = self.analyze()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows[0]["status"], "match")

    def test_rule_directory_preserves_success_when_other_rule_invalid(self):
        self.ingest()
        rules = self.root / "rules"
        rules.mkdir()
        shutil.copy2(self.rule, rules / "a.yaml")
        (rules / "b.yaml").write_text("""title: unsupported
""")
        report, _, _ = self.analyze(rule=None, rules_dir=rules)
        self.assertEqual(report["status"], "error")
        self.assertEqual([r["status"] for r in report["rules"]], ["passed", "error"])

    def test_html_escaping_and_pagination(self):
        self.ingest([self.event("<script>alert(1)</script> demo")] * 101)
        report, _, output = self.analyze()
        self.assertEqual(len(report["rules"][0]["pages"]), 2)
        html = (output / "rule-0001/events-0001.html").read_text()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_dataset_relocation_keeps_selection_valid(self):
        self.ingest()
        selection = self.root / "selection"
        create_selection(self.dataset, selection, {})
        moved = self.root / "moved"
        shutil.copytree(self.dataset, moved)
        self.assertEqual(load_selection(moved, selection)["count"], 2)

    def test_cli_json_exit_codes(self):
        self.ingest()
        command = [
            sys.executable,
            "-B",
            str(ROOT / "main.py"),
            "dump",
            "analyze",
            str(self.dataset),
            "--rule",
            str(self.rule),
            "--json",
            "--output-dir",
            str(self.root / "cli"),
        ]
        process = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", timeout=60
        )
        self.assertEqual(process.returncode, 3, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "needs_verification")

    def test_native_windows_source_and_conflicting_declaration(self):
        from check_evidence import XML

        path = self.root / "events.xml"
        path.write_text(
            XML.replace('Name="Synthetic"', 'Name="Microsoft-Windows-Security-Auditing"'),
        )
        import_dump(ROOT, path, self.dataset)
        self.rule.write_text(
            self.rule.read_text()
            .replace("service: demo", "service: security")
            .replace(
                "contains: demo",
                "contains: example",
            ),
        )
        report, rows, _ = self.analyze(mapping_path=None)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(rows[0]["status"], "match")
        report, rows, _ = self.analyze()
        self.assertEqual(rows[0]["status"], "insufficient_data")
        self.assertTrue(rows[0]["compatibility"]["source_conflicts"])


if __name__ == "__main__":
    unittest.main()
