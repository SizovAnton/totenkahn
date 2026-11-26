import csv
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.evidence import (
    import_dump,
    inspect_dataset,
    verify_dataset,
    preview_source,
)
from handlers.matching import field_check, validate_rule, report_handler
from handlers.value_operations import number, advanced
from handlers.dump_analysis import analyze_dump
from handlers.hunt_definition import evaluate, validate_expression
from handlers.case_store import create_case, add_dataset, verify_case, export_case
from handlers.tabular_input import options


class InputValueTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.event = {
            "timestamp": "2026-11-20T10:00:00Z",
            "host": "fixture",
            "event_id": "1",
            "command_line": "Demo --review",
            "Score": "10.5",
            "Address": "192.0.2.7",
        }

    def ingest(self, name, content, reader_options=None):
        source = self.root / name
        source.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        target = self.root / (name.replace(".", "-") + "-dataset")
        report = import_dump(
            ROOT, source, target, profile="generic-v1", reader_options=reader_options
        )

        return (target, report)

    def csv_text(self, events=None, delimiter=","):
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=list(self.event), delimiter=delimiter)
        writer.writeheader()
        writer.writerows(events or [self.event])

        return output.getvalue()

    def test_csv_multiline_quotes_locator_and_original(self):
        self.event["command_line"] = """first,"quoted"
second"""
        raw = self.csv_text()
        dataset, report = self.ingest("events.csv", raw)
        self.assertEqual(report["status"], "passed")
        item = inspect_dataset(dataset, row_id=1)["items"][0]
        self.assertEqual(item["event"]["command_line"], self.event["command_line"])
        self.assertEqual(item["locator"], {"record": 1, "line_start": 2, "line_end": 3})
        self.assertEqual(
            item["mapping"]["command_line"]["original_cell"],
            self.event["command_line"],
        )
        self.assertEqual((dataset / report["files"][0]["stored"]).read_bytes(), raw.encode())

    def test_tsv_utf16_bom(self):
        self.event["command_line"] = "перевірка"
        dataset, report = self.ingest(
            "events.tsv",
            self.csv_text(delimiter="\t").encode("utf-16"),
            {"encoding": "utf-16"},
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            inspect_dataset(dataset, row_id=1)["items"][0]["event"]["command_line"],
            "перевірка",
        )

    def test_semicolon_and_cp1252(self):
        self.event["command_line"] = "café"
        dataset, report = self.ingest(
            "events.csv",
            self.csv_text(delimiter=";").encode("cp1252"),
            {"encoding": "cp1252", "delimiter": ";"},
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            inspect_dataset(dataset, row_id=1)["items"][0]["event"]["command_line"],
            "café",
        )

    def test_duplicate_header_rejected(self):
        _, report = self.ingest(
            "events.csv",
            """host,host
a,b
""",
        )
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["counts"]["accepted"], 0)
        self.assertIn("unique", report["files"][0]["error"])

    def test_bad_width_does_not_hide_next_record(self):
        raw = self.csv_text()
        header, row = raw.splitlines()
        dataset, report = self.ingest(
            "events.csv",
            header + """
short
""" + row + "\n",
        )
        self.assertEqual(report["counts"], {"read": 2, "accepted": 1, "rejected": 1})
        self.assertEqual(
            inspect_dataset(dataset, row_id=1)["items"][0]["locator"]["line_start"],
            3,
        )

    def test_unterminated_quote_marks_partial(self):
        _, report = self.ingest(
            "events.csv",
            self.csv_text() + """"unterminated
""",
        )
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"]["accepted"], 1)
        self.assertIn("Malformed", report["files"][0]["error"])

    def test_null_token_explicit_and_strings_preserved(self):
        self.event["command_line"] = "NULL"
        dataset, _ = self.ingest("default.csv", self.csv_text())
        self.assertEqual(
            inspect_dataset(dataset, row_id=1)["items"][0]["event"]["command_line"],
            "NULL",
        )
        dataset, _ = self.ingest("explicit.csv", self.csv_text(), {"null_value": "NULL"})
        item = inspect_dataset(dataset, row_id=1)["items"][0]
        self.assertIsNone(item["event"]["command_line"])
        self.assertEqual(item["mapping"]["command_line"]["original_cell"], "NULL")
        self.assertEqual(
            item["mapping"]["command_line"]["input_conversion"],
            "explicit_tabular_null_token",
        )
        self.assertEqual(item["event"]["fields"]["Score"], "10.5")

    def test_empty_csv_cell_not_missing(self):
        self.event["command_line"] = ""
        dataset, _ = self.ingest("events.csv", self.csv_text())
        item = inspect_dataset(dataset, row_id=1)["items"][0]
        self.assertTrue(item["mapping"]["command_line"]["present"])
        self.assertEqual(item["mapping"]["command_line"]["state"], "empty")

    def test_csv_preview_readonly(self):
        source = self.root / "preview.csv"
        source.write_text(self.csv_text())
        report = preview_source(source, profile="generic-v1", limit=1)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_bad_options_rejected_before_output(self):
        invalid: list[dict[str, Any]] = [
            {"delimiter": "::"},
            {"max_expanded_mib": 0},
            {"encoding": "guess"},
        ]

        for opt in invalid:
            with self.assertRaises(ValueError):
                options(**opt)

    def test_gzip_csv_and_jsonl_integrity(self):
        for name, raw in [
            ("events.csv.gz", self.csv_text()),
            (
                "events.jsonl.gz",
                json.dumps(self.event) + "\n",
            ),
        ]:
            with self.subTest(name=name):
                data = gzip.compress(raw.encode(), mtime=0)
                dataset, report = self.ingest(name, data)
                self.assertEqual(report["status"], "passed")
                self.assertEqual(verify_dataset(dataset)["status"], "passed")
                item = inspect_dataset(dataset, row_id=1)["items"][0]
                self.assertEqual(item["locator"]["container"], "gzip")
                self.assertEqual(item["event"]["command_line"], self.event["command_line"])
                self.assertEqual((dataset / report["files"][0]["stored"]).read_bytes(), data)
                (dataset / report["files"][0]["expanded"]["stored"]).write_bytes(b"changed")
                self.assertEqual(verify_dataset(dataset)["status"], "failed")

    def test_gzip_crc_error_never_indexes_partial_payload(self):
        blob = bytearray(gzip.compress((json.dumps(self.event) + "\n").encode()))
        blob[-8] ^= 255
        dataset, report = self.ingest("events.jsonl.gz", bytes(blob))
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["counts"]["accepted"], 0)
        self.assertTrue((dataset / report["files"][0]["stored"]).exists())

    def test_truncated_gzip(self):
        _, report = self.ingest(
            "events.jsonl.gz", gzip.compress(json.dumps(self.event).encode())[:-5]
        )
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["counts"]["accepted"], 0)

    def test_gzip_expansion_limit(self):
        _, report = self.ingest(
            "events.jsonl.gz",
            gzip.compress(b" " * (1024 * 1024 + 1)),
            {"max_expanded_mib": 1},
        )
        self.assertEqual(report["status"], "error")
        self.assertIn("limit", report["files"][0]["error"])
        self.assertEqual(report["counts"]["accepted"], 0)

    def test_gzip_case_snapshot_verifies(self):
        dataset, _ = self.ingest("events.csv.gz", gzip.compress(self.csv_text().encode()))
        case = self.root / "case"
        create_case(case, "fixture", "description")
        add_dataset(case, dataset, None, "fixture")
        self.assertEqual(verify_case(case)["status"], "passed")
        from zipfile import ZipFile

        archive = self.root / "case.zip"
        export_case(case, archive)

        with ZipFile(archive) as zipped:
            self.assertTrue(any(("/derived/" in name for name in zipped.namelist())))
            zipped.extractall(self.root / "received-case")

        self.assertEqual(verify_case(self.root / "received-case")["status"], "passed")

    def test_numeric_precision_and_negative(self):
        self.assertTrue(advanced("9007199254740993", 9007199254740992, "gt")["result"])
        self.assertTrue(advanced("-1.25", "-1.2", "lt")["result"])
        self.assertTrue(advanced("1e2", 100, "gte")["result"])

    def test_invalid_numeric_is_unknown(self):
        for value in (True, None, "NaN", "Infinity", "0x10", "10ms", " 10 ", {}, [], "1e999999"):
            with self.subTest(value=value):
                self.assertIsNone(advanced(value, 1, "gt")["result"])

    def test_cidr_ipv4_ipv6_and_mismatched_versions(self):
        self.assertTrue(advanced("192.0.2.4", "192.0.2.0/24", "cidr")["result"])
        self.assertTrue(advanced("2001:db8::1", "2001:db8::/32", "cidr")["result"])
        self.assertFalse(advanced("192.0.2.4", "2001:db8::/32", "cidr")["result"])
        self.assertIsNone(advanced("bad", "192.0.2.0/24", "cidr")["result"])

    def test_case_sensitive_sigma(self):
        self.assertTrue(field_check("DEMO", "demo", ["contains"])["result"])
        self.assertFalse(field_check("DEMO", "demo", ["contains", "cased"])["result"])
        self.assertTrue(field_check("DEMO", "DE*", ["cased"])["result"])

    def test_multivalue_all_each_expected_has_a_witness(self):
        check = field_check(["alpha", "beta"], ["alpha", "beta"], ["contains", "all"])
        self.assertTrue(check["result"])
        self.assertFalse(check["unknown"])
        self.assertTrue(check["checks"][1]["Elements"][1]["result"])
        self.assertFalse(field_check(["alpha"], ["alpha", "beta"], ["all"])["result"])

    def test_mixed_array_remains_unknown(self):
        check = field_check(["alpha", {}], "alpha", [])
        self.assertTrue(check["result"])
        self.assertTrue(check["unknown"])

    def test_explicit_null_vs_empty_missing_array(self):
        self.assertTrue(field_check(None, None, [])["result"])
        self.assertFalse(field_check("", None, [])["result"])
        self.assertFalse(field_check([None], None, [])["result"])
        self.assertFalse(field_check(None, None, [], False)["result"])
        self.assertFalse(field_check([], "x", [])["result"])

    def rule(self, key="Score|gt", expected=10):
        return {
            "title": "Fixture",
            "logsource": {"product": "windows"},
            "detection": {"selection": {key: expected}, "condition": "selection"},
        }

    def test_rule_validation(self):
        for key, value in [
            ("Score|gt", 10),
            ("Score|lte", "1.5"),
            ("Address|cidr", "192.0.2.0/24"),
            ("CommandLine|cased", "Demo"),
            ("CommandLine", None),
        ]:
            validate_rule(self.rule(key, value))

        for key, value in [
            ("Score|gt", True),
            ("Score|gt", "NaN"),
            ("Address|cidr", "192.0.2.1/24"),
            ("CommandLine", [None, "x"]),
            ("CommandLine|contains", None),
            ("CommandLine|re", ".*"),
            ("Score|gt|cased", 10),
        ]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_rule(self.rule(key, value))

    def test_legacy_replay_invalid_numeric_not_negative_match(self):
        event = {
            "event_id": "1",
            "data_fields": {"Score": "bad"},
            "record_id": "r",
            "computer": "h",
            "channel": "c",
            "provider": "p",
            "system_time": None,
            "source": {"product": "windows"},
        }
        rule = self.rule()
        rule["detection"]["condition"] = "not selection"
        result = report_handler([event], rule)[0]
        self.assertIsNone(result["Selection"])
        self.assertTrue(result["Checks"]["selection"]["Score|gt"]["Unknown"])

    def test_hunt_shared_numeric_and_cidr(self):
        for op, actual, expected in [("gt", "10.5", 10), ("cidr", "192.0.2.7", "192.0.2.0/24")]:
            expression = {"field": "/value", "op": op, "value": expected}
            validate_expression(expression)
            self.assertTrue(evaluate(expression, {"value": actual}, {})["result"])
            self.assertIsNone(evaluate({"not": expression}, {"value": "bad"}, {})["result"])

    def test_hunt_array_quantifier_explicit(self):
        expr = {"field": "/value", "op": "gt", "value": 5}
        self.assertIsNone(evaluate(expr, {"value": [10, 2]}, {})["result"])
        self.assertTrue(evaluate({**expr, "values": "any"}, {"value": [10, 2]}, {})["result"])
        self.assertFalse(evaluate({**expr, "values": "all"}, {"value": [10, 2]}, {})["result"])
        self.assertIsNone(evaluate({**expr, "values": "all"}, {"value": []}, {})["result"])
        self.assertIsNone(
            evaluate({**expr, "values": "all"}, {"value": [10, "bad"]}, {})["result"],
        )

    def test_array_hunt_validation(self):
        for expression in (
            {"field": "/a", "op": "exists", "value": True, "values": "all"},
            {"field": "/a", "op": "cidr", "value": "192.0.2.0/24", "case_sensitive": False},
        ):
            with self.assertRaises(ValueError):
                validate_expression(expression)

    def test_csv_analysis_and_preflight(self):
        dataset, _ = self.ingest("events.csv.gz", gzip.compress(self.csv_text().encode()))
        rule = self.root / "rule.yaml"
        rule.write_text(
            """title: values
logsource:
  product: windows
detection:
  selection:
    Score|gte: 10
    Address|cidr: 192.0.2.0/24
  condition: selection
""",
        )
        mapping = self.root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "fixture",
                    "logsource": {"product": "windows"},
                    "fields": {},
                },
            ),
        )

        with patch(
            "handlers.dump_analysis.report_handler",
            side_effect=AssertionError("No matching"),
        ):
            report = analyze_dump(
                ROOT,
                dataset,
                self.root / "preflight",
                rule=rule,
                mapping_path=mapping,
                preflight_only=True,
            )

        self.assertEqual(report["rules"][0]["readiness"]["fully_evaluable"], 1)
        report = analyze_dump(
            ROOT, dataset, self.root / "analysis", rule=rule, mapping_path=mapping
        )
        self.assertEqual(report["rules"][0]["counts"], {"match": 1})
        record = json.loads((self.root / "analysis/rule-0001/events.jsonl").read_text())
        check = record["engine_evaluation"]["Checks"]["selection"]["Score|gte"]
        self.assertEqual(check["Value Checks"][0]["Elements"][0]["actual_normalized"], "10.5")

    def test_gzip_finding_ci_is_portable(self):
        from handlers.finding_store import create_finding
        from handlers.finding_suite import export_suite
        from handlers.ci import run_ci
        import shutil

        dataset, _ = self.ingest("events.csv.gz", gzip.compress(self.csv_text().encode()))
        case = self.root / "case"
        create_case(case, "fixture")
        add_dataset(case, dataset, label="fixture")
        create_finding(
            case,
            "positive",
            "fixture",
            "tester",
            "reviewed positive",
            True,
            attachment="fixture",
            rows=[1],
        )
        rule = self.root / "rule.yaml"
        rule.write_text(
            """title: numbers
logsource:
  product: windows
detection:
  selection:
    Score|gte: 10
  condition: selection
""",
        )
        mapping = self.root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "fixture",
                    "logsource": {"product": "windows"},
                    "fields": {},
                },
            ),
        )
        bundle = self.root / "bundle"
        export_suite(ROOT, case, ["positive"], rule, rule, bundle, mapping)
        received = self.root / "received"
        shutil.copytree(bundle, received)
        shutil.rmtree(bundle)
        shutil.rmtree(case)
        shutil.rmtree(dataset)
        report = run_ci(received / "pipeline.json", self.root / "ci")
        self.assertEqual(report["status"], "passed")
        self.assertTrue(list(received.rglob("derived/*.csv")))

    def test_record_limit_restores_csv_state(self):
        from handlers import tabular_input

        old = csv.field_size_limit()

        with patch.object(tabular_input, "MAX_RECORD", 40):
            _, report = self.ingest(
                "big.csv",
                '''host
"'''
                + "x" * 60
                + """"
""",
            )

        self.assertEqual(report["status"], "error")
        self.assertEqual(csv.field_size_limit(), old)

    def test_preflight_only_does_not_compare_values(self):
        from handlers.matching import value_supported

        with patch("handlers.matching.scalar_check", side_effect=AssertionError("No comparison")):
            self.assertTrue(value_supported("10", 1, ["gt"], True))
            self.assertTrue(value_supported(["alpha"], "beta", ["contains"], True))

    def test_numeric_json_float_is_supported(self):
        self.assertTrue(field_check(1.25, 1, ["gt"])["result"])
        self.assertFalse(field_check(1.25, 1.25, ["gt"])["result"])


if __name__ == "__main__":
    unittest.main()
