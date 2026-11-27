import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.case_store import (
    create_case,
    add_dataset,
    load_case,
    set_state,
    export_case,
    verify_case,
)
from handlers.evidence import import_dump, file_hash
from handlers.finding_store import create_finding
from handlers.finding_suite import export_suite, load_evidence_suite
from handlers.hunt_store import define_hunt
from handlers.hunt_runner import run_hunt
from handlers.ci import run_ci
from reporting.regression import run_regression


class FindingTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-findings-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = self.root / "case"
        self.dataset = self.root / "dataset"
        self.source = self.root / "events.jsonl"
        self.bundle = self.root / "bundle"
        create_case(self.case, "Reviewed fixture evidence")
        self.source.write_text(
            "\n".join(
                (
                    json.dumps(event)
                    for event in [
                        {
                            "timestamp": "2026-11-19T10:00:00Z",
                            "host": "fixture-host",
                            "event_id": "process",
                            "command_line": "example.exe --demo",
                        },
                        {
                            "timestamp": "2026-11-19T10:01:00Z",
                            "host": "fixture-host",
                            "event_id": "process",
                            "command_line": "other.exe",
                        },
                        {
                            "timestamp": "2026-11-19T10:02:00Z",
                            "host": "fixture-host",
                            "event_id": "network",
                        },
                    ]
                ),
            ),
        )
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        self.attachment = add_dataset(self.case, self.dataset, label="workstation")
        self.rule = self.root / "rule.yaml"
        self.rule.write_text(
            """title: Test rule
logsource:
  product: windows
  service: demo
detection:
  selection:
    CommandLine|contains: --demo
  condition: selection
""",
        )
        self.mapping = self.root / "mapping.json"
        self.mapping.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "fixture-source",
                    "logsource": {"product": "windows", "service": "demo"},
                    "fields": {},
                },
            ),
        )

    def finding(self, name="positive", rows=None, expected=True):
        return create_finding(
            self.case,
            name,
            "Reviewed fixture",
            "engineer",
            "Explicit manual review",
            expected,
            attachment="workstation",
            rows=rows or [1],
        )

    def export(self, names=None, mapping=True):
        return export_suite(
            ROOT,
            self.case,
            names or ["positive"],
            self.rule,
            self.rule,
            self.bundle,
            self.mapping if mapping else None,
        )

    def ci(self):
        return run_ci(
            self.bundle / "pipeline.json",
            self.root / ("ci-" + str(len(list(self.root.glob("ci-*"))))),
        )

    def test_positive_negative_pipeline_and_provenance(self):
        finding = self.finding()
        self.finding("negative", [2], False)
        self.export(["positive", "negative"])
        result = self.ci()
        self.assertEqual(result["status"], "passed")
        cases = result["jobs"][0]["cases"]
        self.assertEqual(
            [case["comparison"] for case in cases],
            ["unchanged_met", "unchanged_met"],
        )
        self.assertEqual(cases[0]["finding"]["sha256"], finding["sha256"])
        self.assertEqual(cases[0]["events"][0]["candidate"]["locator"], {"line": 1})
        self.assertEqual(
            cases[0]["events"][0]["candidate"]["source"]["sha256"],
            file_hash(self.source),
        )
        xml = ET.parse(self.root / "ci-0/junit.xml").getroot()
        self.assertEqual(xml.attrib["failures"], "0")
        html = self.root / "ci-0" / result["jobs"][0]["html"]
        self.assertIn("Reviewed finding", html.read_text())

    def test_candidate_regression_fails_existing_ci_gate(self):
        self.finding()
        self.export()
        candidate = self.bundle / "candidate.yaml"
        candidate.write_text(candidate.read_text().replace("--demo", "--absent"))
        result = self.ci()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["jobs"][0]["counts"]["regressed"], 1)
        self.assertEqual(result["jobs"][0]["cases"][0]["comparison"], "regressed")
        self.assertGreater(
            int(ET.parse(self.root / "ci-0/junit.xml").getroot().attrib["failures"]),
            0,
        )

    def test_new_candidate_field_is_insufficient_not_negative_pass(self):
        self.finding("negative", [2], False)
        self.export(["negative"])
        candidate = self.bundle / "candidate.yaml"
        candidate.write_text(candidate.read_text().replace("CommandLine", "MissingField"))
        result = self.ci()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["jobs"][0]["counts"]["insufficient"], 1)
        self.assertEqual(
            result["jobs"][0]["cases"][0]["candidate"]["status"],
            "insufficient_data",
        )

    def test_missing_field_under_not_remains_insufficient(self):
        self.finding("missing", [3], True)
        self.export(["missing"])
        candidate = self.bundle / "candidate.yaml"
        candidate.write_text(
            candidate.read_text().replace("condition: selection", "condition: not selection"),
        )
        result = self.ci()
        case = result["jobs"][0]["cases"][0]
        self.assertEqual(case["candidate"]["status"], "insufficient_data")
        self.assertTrue(case["events"][0]["candidate"]["engine_evaluation"]["Selection"])

    def test_each_selected_event_must_match_expectation(self):
        self.finding(rows=[1, 2])
        self.export()
        result = self.ci()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["jobs"][0]["cases"][0]["candidate"]["status"], "not_met")

    def test_expectation_not_inferred_from_hunt_result(self):
        define_hunt(
            self.case,
            "demo",
            {
                "schema_version": 1,
                "hypothesis": "Demo marker",
                "condition": {"field": "/command_line", "op": "contains", "value": "--demo"},
            },
            "analyst",
        )
        run_hunt(self.case, "demo", self.root / "hunt")
        finding = create_finding(
            self.case,
            "negative",
            "Reviewed exception",
            "analyst",
            "Analyst explicitly expects no rule match",
            False,
            hunt_report=self.root / "hunt",
            results=[1],
        )
        self.assertFalse(finding["expected_match"])
        self.assertEqual(finding["origin"]["selected_results"][0]["decision"], "match")
        self.export(["negative"])
        self.assertEqual(self.ci()["status"], "failed")

    def test_foreign_hunt_case_rejected(self):
        define_hunt(
            self.case,
            "demo",
            {
                "schema_version": 1,
                "hypothesis": "Demo",
                "condition": {"field": "/command_line", "op": "exists", "value": True},
            },
            "analyst",
        )
        run_hunt(self.case, "demo", self.root / "hunt")
        other = self.root / "other"
        create_case(other, "Other case")

        with self.assertRaisesRegex(ValueError, "another case"):
            create_finding(
                other,
                "wrong",
                "wrong",
                "analyst",
                "reason",
                True,
                hunt_report=self.root / "hunt",
                results=[1],
            )

    def test_unknown_or_duplicate_references_rejected(self):
        for rows in ([999], [1, 1], []):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                create_finding(
                    self.case,
                    "bad",
                    "Bad",
                    "author",
                    "reason",
                    True,
                    attachment="workstation",
                    rows=rows,
                )

        with self.assertRaises(ValueError):
            create_finding(
                self.case,
                "bad",
                "Bad",
                "author",
                "reason",
                "match",
                attachment="workstation",
                rows=[1],
            )

    def test_findings_immutable_and_closed_case_protected(self):
        self.finding()

        with self.assertRaisesRegex(ValueError, "exists"):
            self.finding()

        set_state(self.case, "closed", "analyst", "Reviewed")

        with self.assertRaisesRegex(ValueError, "closed"):
            self.finding("new")

        self.export()
        self.assertEqual(self.ci()["status"], "passed")

    def test_conflicting_expectations_rejected(self):
        self.finding()
        self.finding("opposite", [1], False)

        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.export(["positive", "opposite"])

    def test_missing_logsource_mapping_is_insufficient(self):
        self.finding()
        self.export(mapping=False)
        result = self.ci()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["jobs"][0]["counts"]["insufficient"], 1)

    def test_mapping_and_evidence_tamper_rejected(self):
        self.finding()
        self.export()
        mapping = self.bundle / "mapping.json"
        original = mapping.read_bytes()
        mapping.write_text("{}")
        self.assertEqual(self.ci()["status"], "error")
        mapping.write_bytes(original)
        original_file = next((self.bundle / "case/evidence").glob("*/dataset/originals/*"))
        original_file.write_text("tampered")
        self.assertEqual(self.ci()["status"], "error")

    def test_suite_expectation_list_pinned(self):
        self.finding()
        self.export()
        path = self.bundle / "suite.json"
        value = json.loads(path.read_text())
        value["findings"] = []
        path.write_text(json.dumps(value))

        with self.assertRaises(ValueError):
            load_evidence_suite(path)

    def test_bundle_relocation_without_original_case(self):
        self.finding()
        self.export()
        moved = self.root / "moved"
        shutil.copytree(self.bundle, moved)
        shutil.rmtree(self.bundle)
        shutil.rmtree(self.case)
        shutil.rmtree(self.dataset)
        self.assertEqual(
            run_ci(moved / "pipeline.json", self.root / "moved-ci")["status"],
            "passed",
        )

    def test_case_export_carries_findings(self):
        finding = self.finding()
        archive = self.root / "case.zip"
        export_case(self.case, archive)

        with ZipFile(archive) as zipfile:
            zipfile.extractall(self.root / "received")

        self.assertEqual(verify_case(self.root / "received")["status"], "passed")
        self.assertEqual(load_case(self.root / "received")["findings"][0], finding)

    def test_failed_export_marked_incomplete(self):
        self.finding()

        with patch("handlers.finding_suite.copy_checked", side_effect=OSError("disk fixture")):
            with self.assertRaises(OSError):
                self.export()

        self.assertTrue((self.bundle / "EXPORT-INCOMPLETE.txt").exists())

        with self.assertRaisesRegex(ValueError, "incomplete"):
            load_evidence_suite(self.bundle / "suite.json")

    def test_output_reuse_and_nested_case_rejected(self):
        self.finding()
        self.export()

        with self.assertRaises(FileExistsError):
            self.export()

        with self.assertRaises(ValueError):
            export_suite(
                ROOT,
                self.case,
                ["positive"],
                self.rule,
                self.rule,
                self.case / "bundle",
                self.mapping,
            )

    def test_legacy_suite_still_works(self):
        report = run_regression(
            ROOT / "examples/ci/suite.json",
            ROOT / "examples/regression/baseline.yaml",
            ROOT / "examples/ci/candidate.yaml",
        )
        self.assertEqual(report["report_type"], "regression")
        self.assertEqual(len(report["cases"]), 2)

    def test_cli_requires_explicit_expectation(self):
        command = [
            sys.executable,
            "-B",
            str(ROOT / "main.py"),
            "finding",
            "add",
            str(self.case),
            "--name",
            "positive",
            "--title",
            "Reviewed",
            "--author",
            "analyst",
            "--reason",
            "Manual review",
            "--attachment",
            "workstation",
            "--row",
            "1",
        ]
        failed = subprocess.run(command, capture_output=True, text=True, timeout=60)
        self.assertEqual(failed.returncode, 2)
        process = subprocess.run(
            command + ["--expect", "match", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["finding"]["expected_match"])

    def test_improved_candidate_passes(self):
        self.finding()
        self.export()
        baseline = self.bundle / "baseline.yaml"
        baseline.write_text(baseline.read_text().replace("--demo", "--missing"))
        result = self.ci()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["jobs"][0]["cases"][0]["comparison"], "improved")

    def test_partial_selected_dataset_cannot_pass(self):
        partial_source = self.root / "partial.jsonl"
        partial_source.write_text(self.source.read_text().splitlines()[0] + """
invalid""")
        partial = self.root / "partial"
        import_dump(ROOT, partial_source, partial, profile="generic-v1")
        add_dataset(self.case, partial, label="partial")
        create_finding(
            self.case,
            "partial",
            "Partial source",
            "analyst",
            "Review",
            True,
            attachment="partial",
            rows=[1],
        )
        self.export(["partial"])
        result = self.ci()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["jobs"][0]["counts"]["insufficient"], 1)

    def test_unknown_logsource_never_successful_negative(self):
        self.finding("negative", [2], False)
        self.export(["negative"])
        candidate = self.bundle / "candidate.yaml"
        candidate.write_text(
            candidate.read_text().replace("service: demo", "service: unrelated"),
        )
        result = self.ci()
        self.assertEqual(
            result["jobs"][0]["cases"][0]["candidate"]["status"],
            "insufficient_data",
        )
        self.assertEqual(result["status"], "failed")

    def test_lock_must_cover_all_inputs_even_if_resealed(self):
        from handlers.evidence import canonical, digest

        self.finding()
        self.export()
        path = self.bundle / "evidence-lock.json"
        value = json.loads(path.read_text())
        del value["files"]["mapping.json"]
        value.pop("sha256")
        value["sha256"] = digest(canonical(value))
        path.write_text(json.dumps(value))

        with self.assertRaisesRegex(ValueError, "cover every"):
            load_evidence_suite(self.bundle / "suite.json")

    def test_legacy_case_has_no_findings_until_created(self):
        self.assertEqual(load_case(self.case).get("findings", []), [])
        self.finding()
        self.assertEqual(load_case(self.case)["history"][-1]["action"], "finding_created")


if __name__ == "__main__":
    unittest.main()
