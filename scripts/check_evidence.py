import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.evidence import import_dump, inspect_dataset, verify_dataset, list_issues
from handlers.dump_readers import JsonStream, json_records

XML = '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Synthetic"/><EventID>4688</EventID><EventRecordID>7</EventRecordID><TimeCreated SystemTime="2026-11-18T10:00:00Z"/><Channel>Security</Channel><Computer>fixture-host</Computer></System><EventData><Data Name="CommandLine">example.exe</Data><Data Name="Repeated">a</Data><Data Name="Repeated">b</Data></EventData></Event></Events>'


class EvidenceTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-evidence-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "events.jsonl"
        self.output = self.root / "dataset"
        self.event = {
            "timestamp": "2026-11-18T12:00:00+02:00",
            "host": "fixture-host",
            "event_id": "4688",
            "command_line": "example.exe",
            "extra": {"preserved": True},
        }
        self.source.write_text(json.dumps(self.event) + "\n", encoding="utf-8")

    def run_import(self, source=None, profile: str | None = "generic-v1", output=None, **kwargs):
        return import_dump(
            ROOT,
            source or self.source,
            output or self.output,
            profile=profile,
            **kwargs,
        )

    def test_original_identity_provenance_and_integrity(self):
        report = self.run_import()
        self.assertEqual(report["status"], "passed")
        original = self.output / report["files"][0]["stored"]
        self.assertEqual(original.read_bytes(), self.source.read_bytes())
        item = inspect_dataset(self.output, row_id=1)["items"][0]
        self.assertEqual(item["event"]["time_utc"], "2026-11-18T10:00:00.000000+00:00")
        self.assertEqual(item["event"]["fields"]["extra"], {"preserved": True})
        self.assertEqual(item["mapping"]["host"]["path"], ["host"])
        self.assertEqual(item["locator"], {"line": 1})
        self.assertEqual(verify_dataset(self.output)["status"], "passed")
        other = self.root / "other"
        self.run_import(output=other)
        self.assertEqual(
            item["event_id"],
            inspect_dataset(other, row_id=1)["items"][0]["event_id"],
        )

    def test_bad_jsonl_record_does_not_skip_valid_following_records(self):
        self.source.write_text(json.dumps(self.event) + "\nnot-json\n" + json.dumps(self.event))
        report = self.run_import()
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"], {"read": 3, "accepted": 2, "rejected": 1})
        issue = list_issues(self.output)["items"][0]
        self.assertEqual(issue["locator"]["line"], 2)
        self.assertEqual(report["quality"]["possible_duplicate_occurrences"], 1)

    def test_no_timezone_is_not_assumed_utc(self):
        self.event["timestamp"] = "2026-11-18T10:00:00"
        self.source.write_text(json.dumps(self.event))
        report = self.run_import()
        self.assertEqual(report["status"], "passed_with_warnings")
        self.assertEqual(report["quality"]["warning_counts"]["unknown_timezone"], 1)
        self.assertEqual(
            inspect_dataset(self.output, start="2026-11-18T00:00:00Z")["items"],
            [],
        )

    def test_missing_fields_reported_without_invention(self):
        self.source.write_text('{"unexpected":"value"}')
        report = self.run_import()
        self.assertEqual(report["quality"]["warning_counts"]["missing_host"], 1)
        self.assertIsNone(inspect_dataset(self.output)["items"][0]["event"]["host"])

    def test_xml_repeated_fields_preserved(self):
        path = self.root / "windows.xml"
        path.write_text(XML)
        self.assertEqual(self.run_import(path, profile=None)["status"], "passed")
        item = inspect_dataset(self.output, row_id=1)["items"][0]
        self.assertEqual(item["event"]["fields"]["fields"]["Repeated"], ["a", "b"])
        self.assertEqual(item["event"]["command_line"], "example.exe")
        self.assertEqual(item["locator"], {"event": 1})

    def test_xml_entities_rejected(self):
        path = self.root / "evil.xml"
        path.write_text('<!DOCTYPE x [<!ENTITY a "bad">]><Events/>')
        report = self.run_import(path)
        self.assertEqual(report["status"], "error")
        self.assertIn("DTD", report["files"][0]["error"])

    def test_truncated_xml_is_partial_and_next_file_is_read(self):
        folder = self.root / "inputs"
        folder.mkdir()
        (folder / "a.xml").write_text(XML[:-9])
        (folder / "b.jsonl").write_text(json.dumps(self.event))
        report = self.run_import(folder)
        self.assertEqual(report["status"], "partial")
        self.assertGreaterEqual(report["counts"]["accepted"], 1)
        self.assertTrue(any((f["status"] == "error" for f in report["files"])))

    def test_json_array_streams_and_partial_tail_is_reported(self):
        path = self.root / "array.json"
        path.write_text("[" + json.dumps(self.event) + ",broken")
        report = self.run_import(path)
        self.assertEqual(report["counts"]["accepted"], 1)
        self.assertEqual(report["status"], "partial")

    def test_splunk_envelope_and_result_wrapper(self):
        path = self.root / "splunk.json"
        entry = {
            "_time": "1794996000",
            "host": "splunk-host",
            "EventCode": "4688",
            "_raw": "unchanged",
        }
        path.write_text(json.dumps({"results": [entry, entry], "messages": []}))
        report = self.run_import(path, profile="splunk-v1")
        self.assertEqual(report["counts"]["accepted"], 2)
        self.assertEqual(
            inspect_dataset(self.output, row_id=1)["items"][0]["event"]["fields"]["_raw"],
            "unchanged",
        )
        wrapper = self.root / "wrapper.jsonl"
        wrapper.write_text(
            json.dumps({"preview": False, "result": entry})
            + "\n"
            + json.dumps({"preview": True, "result": entry}),
        )
        report = self.run_import(wrapper, profile="splunk-v1", output=self.root / "wrapper")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"]["rejected"], 1)

    def test_json_requires_profile_and_original_is_retained(self):
        report = self.run_import(profile=None)
        self.assertEqual(report["status"], "error")
        self.assertTrue((self.output / report["files"][0]["stored"]).is_file())

    def test_custom_mapping_is_snapshotted(self):
        profile = self.root / "profile.json"
        profile.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "custom",
                    "time_format": "iso8601",
                    "mappings": {"host": ["device", "name"]},
                },
            ),
        )
        self.source.write_text('{"device":{"name":"mapped"}}')
        report = self.run_import(profile=str(profile))
        profile.write_text("{}")
        self.assertEqual(report["files"][0]["profile"]["id"], "custom")
        self.assertEqual(inspect_dataset(self.output)["items"][0]["event"]["host"], "mapped")

    def test_existing_output_and_nested_output_rejected(self):
        self.run_import()
        before = (self.output / "manifest.json").read_bytes()

        with self.assertRaises(FileExistsError):
            self.run_import()

        self.assertEqual(before, (self.output / "manifest.json").read_bytes())

        with self.assertRaises(ValueError):
            self.run_import(self.root, output=self.root / "nested")

    def test_tampered_original_and_index_detected(self):
        report = self.run_import()
        (self.output / report["files"][0]["stored"]).write_text("changed")

        with (self.output / "index.sqlite").open("ab") as stream:
            stream.write(b"changed")

        result = verify_dataset(self.output)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["issues"]), 2)

    def test_query_is_parameterized_paginated_and_read_only(self):
        self.source.write_text((json.dumps(self.event) + "\n") * 3)
        self.run_import()
        index_before = (self.output / "index.sqlite").read_bytes()
        first = inspect_dataset(self.output, limit=2)
        self.assertEqual(first["next_after"], 2)
        self.assertEqual(len(inspect_dataset(self.output, after=2)["items"]), 1)
        self.assertEqual(inspect_dataset(self.output, host="' OR 1=1 --")["items"], [])
        self.assertEqual(len(inspect_dataset(self.output, text="EXAMPLE.EXE")["items"]), 3)
        self.assertEqual(index_before, (self.output / "index.sqlite").read_bytes())

    def test_interrupt_retains_partial_manifest(self):

        def records(*args, **kwargs):
            yield {"record": self.event, "raw": json.dumps(self.event), "locator": {"line": 1}}

            raise KeyboardInterrupt

        with patch("handlers.evidence.json_records", side_effect=records):
            report = self.run_import()

        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(len(inspect_dataset(self.output)["items"]), 1)

    def test_evtx_error_is_not_empty_success(self):
        path = self.root / "fixture.evtx"
        path.write_bytes(b"inert")

        with patch("handlers.evidence.evtx_export", side_effect=ValueError("Windows unavailable")):
            report = self.run_import(path)

        self.assertEqual(report["status"], "error")
        self.assertTrue((self.output / report["files"][0]["stored"]).is_file())

    def test_evtx_export_records_normalized_without_real_host_access(self):
        path = self.root / "fixture.evtx"
        path.write_bytes(b"inert")

        def export(project, original, derived, timeout):
            derived.write_text(
                json.dumps({"xml": XML.replace("<Events>", "").replace("</Events>", "")}) + "\n",
            )

            return 0

        with patch("handlers.evidence.evtx_export", side_effect=export):
            report = self.run_import(path)

        self.assertEqual(report["status"], "passed")
        self.assertEqual(
            inspect_dataset(self.output, row_id=1)["items"][0]["locator"],
            {"evtx_event": 1},
        )

    def test_json_record_limit_and_duplicate_keys(self):
        with patch("handlers.dump_readers.MAX_RECORD", 20):
            reader = JsonStream(io.StringIO('"' + "a" * 70000 + '"'))

            with self.assertRaises(ValueError):
                reader.value()

        self.source.write_text('{"host":"a","host":"b"}')
        self.assertEqual(self.run_import()["counts"]["rejected"], 1)

    def test_cli_json_without_dependencies(self):
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "main.py"),
                "dump",
                "import",
                str(self.source),
                "--profile",
                "generic-v1",
                "--output-dir",
                str(self.output),
                "--json",
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["counts"]["accepted"], 1)

    def test_unsupported_file_is_retained_and_valid_file_continues(self):
        folder = self.root / "input"
        folder.mkdir()
        (folder / "a.txt").write_text("unrecognized evidence")
        (folder / "b.jsonl").write_text(json.dumps(self.event))
        report = self.run_import(folder)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"]["accepted"], 1)
        self.assertTrue((self.output / report["files"][0]["stored"]).is_file())

    def test_search_preview_does_not_lose_full_fields(self):
        self.event["command_line"] = "x" * 5000
        self.source.write_text(json.dumps(self.event))
        self.run_import()
        preview = inspect_dataset(self.output)["items"][0]
        self.assertEqual(preview["truncated_fields"], ["command_line"])
        self.assertNotIn("fields", preview["event"])
        self.assertEqual(
            len(inspect_dataset(self.output, row_id=1)["items"][0]["event"]["command_line"]),
            5000,
        )

    def test_invalid_time_interval_rejected(self):
        self.run_import()

        with self.assertRaises(ValueError):
            inspect_dataset(self.output, start="2026-11-19T00:00:00Z", end="2026-11-18T00:00:00Z")

    def test_cli_partial_has_distinct_exit_code(self):
        self.source.write_text(json.dumps(self.event) + "\ninvalid")
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "main.py"),
                "dump",
                "import",
                str(self.source),
                "--profile",
                "generic-v1",
                "--output-dir",
                str(self.output),
                "--json",
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["status"], "partial")

    def test_large_array_stream_does_not_read_entire_file(self):

        class SmallReads(io.StringIO):

            def read(self, size: int | None = -1):
                if size is None or size < 0:
                    raise AssertionError("Unbounded read")

                return super().read(min(size, 64))

        stream = SmallReads("[" + ",".join((json.dumps(self.event) for _ in range(2000))) + "]")
        reader = JsonStream(stream)
        records = reader.array()
        next(records)
        self.assertLess(stream.tell(), 1024)
        self.assertEqual(sum((1 for _ in records)), 1999)


if __name__ == "__main__":
    unittest.main()
