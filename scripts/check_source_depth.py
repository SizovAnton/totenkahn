import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.evidence import (
    normalize,
    PROFILES,
    import_dump,
    inspect_dataset,
    verify_dataset,
    preview_source,
)
from handlers.dump_readers import xml_record
from handlers.dump_analysis import analyze_dump
from handlers.evidence_selection import pointer


def windows(
    event_id="4688", fields=None, channel="Security", provider="Microsoft-Windows-Security-Auditing"
):
    root = ET.Element("Event")
    system = ET.SubElement(root, "System")
    ET.SubElement(system, "Provider", Name=provider)

    for key, value in {
        "EventID": event_id,
        "Channel": channel,
        "Computer": "fixture-host",
        "EventRecordID": "7",
    }.items():
        ET.SubElement(system, key).text = value

    ET.SubElement(system, "TimeCreated", SystemTime="2026-11-19T10:00:00Z")
    ET.SubElement(system, "Security", UserID="S-1-5-18")
    data = ET.SubElement(root, "EventData")

    for key, value in (fields or {}).items():
        for item in value if isinstance(value, list) else [value]:
            ET.SubElement(data, "Data", Name=key).text = item

    return ET.tostring(root, encoding="unicode")


class SourceDepthTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.xml = windows(
            fields={
                "NewProcessId": "0x10",
                "ProcessId": "0x08",
                "CommandLine": "example.exe --review",
                "SubjectUserName": "alice",
                "TargetUserName": "bob",
            },
        )

    def norm(self, xml=None):
        return normalize(xml_record(ET.fromstring(xml or self.xml)), PROFILES["windows-xml-v1"])

    def test_security_roles_and_process_identity(self):
        value, trace, warnings = self.norm()
        self.assertEqual((value["process_id"], value["parent_process_id"]), (16, 8))
        self.assertEqual(
            (value["user"], value["actor_user"], value["target_user"], value["system_user_sid"]),
            ("alice", "alice", "bob", "S-1-5-18"),
        )
        self.assertEqual(trace["process_id"]["original_value"], "0x10")
        self.assertEqual(trace["process_id"]["path"], ["fields", "NewProcessId"])
        self.assertFalse(warnings)

    def test_invalid_pid_is_not_a_valid_null(self):
        value, trace, warnings = self.norm(self.xml.replace("0x10", "not-pid"))
        self.assertIsNone(value["process_id"])
        self.assertEqual(trace["process_id"]["state"], "conversion_error")
        self.assertIn("invalid_process_id", warnings)

    def test_unknown_provider_does_not_infer_4688_semantics(self):
        value, trace, _ = self.norm(
            self.xml.replace("Microsoft-Windows-Security-Auditing", "Unknown")
        )
        self.assertEqual(value["process_id"], "0x08")
        self.assertEqual(value["source_profile"], "windows-generic")

    def test_sysmon_pid_decimal(self):
        value, trace, _ = self.norm(
            windows(
                "1",
                {"ProcessId": "010", "User": "DOMAIN\\alice"},
                "Microsoft-Windows-Sysmon/Operational",
                "Microsoft-Windows-Sysmon",
            ),
        )
        self.assertEqual(value["process_id"], 10)
        self.assertEqual(value["user"], "DOMAIN\\alice")

    def test_powershell_multiline(self):
        value, _, _ = self.norm(
            windows(
                "4104",
                {"ScriptBlockText": """first
second"""},
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-PowerShell",
            ),
        )
        self.assertEqual(
            value["script_block"],
            """first
second""",
        )
        self.assertEqual(value["source_profile"], "windows-powershell")

    def test_userdata_namespaces_attributes_and_repeats(self):
        xml = self.xml.replace(
            "</Event>",
            '<UserData><Login xmlns="urn:fixture" type="local"><User>alice</User><User>bob</User></Login></UserData></Event>',
        )
        value, _, _ = self.norm(xml)
        present, user = pointer(value, "/fields/user_data/0/children/0/children/1/text")
        self.assertTrue(present)
        self.assertEqual(user, "bob")
        self.assertEqual(
            value["fields"]["user_data"][0]["children"][0]["attributes"],
            {"type": "local"},
        )
        self.assertEqual(
            value["fields"]["user_data"][0]["children"][0]["tag"],
            "{urn:fixture}Login",
        )

    def test_pointer_list_bounds_and_keys(self):
        self.assertEqual(pointer({"a": [{"0": "yes"}]}, "/a/0/0"), (True, "yes"))

        for key in ("-1", "01", "2"):
            self.assertEqual(pointer({"a": [1]}, "/a/" + key), (False, None))

    def test_field_states(self):
        value, mapping, _ = normalize(
            {"host": None, "event_id": "", "command_line": ["a", "b"], "process_id": True},
            PROFILES["generic-v1"],
        )
        self.assertEqual(
            {
                k: mapping[k]["state"]
                for k in ("host", "event_id", "command_line", "process_id", "timestamp")
            },
            {
                "host": "null",
                "event_id": "empty",
                "command_line": "multivalue",
                "process_id": "unsupported_type",
                "timestamp": "missing",
            },
        )

    def test_splunk_plain_preserves_raw_and_metadata(self):
        record = {
            "_raw": self.xml,
            "sourcetype": "XmlWinEventLog:Security",
            "index": "main",
            "source": "WinEventLog:Security",
            "CommandLine": ["one", "two"],
        }
        value, _, _ = normalize(record, PROFILES["splunk-v1"])
        self.assertNotIn("decoded_raw", value)
        self.assertEqual(value["fields"], record)
        self.assertEqual(value["source_metadata"]["index"], "main")
        self.assertEqual(value["command_line"], ["one", "two"])

    def test_raw_windows_equivalence(self):
        value, trace, warnings = normalize(
            {
                "result": {
                    "_raw": self.xml,
                    "EventCode": "4688",
                    "_time": "1795082400",
                    "ProcessId": "16",
                },
            },
            PROFILES["splunk-raw-windows-v1"],
        )
        direct, _, _ = self.norm()

        for field in ("host", "event_id", "process_id", "command_line", "user", "time_utc"):
            self.assertEqual(value[field], direct[field])

        self.assertEqual(value["normalization_conflicts"], [])
        self.assertEqual(trace["command_line"]["path"], ["result", "_raw"])
        self.assertEqual(trace["command_line"]["decoded_path"], ["fields", "CommandLine"])

    def test_conflict_retains_both_values(self):
        value, trace, warnings = normalize(
            {"_raw": self.xml, "CommandLine": "different"},
            PROFILES["splunk-raw-windows-v1"],
        )
        self.assertEqual(value["command_line"], "different")
        self.assertEqual(value["normalization_conflicts"][0]["decoded"], "example.exe --review")
        self.assertEqual(trace["command_line"]["state"], "conflict")
        self.assertIn("extracted_raw_conflict", warnings)

    def test_invalid_raw_and_dtd_rejected(self):
        for raw in ("broken", "<!DOCTYPE Event><Event/>", "<Events/>"):
            with self.assertRaises(ValueError):
                normalize({"_raw": raw}, PROFILES["splunk-raw-windows-v1"])

    def test_raw_json_is_explicit_generic_schema(self):
        raw = {
            "timestamp": "2026-11-19T10:00:00Z",
            "host": "fixture-host",
            "event_id": "demo",
            "command_line": "example.exe",
        }
        value, trace, _ = normalize({"_raw": json.dumps(raw)}, PROFILES["splunk-raw-json-v1"])
        self.assertEqual(value["command_line"], "example.exe")
        self.assertEqual(trace["command_line"]["decoded_path"], ["command_line"])

    def test_preview_rows_rejected_for_new_profiles(self):
        for profile in ("splunk-v1", "splunk-raw-windows-v1", "splunk-raw-json-v1"):
            with self.assertRaises(ValueError):
                normalize({"preview": True, "result": {"_raw": self.xml}}, PROFILES[profile])

    def ingest(self, content, suffix, profile=None):
        source = self.root / ("source." + suffix)
        source.write_text(content, encoding="utf-8")
        dataset = self.root / ("data-" + suffix)
        report = import_dump(ROOT, source, dataset, profile=profile)
        self.assertEqual(verify_dataset(dataset)["status"], "passed")

        return (dataset, report)

    def rule(self):
        rule = self.root / "rule.yaml"
        rule.write_text(
            """title: Source parity
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: review
  condition: selection
""",
        )

        return rule

    def test_import_raw_invalid_record_retains_next(self):
        content = "\n".join((json.dumps({"_raw": v}) for v in ("bad", self.xml)))
        dataset, report = self.ingest(content, "jsonl", "splunk-raw-windows-v1")
        self.assertEqual(report["counts"], {"read": 2, "accepted": 1, "rejected": 1})
        item = inspect_dataset(dataset, row_id=1)["items"][0]
        self.assertEqual(item["locator"], {"line": 2})
        self.assertEqual(item["mapping"]["process_id"]["original_value"], "0x10")

    def test_preflight_does_not_evaluate_matches(self):
        dataset, _ = self.ingest(self.xml, "xml")

        with patch(
            "handlers.dump_analysis.report_handler",
            side_effect=AssertionError("Must not evaluate"),
        ):
            report = analyze_dump(
                ROOT,
                dataset,
                self.root / "preflight",
                rule=self.rule(),
                preflight_only=True,
            )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["rules"][0]["readiness"]["fully_evaluable"], 1)
        self.assertFalse((self.root / "preflight/rule-0001/events.jsonl").exists())

    def test_windows_and_splunk_rule_decisions_agree(self):
        rule = self.rule()

        for suffix, content, profile in [
            ("xml", self.xml, None),
            ("jsonl", json.dumps({"_raw": self.xml}), "splunk-raw-windows-v1"),
        ]:
            dataset, _ = self.ingest(content, suffix, profile)
            report = analyze_dump(ROOT, dataset, self.root / ("analysis-" + suffix), rule=rule)
            self.assertEqual(report["rules"][0]["counts"], {"match": 1})

    def test_conflict_makes_decision_insufficient(self):
        dataset, _ = self.ingest(
            json.dumps({"_raw": self.xml, "CommandLine": "review"}),
            "jsonl",
            "splunk-raw-windows-v1",
        )
        report = analyze_dump(ROOT, dataset, self.root / "analysis", rule=self.rule())
        self.assertEqual(report["rules"][0]["counts"], {"insufficient_data": 1})
        self.assertEqual(report["rules"][0]["readiness"]["source_states"], {"conflict": 1})

    def test_readiness_null_empty_missing_multivalue(self):
        records = [
            {"timestamp": "2026-11-19T10:00:00Z", "host": "h", "event_id": "1", **extra}
            for extra in (
                {},
                {"command_line": None},
                {"command_line": ""},
                {"command_line": ["review"]},
            )
        ]
        dataset, imp = self.ingest(
            "\n".join(map(json.dumps, records)),
            "jsonl",
            "generic-v1",
        )
        self.assertEqual(
            imp["quality"]["field_states"]["command_line"],
            {"missing": 1, "null": 1, "empty": 1, "multivalue": 1},
        )
        mapping = self.root / "mapping.json"
        mapping.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "id": "reviewed",
                    "logsource": {"product": "windows", "category": "process_creation"},
                    "fields": {},
                },
            ),
        )
        report = analyze_dump(
            ROOT,
            dataset,
            self.root / "analysis",
            rule=self.rule(),
            mapping_path=mapping,
            preflight_only=True,
        )
        check = report["rules"][0]["readiness"]
        self.assertEqual(check["fully_evaluable"], 2)
        self.assertEqual(
            check["fields"]["CommandLine"],
            {"missing": 1, "null": 1, "empty": 1, "multivalue": 1},
        )

    def test_preview_read_only_and_bounded(self):
        source = self.root / "preview.jsonl"
        source.write_text(json.dumps({"_raw": self.xml}) + """
invalid
""")
        before = source.read_bytes()
        result = preview_source(source, profile="splunk-raw-windows-v1", limit=1)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(len(result["samples"]), 1)
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual(len(list(self.root.iterdir())), 1)
        self.assertIn("sampled", result["scope"])

    def test_preview_reports_bad_sample(self):
        source = self.root / "preview.jsonl"
        source.write_text("""invalid
""" + json.dumps({"_raw": self.xml}))
        result = preview_source(source, profile="splunk-raw-windows-v1")
        self.assertEqual(result["status"], "passed_with_warnings")
        self.assertEqual(result["samples"][0]["status"], "error")

    def test_multivalue_raw_windows_does_not_flatten(self):
        xml = windows(fields={"CommandLine": ["a", "b"]})
        value, trace, _ = self.norm(xml)
        self.assertEqual(value["command_line"], ["a", "b"])
        self.assertEqual(trace["command_line"]["state"], "multivalue")

    def test_hunt_conflict_is_unknown_not_false(self):
        from handlers.hunt_definition import evaluate

        event, mapping, _ = normalize(
            {"_raw": self.xml, "CommandLine": "review"},
            PROFILES["splunk-raw-windows-v1"],
        )
        predicate = {"field": "/command_line", "op": "contains", "value": "review"}
        result = evaluate({"not": predicate}, event, mapping)
        self.assertIsNone(result["result"])
        self.assertIn("conflict", result["children"][0]["reason"])

    def test_powershell_rule_source(self):
        xml = windows(
            "4104",
            {"ScriptBlockText": "Write-Output fixture"},
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
        )
        dataset, _ = self.ingest(xml, "xml")
        rule = self.root / "ps.yaml"
        rule.write_text(
            """title: Script fixture
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains: fixture
  condition: selection
""",
        )
        report = analyze_dump(ROOT, dataset, self.root / "ps-report", rule=rule)
        self.assertEqual(report["rules"][0]["counts"], {"match": 1})


if __name__ == "__main__":
    unittest.main()
