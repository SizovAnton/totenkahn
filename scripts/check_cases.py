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
    load_case,
    add_dataset,
    add_note,
    verify_case,
    export_case,
    case_lock,
    set_state,
)
from handlers.case_timeline import build_timeline
from handlers.evidence import import_dump, file_hash
from handlers.evidence_selection import create_selection


class CaseTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-case-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.case = self.root / "case"
        create_case(self.case, "Synthetic investigation")
        self.dataset = self.root / "dataset"
        self.source = self.root / "events.jsonl"
        self.events = [
            self.event("2026-11-18T11:00:00Z", "later"),
            self.event("2026-11-18T10:00:00Z", "earlier"),
        ]

    def event(self, timestamp, command):
        return {
            "timestamp": timestamp,
            "host": "host-a",
            "event_id": "process",
            "command_line": command,
            "process_id": "123",
            "user": "analyst",
        }

    def attach(self, events=None, **kwargs):
        self.source.write_text(
            "\n".join((json.dumps(e) for e in (events if events is not None else self.events))),
        )
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")

        return add_dataset(self.case, self.dataset, **kwargs)

    def timeline(self, **kwargs):
        output = self.root / ("timeline-" + str(len(list(self.root.glob("timeline-*")))))
        report = build_timeline(self.case, output, **kwargs)
        rows = (
            [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
            if (output / "events.jsonl").exists()
            else []
        )

        return (report, rows, output)

    def test_create_refuses_overwrite_and_empty_title(self):
        with self.assertRaises(FileExistsError):
            create_case(self.case, "overwrite")

        with self.assertRaises(ValueError):
            create_case(self.root / "empty", "")

        self.assertEqual(load_case(self.case)["history"][0]["action"], "created")

    def test_attach_is_self_contained_and_keeps_originals_unchanged(self):
        attachment = self.attach()
        original_hash = file_hash(self.dataset / "index.sqlite")
        self.assertEqual(verify_case(self.case)["events"], 2)
        self.assertEqual(original_hash, file_hash(self.dataset / "index.sqlite"))
        shutil.rmtree(self.dataset)
        self.source.unlink()
        self.assertEqual(verify_case(self.case)["status"], "passed")
        self.assertEqual(attachment["count"], 2)

    def test_saved_selection_controls_membership(self):
        self.source.write_text("\n".join((json.dumps(e) for e in self.events)))
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        selection = self.root / "selection"
        create_selection(self.dataset, selection, {"rows": [2]})
        attachment = add_dataset(self.case, self.dataset, selection)
        report, rows, _ = self.timeline()
        self.assertEqual(report["events"], 1)
        self.assertEqual(rows[0]["row_id"], 2)

        with self.assertRaisesRegex(ValueError, "outside"):
            add_note(self.case, "bad", "analyst", attachment["id"], 1)

    def test_duplicate_attachment_rejected(self):
        self.attach()

        with self.assertRaisesRegex(ValueError, "already attached"):
            add_dataset(self.case, self.dataset)

        self.assertEqual(len(load_case(self.case)["attachments"]), 1)
        self.assertFalse(list(self.case.glob(".pending-*")))

    def test_case_and_event_notes_separated_from_observations(self):
        attachment = self.attach()
        note = add_note(
            self.case, "Working hypothesis", "Engineer", attachment["id"], 2, ["review"]
        )
        add_note(self.case, "Case note", "Engineer")
        report, rows, _ = self.timeline()
        self.assertEqual(report["events"], 2)
        self.assertEqual(rows[0]["notes"][0]["id"], note["id"])
        self.assertEqual(rows[1]["notes"], [])
        self.assertEqual(len(load_case(self.case)["history"]), 4)
        self.assertEqual(note["kind"], "analyst_annotation_not_observed_event")

    def test_invalid_note_target(self):
        with self.assertRaises(ValueError):
            add_note(self.case, "note", "author", "missing", 1)

        with self.assertRaises(ValueError):
            add_note(self.case, "note", "author", row=1)

        with self.assertRaises(ValueError):
            add_note(self.case, "", "author")

    def test_timeline_sorts_utc_not_input_order(self):
        self.attach()
        report, rows, _ = self.timeline()
        self.assertEqual(report["status"], "passed")
        self.assertEqual([r["row_id"] for r in rows], [2, 1])
        self.assertEqual(rows[0]["locator"], {"line": 2})
        self.assertEqual(rows[0]["source"]["ordinal"], 2)

    def test_multi_dataset_duplicates_retained_and_ties_stable(self):
        self.attach()
        other = self.root / "other"
        import_dump(ROOT, self.source, other, profile="generic-v1")
        add_dataset(self.case, other)
        report, rows, _ = self.timeline()
        self.assertEqual(report["events"], 4)
        self.assertEqual(len({r["event_id"] for r in rows}), 2)
        self.assertEqual(len({(r["attachment"], r["row_id"]) for r in rows}), 4)
        self.assertLessEqual(rows[0]["attachment"], rows[1]["attachment"])

    def test_unknown_time_kept_separately(self):
        self.attach([self.event(None, "unknown"), self.events[0]])
        report, rows, _ = self.timeline()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(report["unknown_time"], 1)
        self.assertEqual(rows[-1]["time_status"], "unknown")
        self.assertIsNone(rows[-1]["time_utc"])

    def test_filters_and_unknown_exclusion_explicit(self):
        self.attach([self.event(None, "unknown"), *self.events])
        report, rows, _ = self.timeline(
            filters={
                "start": "2026-11-18T10:30:00Z",
                "host": "host-a",
                "user": "analyst",
                "process_id": "123",
            },
        )
        self.assertEqual(report["events"], 1)
        self.assertEqual(report["excluded"], 2)
        self.assertEqual(rows[0]["event"]["command_line"], "later")

        with self.assertRaises(ValueError):
            self.timeline(filters={"start": "2026-11-18"})

    def test_empty_case_not_successful_analysis(self):
        report, rows, _ = self.timeline()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(rows, [])

    def test_manifest_tamper_detected(self):
        path = self.case / "case.json"
        value = json.loads(path.read_text())
        value["title"] = "changed"
        path.write_text(json.dumps(value))

        with self.assertRaisesRegex(ValueError, "manifest changed"):
            verify_case(self.case)

    def test_original_tamper_detected(self):
        attachment = self.attach()
        dataset = self.case / attachment["directory"] / "dataset"
        manifest = json.loads((dataset / "manifest.json").read_text())
        (dataset / manifest["files"][0]["stored"]).write_text("tampered")

        with self.assertRaises(ValueError):
            verify_case(self.case)

    def test_lock_prevents_second_writer(self):
        with case_lock(self.case):
            with self.assertRaisesRegex(ValueError, "busy"):
                add_note(self.case, "note", "author")

        self.assertFalse((self.case / ".case.lock").exists())

    def test_failed_copy_does_not_register_evidence(self):
        self.source.write_text(json.dumps(self.events[0]))
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")

        with patch("handlers.case_store.copy_checked", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                add_dataset(self.case, self.dataset)

        self.assertEqual(load_case(self.case)["attachments"], [])
        self.assertFalse(list(self.case.glob(".pending-*")))
        self.assertFalse((self.case / ".case.lock").exists())

    def test_export_relocation_and_verify(self):
        self.attach()
        add_note(self.case, "reviewed", "analyst")
        archive = self.root / "export.zip"
        self.assertEqual(export_case(self.case, archive)["status"], "passed")
        moved = self.root / "moved"

        with ZipFile(archive) as zipfile:
            zipfile.extractall(moved)

        shutil.rmtree(self.case)
        shutil.rmtree(self.dataset)
        self.assertEqual(verify_case(moved)["events"], 2)
        self.assertEqual(len(load_case(moved)["notes"]), 1)

        with self.assertRaises(FileExistsError):
            export_case(moved, archive)

    def test_html_escape_and_pagination(self):
        self.attach([self.event("2026-11-18T10:00:00Z", "<script>alert(1)</script>")] * 101)
        report, _, output = self.timeline()
        self.assertEqual(len(report["pages"]), 2)
        html = (output / "events-0001.html").read_text()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_publication_failure_does_not_leave_registered_or_orphan_evidence(self):
        self.source.write_text(json.dumps(self.events[0]))
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")

        with patch("handlers.case_store.save_case", side_effect=OSError("publication failed")):
            with self.assertRaises(OSError):
                add_dataset(self.case, self.dataset)

        self.assertEqual(load_case(self.case)["attachments"], [])
        self.assertEqual(list((self.case / "evidence").glob("*")), [])

    def test_note_accepts_unique_label(self):
        attachment = self.attach(label="workstation")
        note = add_note(self.case, "reviewed row", "analyst", "workstation", 1)
        self.assertEqual(note["attachment"], attachment["id"])

    def test_partial_dataset_preserves_limitation(self):
        self.source.write_text(json.dumps(self.events[0]) + """
invalid""")
        import_dump(ROOT, self.source, self.dataset, profile="generic-v1")
        add_dataset(self.case, self.dataset)
        report, rows, _ = self.timeline()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(len(rows), 1)
        self.assertEqual(report["limitations"][0]["dataset_status"], "partial")

    def test_output_cannot_be_nested_in_case(self):
        with self.assertRaises(ValueError):
            build_timeline(self.case, self.case / "report")

        with self.assertRaises(ValueError):
            export_case(self.case, self.case / "export.zip")

    def test_close_reopen_and_readonly_timeline(self):
        self.attach()
        set_state(self.case, "closed", "analyst", "Review completed")

        with self.assertRaisesRegex(ValueError, "closed"):
            add_note(self.case, "late edit", "analyst")

        report, _, _ = self.timeline()
        self.assertEqual(report["status"], "passed")
        set_state(self.case, "open", "analyst", "New evidence received")
        add_note(self.case, "follow-up", "analyst")
        self.assertEqual(load_case(self.case)["state"], "open")

    def test_cli_without_bootstrap(self):
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "main.py"), "case", "show", str(self.case), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["case"]["title"], "Synthetic investigation")


if __name__ == "__main__":
    unittest.main()
