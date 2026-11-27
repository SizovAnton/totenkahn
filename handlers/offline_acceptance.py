import csv
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4
import zipfile
from reporting.offline_report import save_html, explain_check, INPUTS, LIMITS

STAGES = [
    (
        "01-import",
        "1. Dump import and provenance",
        ["formats", "normalization", "malformed", "integrity"],
    ),
    (
        "02-sigma",
        "2. Sigma analysis and explanation",
        ["decisions", "trace", "selection", "compound"],
    ),
    (
        "03-case",
        "3. Case, timeline and IR evidence",
        ["timeline", "notes", "export", "multi_source"],
    ),
    ("04-hunt", "4. Threat Hunting and scope", ["decisions", "scope", "trace", "multi_host"]),
    (
        "05-regression",
        "5. Findings and regression",
        ["positive", "negative", "insufficient", "hunt_to_ci"],
    ),
]


PURPOSES = {
    "01-import": (
        "File → hash → stored original → normalization → index",
        {
            "formats": "Import eight format variants: preserve three records each and verify evidence integrity.",
            "normalization": "Verify time, host, user, PID and commands across seven generic formats; preserve CSV/TSV empty cells versus absent JSON fields. XML has a different contract.",
            "malformed": "Retain three valid records and reject exactly one malformed row; PARTIAL is expected.",
            "integrity": "Detect an altered original in a controlled copy; FAILED is expected only for that cause.",
        },
    ),
    "02-sigma": (
        "Original → mapping → field check → block → condition → decision",
        {
            "decisions": "Distinguish MATCH, NO MATCH and INSUFFICIENT DATA; one event of each kind.",
            "trace": "Verify field presence, contains result, block, condition, source row and original hash.",
            "selection": "Analyze only the selected first record; expect exactly one match.",
            "compound": "Evaluate selection AND NOT filter on two hosts: match, ordinary no-match, excluded match and missing field.",
        },
    ),
    "03-case": (
        "Attachments → timeline → analyst note → portable evidence export",
        {
            "timeline": "Order three events and retain their original source hashes and locators.",
            "notes": "Keep the analyst note separate from observed events and verify case integrity.",
            "export": "Extract the exported case into a new directory and verify its evidence after relocation.",
            "multi_source": "Merge two attachments, preserve an unknown timestamp, filter by host and retain a row-specific note.",
        },
    ),
    "04-hunt": (
        "Case → search scope → AND/NOT hypothesis → decision → source record",
        {
            "decisions": "One match, one no-match and one unknown outcome; NOT must not turn missing data into fact.",
            "scope": "Select the matching host evidence while retaining the incomplete-scope warning.",
            "trace": "Verify true/false/unknown results against original rows and source hashes.",
            "multi_host": "Evaluate two hosts and two users with an excluded command; scope must not claim other-host matches.",
        },
    ),
    "05-regression": (
        "Reviewed hunt result → finding → explicit expectation → suite → CI",
        {
            "positive": "Both explicit expectations must hold with no regression or insufficient data.",
            "negative": "A deliberately changed candidate must fail CI with exactly one regression.",
            "insufficient": "Missing data cannot satisfy a no-match expectation; CI must reject it.",
            "hunt_to_ci": "Review a hunt result into a finding, verify the exported evidence bundle, then evaluate the explicit expectation in CI.",
        },
    ),
}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fixture_files(folder):
    folder.mkdir()
    rows = [
        {
            "timestamp": "2026-11-19T10:00:00Z",
            "host": "synthetic-host",
            "user": "demo",
            "event_id": "process-start",
            "process_id": "100",
            "command_line": "example.exe --review",
        },
        {
            "timestamp": "2026-11-19T10:01:00Z",
            "host": "synthetic-host",
            "user": "demo",
            "event_id": "process-start",
            "process_id": "101",
            "command_line": "example.exe --benign",
        },
        {
            "timestamp": "2026-11-19T10:02:00Z",
            "host": "synthetic-host",
            "user": "demo",
            "event_id": "process-start",
            "process_id": "102",
        },
    ]
    line_bytes = ("\n".join(json.dumps(row) for row in rows) + "\n").encode("utf-8")
    (folder / "events.jsonl").write_bytes(line_bytes)
    write_json(folder / "events.json", rows)

    for suffix, delimiter in [("csv", ","), ("tsv", "\t")]:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter=delimiter)
        writer.writeheader()
        writer.writerows(rows)
        (folder / ("events." + suffix)).write_bytes(stream.getvalue().encode("utf-8"))

    for suffix in ("jsonl", "csv", "tsv"):
        (folder / ("events." + suffix + ".gz")).write_bytes(
            gzip.compress((folder / ("events." + suffix)).read_bytes(), mtime=0)
        )

    (folder / "malformed.jsonl").write_bytes(line_bytes + b"{ invalid json\n")
    xml = (
        "<Events>"
        + "".join(
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID><TimeCreated SystemTime="'
            + row["timestamp"]
            + '"/><EventRecordID>'
            + str(i + 1)
            + '</EventRecordID><Channel>Security</Channel><Computer>synthetic-host</Computer></System><EventData><Data Name="NewProcessName">example.exe</Data></EventData></Event>'
            for i, row in enumerate(rows)
        )
        + "</Events>"
    )
    (folder / "events.xml").write_text(xml, encoding="utf-8")
    rule = "title: Offline acceptance marker\nlogsource:\n  product: windows\n  service: totenkahn-demo\ndetection:\n  selection:\n    CommandLine|contains: '--review'\n  condition: selection\n"

    for name in ("baseline.yaml", "candidate.yaml"):
        (folder / name).write_text(rule, encoding="utf-8")

    (folder / "regressed.yaml").write_text(
        rule.replace("--review", "--wrong-marker"), encoding="utf-8"
    )
    write_json(
        folder / "mapping.json",
        {
            "schema_version": 1,
            "id": "offline-fixture",
            "logsource": {"product": "windows", "service": "totenkahn-demo"},
            "fields": {"CommandLine": "/command_line"},
        },
    )
    write_json(
        folder / "hunt.json",
        {
            "schema_version": 1,
            "hypothesis": "Synthetic reviewed command is present",
            "scope": {"field": "/event_id", "op": "equals", "value": "process-start"},
            "condition": {
                "all": [
                    {"field": "/command_line", "op": "contains", "value": "--review"},
                    {"not": {"field": "/command_line", "op": "contains", "value": "--excluded"}},
                ]
            },
        },
    )

    investigation = [
        dict(rows[0], host="lab-a", user="alice", process_id="200"),
        dict(rows[1], host="lab-b", user="bob", process_id="200"),
        dict(
            rows[0],
            timestamp="2026-11-19T10:02:00Z",
            host="lab-b",
            user="bob",
            process_id="201",
            command_line="example.exe --review --excluded",
        ),
        dict(
            rows[2], timestamp="2026-11-19T10:03:00Z", host="lab-a", user="alice", process_id="201"
        ),
    ]
    secondary = [
        dict(
            rows[0], timestamp="2026-11-19T10:00:30Z", host="lab-a", user="alice", process_id="202"
        ),
        {
            "host": "lab-b",
            "user": "bob",
            "event_id": "process-start",
            "process_id": "202",
            "command_line": "example.exe --benign",
        },
    ]

    for name, records in [("investigation.jsonl", investigation), ("secondary.jsonl", secondary)]:
        (folder / name).write_bytes(
            ("\n".join(json.dumps(row) for row in records) + "\n").encode("utf-8")
        )

    (folder / "compound.yaml").write_text(
        rule.replace(
            "  condition: selection",
            "  filter:\n    CommandLine|contains: '--excluded'\n  condition: selection and not filter",
        ),
        encoding="utf-8",
    )


class OfflineAcceptance:

    def __init__(self, project, output, command=None, stages=None):
        self.selected_stages = set(stages or range(1, 6))

        if not self.selected_stages <= set(range(1, 6)):
            raise ValueError("Stages must be 1 through 5")

        self.project = Path(project).resolve()
        self.output = Path(output).resolve()
        self.command = command or (
            [sys.executable]
            if getattr(sys, "frozen", False)
            else [sys.executable, "-B", str(self.project / "main.py")]
        )
        self.environment = dict(
            os.environ,
            TOTENKAHN_HOME=str(self.output / "isolated-data"),
            PYTHONIOENCODING="utf-8",
            PYTHONUTF8="1",
            NO_COLOR="1",
        )
        self.report = {
            "schema_version": 2,
            "status": "running",
            "scope": "five_stage_synthetic_offline_acceptance",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": str(self.output),
            "selected_stages": sorted(self.selected_stages),
            "atomic_tests_executed": 0,
            "external_services_used": [],
            "host_configuration_changes": False,
            "limitations": [
                "Synthetic fixtures only; no real SIEM/EDR compatibility certification",
                "No live collection, Atomic execution, endpoint response, EVTX adapter or external service connection",
                "Expected negative controls are successful only when the precise failure is detected",
            ],
            "stages": [],
        }
        self.stage = {}
        self.folder = self.output
        self.sequence = 0

    def save(self):
        temporary = self.output / "report.json.tmp"
        write_json(temporary, self.report)
        os.replace(temporary, self.output / "report.json")
        save_html(self.output, self.report)

    def cli(self, *arguments, allowed=(0,)):
        self.sequence += 1
        stem = f"{self.sequence:03d}-" + "-".join(str(x) for x in arguments[:2])
        stdout, stderr = self.folder / (stem + ".stdout.txt"), self.folder / (stem + ".stderr.txt")
        command = self.command + [str(x) for x in arguments]

        if arguments[0] not in {"dump", "case", "hunt", "finding", "ci"}:
            raise ValueError("Offline acceptance only permits evidence commands")

        entry = {
            "command": command,
            "stdout": stdout.relative_to(self.output).as_posix(),
            "stderr": stderr.relative_to(self.output).as_posix(),
            "expected_exit_codes": list(allowed),
        }
        self.stage["commands"].append(entry)

        with stdout.open("wb") as out, stderr.open("wb") as err:
            result = subprocess.run(
                command,
                cwd=self.project,
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                timeout=180,
                check=False,
            )

        entry["exit_code"] = result.returncode

        if result.returncode not in allowed:
            reason = "No structured failure reason returned"
            try:
                payload = read_json(stdout)
                if isinstance(payload, dict) and payload.get("reason"):
                    reason = str(payload["reason"])
            except (OSError, ValueError):
                pass
            raise RuntimeError(
                f"Command failed ({result.returncode}): {arguments[:2]}; {reason}; "
                f"see {stdout.name} and {stderr.name}"
            )

        return read_json(stdout)

    def check(self, name, expected, observed, *evidence, stories=None):
        for path in evidence:
            if not Path(path).is_file():
                raise ValueError("Missing acceptance evidence: " + str(path))

        item = next(c for c in self.stage["checks"] if c["name"] == name)
        item.update(
            status="passed" if observed == expected else "failed",
            expected=expected,
            observed=observed,
            evidence=[Path(path).relative_to(self.output).as_posix() for path in evidence],
            stories=stories or [],
            explanation=explain_check(name, observed, observed == expected),
        )
        self.save()

    def dataset(self, name="dataset", source="events.jsonl"):
        path = self.folder / name
        args = ["dump", "import", self.output / "fixtures" / source, "--output-dir", path, "--json"]

        if not source.endswith(".xml"):
            args += ["--profile", "generic-v1"]

        self.cli(*args)

        return path

    def case(self):
        dataset = self.dataset()
        case = self.folder / "case"
        self.cli(
            "case", "create", "--title", "Synthetic offline case", "--output-dir", case, "--json"
        )
        self.cli("case", "add", case, "--dataset", dataset, "--label", "fixture", "--json")

        return case

    def stage_import(self):
        observations = {}

        for suffix in ("json", "jsonl", "csv", "tsv", "jsonl.gz", "csv.gz", "tsv.gz", "xml"):
            path = self.dataset("format-" + suffix.replace(".", "-"), "events." + suffix)
            manifest = read_json(path / "manifest.json")
            verified = self.cli("dump", "verify", path, "--json")
            observations[suffix] = {
                "accepted": manifest["counts"]["accepted"],
                "rejected": manifest["counts"]["rejected"],
                "integrity": verified["status"],
            }

        self.check(
            "formats",
            {
                k: {"accepted": 3, "rejected": 0, "integrity": "passed"}
                for k in ("json", "jsonl", "csv", "tsv", "jsonl.gz", "csv.gz", "tsv.gz", "xml")
            },
            observations,
            *sorted(self.folder.glob("format-*/manifest.json")),
        )
        from handlers.evidence import read_index

        normalized = {}
        fields = ("time_utc", "host", "user", "process_id", "command_line")

        for suffix in ("json", "jsonl", "csv", "tsv", "jsonl.gz", "csv.gz", "tsv.gz"):
            connection, _ = read_index(self.folder / ("format-" + suffix.replace(".", "-")))

            try:
                normalized[suffix] = [
                    {key: json.loads(r[0]).get(key) for key in fields}
                    for r in connection.execute("SELECT normalized FROM events ORDER BY row_id")
                ]
            finally:
                connection.close()

        expected_rows = [
            {
                "time_utc": f"2026-11-19T10:0{i}:00.000000+00:00",
                "host": "synthetic-host",
                "user": "demo",
                "process_id": str(100 + i),
                "command_line": command,
            }
            for i, command in enumerate(("example.exe --review", "example.exe --benign", None))
        ]
        expected_normalized = {
            key: [
                dict(
                    row,
                    command_line=(
                        "" if key.startswith(("csv", "tsv")) and i == 2 else row["command_line"]
                    ),
                )
                for i, row in enumerate(expected_rows)
            ]
            for key in normalized
        }
        self.check(
            "normalization",
            expected_normalized,
            normalized,
            *sorted(self.folder.glob("format-*/report.html")),
        )
        damaged = self.folder / "malformed"
        self.cli(
            "dump",
            "import",
            self.output / "fixtures/malformed.jsonl",
            "--profile",
            "generic-v1",
            "--output-dir",
            damaged,
            "--json",
            allowed=(2, 3),
        )
        manifest = read_json(damaged / "manifest.json")
        self.check(
            "malformed",
            {"status": "partial", "accepted": 3, "rejected": 1},
            {
                "status": manifest["status"],
                "accepted": manifest["counts"]["accepted"],
                "rejected": manifest["counts"]["rejected"],
            },
            damaged / "manifest.json",
        )
        changed = self.folder / "tampered-copy"
        shutil.copytree(self.folder / "format-jsonl", changed)
        manifest = read_json(changed / "manifest.json")
        (changed / manifest["files"][0]["stored"]).write_bytes(b"controlled tampering\n")
        verified = self.cli("dump", "verify", changed, "--json", allowed=(2,))
        self.check(
            "integrity",
            {"status": "failed", "original_changed": True},
            {
                "status": verified["status"],
                "original_changed": any(
                    i["reason"] == "Original missing or changed" for i in verified["issues"]
                ),
            },
            self.folder / (f"{self.sequence:03d}-dump-verify.stdout.txt"),
        )

    def stage_sigma(self):
        dataset = self.dataset()
        result = self.folder / "analysis"
        fixtures = self.output / "fixtures"
        self.cli(
            "dump",
            "analyze",
            dataset,
            "--rule",
            fixtures / "baseline.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            result,
            "--json",
            allowed=(3,),
        )
        report = read_json(result / "report.json")
        self.check(
            "decisions",
            {"match": 1, "no_match": 1, "insufficient_data": 1},
            report["rules"][0]["counts"],
            result / "report.json",
            result / "report.html",
        )
        event_files = list(result.rglob("events.jsonl"))
        records = [
            json.loads(line)
            for path in event_files
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        traces = []

        for row in records:
            engine = row["engine_evaluation"]
            check = engine["Checks"]["selection"]["CommandLine|contains"]
            traces.append(
                {
                    "line": row["locator"]["line"],
                    "field_present": check["Field Present"],
                    "matched": check["Matched"],
                    "block": engine["Block Results"]["selection"],
                    "condition": engine["Condition"],
                    "decision": row["status"],
                    "mapping": row["compatibility"]["fields"]["CommandLine"]["path"],
                    "source_hash": row["source"]["sha256"]
                    == self.report["fixture_sha256"]["events.jsonl"],
                }
            )

        expected = [
            {
                "line": i,
                "field_present": i != 3,
                "matched": i == 1,
                "block": i == 1,
                "condition": "selection",
                "decision": decision,
                "mapping": "/command_line",
                "source_hash": True,
            }
            for i, decision in enumerate(("match", "no_match", "insufficient_data"), 1)
        ]
        self.check(
            "trace",
            expected,
            traces,
            *event_files,
            result / "rule-0001/events-0001.html",
            stories=self.sigma_stories(records),
        )
        selection = self.folder / "selection"
        self.cli("dump", "select", dataset, "--row", "1", "--output-dir", selection, "--json")
        selected = self.folder / "selected-analysis"
        self.cli(
            "dump",
            "analyze",
            dataset,
            "--selection",
            selection,
            "--rule",
            fixtures / "baseline.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            selected,
            "--json",
        )
        self.check(
            "selection",
            {"match": 1},
            read_json(selected / "report.json")["rules"][0]["counts"],
            selected / "report.json",
        )

        dataset = self.dataset("investigation", "investigation.jsonl")
        result = self.folder / "compound-analysis"
        self.cli(
            "dump",
            "analyze",
            dataset,
            "--rule",
            fixtures / "compound.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            result,
            "--json",
            allowed=(3,),
        )
        records = self.event_rows(result / "rule-0001/events.jsonl")
        observed = [
            {
                "row": r["locator"]["line"],
                "decision": r["status"],
                "blocks": r["engine_evaluation"]["Block Results"],
            }
            for r in records
        ]
        expected = [
            {"row": i, "decision": d, "blocks": {"selection": sel, "filter": filt}}
            for i, d, sel, filt in [
                (1, "match", True, False),
                (2, "no_match", False, False),
                (3, "no_match", True, True),
                (4, "insufficient_data", False, False),
            ]
        ]
        self.check(
            "compound",
            expected,
            observed,
            result / "report.html",
            result / "rule-0001/events.jsonl",
            result / "rule-0001/events-0001.html",
            fixtures / "compound.yaml",
            stories=self.sigma_stories(records),
        )

    @staticmethod
    def event_rows(path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    @staticmethod
    def sigma_stories(records):
        stories = []

        for row in records:
            engine = row["engine_evaluation"]
            chain = [
                f"Source SHA-256: {row['source']['sha256']}; row {row['locator']['line']}",
                "Mapping: command_line → CommandLine (explicit fixture mapping)",
            ]

            for block, checks in engine["Checks"].items():
                for name, check in checks.items():
                    chain.append(
                        f"{block}: {name}; field present={check.get('Field Present')}; actual={check.get('Actual')!r}; expected={check.get('Expected')!r}; matched={check.get('Matched')}"
                    )

                chain.append(f"Block {block}: {engine['Block Results'].get(block)}")

            chain.extend(
                [
                    f"Condition: {engine['Condition']}; recorded result: {engine['Selection']}",
                    f"Evidence decision: {row['status']}",
                ]
            )

            if row["status"] == "insufficient_data":
                explanation = "The required field is missing. Provisional false field checks do not establish NO MATCH; the evidence decision remains INSUFFICIENT DATA."
            else:
                explanation = (
                    "The decision follows the recorded field checks and the complete condition below. A true selection can still be excluded by NOT filter."
                    if "filter" in engine["Block Results"]
                    else "The recorded contains check feeds selection, which is the complete rule condition. Its result determines MATCH or NO MATCH."
                )

            if row["status"] != "insufficient_data":
                parts = []

                for block, checks in engine["Checks"].items():
                    for check in checks.values():
                        parts.append(
                            f"{check['Field']} is present: {check['Actual']!r}. Contains {check['Expected']!r}: {check['Matched']}. Block {block}: {engine['Block Results'][block]}."
                        )

                explanation = (
                    " ".join(parts)
                    + f" Condition {engine['Condition']!r}: {engine['Selection']}. Decision: {row['status']}."
                )

            stories.append(
                {
                    "title": f"Event row {row['locator']['line']}: {row['status']}",
                    "explanation": explanation,
                    "chain": chain,
                }
            )

        return stories

    def stage_case(self):
        case = self.case()
        self.cli(
            "case",
            "note",
            case,
            "--author",
            "fixture-engineer",
            "--text",
            "Synthetic analyst note; not an observed event",
            "--json",
        )
        timeline = self.folder / "timeline"
        self.cli("case", "timeline", case, "--output-dir", timeline, "--json")
        rows = [
            json.loads(line)
            for line in (timeline / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        observed = {
            "events": len(rows),
            "ordered": [r["time_utc"] for r in rows] == sorted(r["time_utc"] for r in rows),
            "provenance": all(r.get("source", {}).get("sha256") and r.get("locator") for r in rows),
        }
        self.check(
            "timeline",
            {"events": 3, "ordered": True, "provenance": True},
            observed,
            timeline / "report.json",
            timeline / "report.html",
            timeline / "events.jsonl",
        )
        saved = read_json(case / "case.json")
        verified = self.cli("case", "verify", case, "--json")
        self.check(
            "notes",
            {"notes": 1, "integrity": "passed"},
            {"notes": len(saved["notes"]), "integrity": verified["status"]},
            case / "case.json",
        )
        exported = self.folder / "case-export.zip"
        self.cli("case", "export", case, "--output", exported, "--json")

        with zipfile.ZipFile(exported) as archive:
            good = archive.testzip() is None and any(
                n.endswith("case.json") for n in archive.namelist()
            )
            restored = self.folder / "relocated"
            archive.extractall(restored)

        manifest = next(restored.rglob("case.json"))
        verification = self.cli("case", "verify", manifest.parent, "--json")
        self.check(
            "export",
            {"archive_valid": True, "relocated_integrity": "passed"},
            {"archive_valid": good, "relocated_integrity": verification["status"]},
            exported,
            self.folder / f"{self.sequence:03d}-case-verify.stdout.txt",
        )
        case = self.investigation_case()
        self.cli(
            "case",
            "note",
            case,
            "--author",
            "fixture-engineer",
            "--text",
            "Review marker observed; not a compromise verdict",
            "--attachment",
            "primary",
            "--row",
            "1",
            "--json",
        )
        timeline = self.folder / "multi-timeline"
        self.cli("case", "timeline", case, "--output-dir", timeline, "--json", allowed=(3,))
        rows = self.event_rows(timeline / "events.jsonl")
        filtered = self.folder / "host-timeline"
        self.cli("case", "timeline", case, "--host", "lab-a", "--output-dir", filtered, "--json")
        host_rows = self.event_rows(filtered / "events.jsonl")
        observed = {
            "events": len(rows),
            "unknown_time": sum(r["time_utc"] is None for r in rows),
            "attachments": sorted({r["attachment_label"] for r in rows}),
            "host_events": len(host_rows),
            "hosts": sorted({r["event"]["host"] for r in host_rows}),
            "row_notes": sum(len(r["notes"]) for r in rows),
            "ordered_known_times": [r["time_utc"] for r in rows if r["time_utc"]]
            == sorted(r["time_utc"] for r in rows if r["time_utc"]),
            "source_hashes": all(
                r["source"]["sha256"]
                == self.report["fixture_sha256"][
                    (
                        "investigation.jsonl"
                        if r["attachment_label"] == "primary"
                        else "secondary.jsonl"
                    )
                ]
                for r in rows
            ),
        }
        stories = [
            {
                "title": f"{r['attachment_label']} / row {r['row_id']}",
                "explanation": "Time order is recorded evidence, not a causal relationship. Unknown timestamps remain unknown; notes are analyst statements.",
                "chain": [
                    f"Source SHA-256: {r['source']['sha256']}",
                    f"Locator: {r['locator']}",
                    f"Time: {r['time_utc']}",
                    f"Host: {r['event']['host']}; user: {r['event']['user']}; PID: {r['event']['process_id']}",
                    f"Analyst notes: {len(r['notes'])}",
                ],
            }
            for r in rows
        ]
        self.check(
            "multi_source",
            {
                "events": 6,
                "unknown_time": 1,
                "attachments": ["primary", "secondary"],
                "host_events": 3,
                "hosts": ["lab-a"],
                "row_notes": 1,
                "ordered_known_times": True,
                "source_hashes": True,
            },
            observed,
            timeline / "report.html",
            timeline / "events.jsonl",
            filtered / "report.html",
            stories=stories,
        )

    def investigation_case(self):
        case = self.folder / "investigation-case"
        self.cli(
            "case",
            "create",
            "--title",
            "Two-host synthetic investigation",
            "--output-dir",
            case,
            "--json",
        )

        for label, filename in [
            ("primary", "investigation.jsonl"),
            ("secondary", "secondary.jsonl"),
        ]:
            dataset = self.dataset(label, filename)
            self.cli("case", "add", case, "--dataset", dataset, "--label", label, "--json")

        return case

    def stage_hunt(self):
        case = self.case()
        self.cli(
            "hunt",
            "define",
            case,
            "--name",
            "review",
            "--author",
            "fixture-engineer",
            "--spec",
            self.output / "fixtures/hunt.json",
            "--json",
        )
        result = self.folder / "hunt"
        self.cli(
            "hunt", "run", case, "--name", "review", "--output-dir", result, "--json", allowed=(3,)
        )
        report = read_json(result / "report.json")
        self.check(
            "decisions",
            {"match": 1, "no_match": 1, "insufficient_data": 1},
            report["counts"],
            result / "report.json",
            result / "report.html",
        )
        scoped = self.cli(
            "hunt", "scope", result, "--by", "host", "--value", "synthetic-host", "--json"
        )
        self.check(
            "scope",
            {"status": "passed", "matching_rows": [1], "scope_status": "incomplete"},
            {
                "status": scoped["status"],
                "matching_rows": [i["row_id"] for i in scoped["items"]],
                "scope_status": scoped["scope_status"],
            },
            self.folder / (f"{self.sequence:03d}-hunt-scope.stdout.txt"),
        )
        rows = [
            json.loads(line)
            for line in (result / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.check(
            "trace",
            {"results": [True, False, None], "lines": [1, 2, 3], "source_hashes": True},
            {
                "results": [row["evaluation"]["result"] for row in rows],
                "lines": [row["locator"]["line"] for row in rows],
                "source_hashes": all(
                    row["source"]["sha256"] == self.report["fixture_sha256"]["events.jsonl"]
                    for row in rows
                ),
            },
            result / "events.jsonl",
        )

        case = self.investigation_case()
        result = self.folder / "multi-hunt"
        self.cli(
            "hunt",
            "define",
            case,
            "--name",
            "review",
            "--author",
            "fixture-engineer",
            "--spec",
            self.output / "fixtures/hunt.json",
            "--json",
        )
        self.cli(
            "hunt", "run", case, "--name", "review", "--output-dir", result, "--json", allowed=(3,)
        )
        report = read_json(result / "report.json")
        scoped = self.cli("hunt", "scope", result, "--by", "host", "--value", "lab-b", "--json")
        rows = self.event_rows(result / "events.jsonl")
        stories = [
            {
                "title": f"Hunt result {r['result_id']}: {r['decision']}",
                "explanation": "AND and NOT use the recorded predicates; an unknown operand is not a confirmed negative. The detailed event report contains every predicate.",
                "chain": [
                    f"Source SHA-256: {r['source']['sha256']}; locator: {r['locator']}",
                    (
                        f"Scope result: {r['scope_evaluation']['result']}"
                        if "scope_evaluation" in r
                        else "Scope: process-start events"
                    ),
                    f"Host: {r['event']['host']}; user: {r['event']['user']}",
                ]
                + self.predicate_chain(r["evaluation"])
                + [f"Evidence decision: {r['decision']}"],
            }
            for r in rows
        ]
        self.check(
            "multi_host",
            {
                "counts": {"match": 2, "no_match": 3, "insufficient_data": 1},
                "lab_b_matches": 0,
                "scope_status": "incomplete",
            },
            {
                "counts": report["counts"],
                "lab_b_matches": len(scoped["items"]),
                "scope_status": scoped["scope_status"],
            },
            result / "report.html",
            result / "events-0001.html",
            result / "events.jsonl",
            stories=stories,
        )

    @staticmethod
    def predicate_chain(node):
        if "field" in node:
            return [
                f"{node['field']}: present={node.get('present')}; value={node.get('actual')!r}; {node['op']} {node.get('expected')!r} → {node['result']}"
            ]

        chain = []

        for child in node.get("children", []):
            chain.extend(OfflineAcceptance.predicate_chain(child))

        chain.append(f"{node.get('operator', 'scope')}: {node['result']} (three-valued evaluation)")

        return chain

    def stage_regression(self):
        case = self.case()
        fixtures = self.output / "fixtures"

        for name, row, expected in [
            ("positive", 1, "match"),
            ("negative", 2, "no-match"),
            ("missing", 3, "no-match"),
        ]:
            self.cli(
                "finding",
                "add",
                case,
                "--name",
                name,
                "--title",
                name,
                "--author",
                "fixture-engineer",
                "--reason",
                "Explicit synthetic expectation",
                "--expect",
                expected,
                "--attachment",
                "fixture",
                "--row",
                str(row),
                "--json",
            )

        bundle = self.folder / "bundle"
        self.cli(
            "finding",
            "export",
            case,
            "--name",
            "positive",
            "--name",
            "negative",
            "--baseline",
            fixtures / "baseline.yaml",
            "--candidate",
            fixtures / "candidate.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            bundle,
            "--json",
        )
        result = self.folder / "positive-ci"
        self.cli("ci", "--config", bundle / "pipeline.json", "--output-dir", result)
        report = read_json(result / "report.json")
        self.check(
            "positive",
            {
                "status": "passed",
                "counts": {"regressed": 0, "not_met": 0, "insufficient": 0, "cases": 2},
            },
            {"status": report["status"], "counts": report["jobs"][0]["counts"]},
            result / "report.json",
            result / "report.html",
            result / "junit.xml",
        )
        config = read_json(bundle / "pipeline.json")
        config["jobs"][0].update(
            suite=str(bundle / "suite.json"),
            baseline=str(bundle / "baseline.yaml"),
            candidate=str(fixtures / "regressed.yaml"),
        )
        write_json(self.folder / "negative.json", config)
        result = self.folder / "negative-ci"
        self.cli(
            "ci", "--config", self.folder / "negative.json", "--output-dir", result, allowed=(1,)
        )
        report = read_json(result / "report.json")
        self.check(
            "negative",
            {"status": "failed", "regressed": 1},
            {"status": report["status"], "regressed": report["jobs"][0]["counts"]["regressed"]},
            result / "report.json",
            result / "report.html",
        )
        bundle = self.folder / "missing-bundle"
        self.cli(
            "finding",
            "export",
            case,
            "--name",
            "missing",
            "--baseline",
            fixtures / "baseline.yaml",
            "--candidate",
            fixtures / "candidate.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            bundle,
            "--json",
        )
        result = self.folder / "missing-ci"
        self.cli("ci", "--config", bundle / "pipeline.json", "--output-dir", result, allowed=(1,))
        report = read_json(result / "report.json")
        self.check(
            "insufficient",
            {"status": "failed", "insufficient": 1},
            {
                "status": report["status"],
                "insufficient": report["jobs"][0]["counts"]["insufficient"],
            },
            result / "report.json",
            result / "report.html",
        )

        hunt = self.folder / "reviewed-hunt"
        self.cli(
            "hunt",
            "define",
            case,
            "--name",
            "review",
            "--author",
            "fixture-engineer",
            "--spec",
            fixtures / "hunt.json",
            "--json",
        )
        self.cli(
            "hunt", "run", case, "--name", "review", "--output-dir", hunt, "--json", allowed=(3,)
        )
        finding = self.cli(
            "finding",
            "add",
            case,
            "--name",
            "reviewed-hunt",
            "--title",
            "Reviewed synthetic match",
            "--author",
            "fixture-engineer",
            "--reason",
            "Fixture analyst explicitly expects the first hunt result to match",
            "--expect",
            "match",
            "--hunt-report",
            hunt,
            "--result",
            "1",
            "--json",
        )
        bundle = self.folder / "hunt-bundle"
        self.cli(
            "finding",
            "export",
            case,
            "--name",
            "reviewed-hunt",
            "--baseline",
            fixtures / "baseline.yaml",
            "--candidate",
            fixtures / "candidate.yaml",
            "--mapping",
            fixtures / "mapping.json",
            "--output-dir",
            bundle,
            "--json",
        )
        verification = self.cli("finding", "verify-bundle", bundle, "--json")
        result = self.folder / "hunt-ci"
        self.cli("ci", "--config", bundle / "pipeline.json", "--output-dir", result)
        report = read_json(result / "report.json")
        write_json(self.folder / "reviewed-finding.json", finding)
        self.check(
            "hunt_to_ci",
            {"bundle": "passed", "ci": "passed", "cases": 1},
            {
                "bundle": verification["status"],
                "ci": report["status"],
                "cases": report["jobs"][0]["counts"]["cases"],
            },
            hunt / "events-0001.html",
            self.folder / "reviewed-finding.json",
            bundle / "suite.json",
            result / "report.html",
            result / "report.json",
            stories=[
                {
                    "title": "Reviewed hunt evidence becomes a repeatable expectation",
                    "explanation": "The fixture analyst explicitly supplied MATCH. A hunt match alone does not create an expectation or prove malicious activity.",
                    "chain": [
                        "Hunt result 1 → original fixture row 1",
                        "Analyst review → finding reviewed-hunt → expected MATCH",
                        f"Exported evidence bundle verification: {verification['status']}",
                        f"Baseline/candidate CI: {report['status']}; cases: {report['jobs'][0]['counts']['cases']}",
                    ],
                }
            ],
        )

    def run(self):
        self.output.mkdir(parents=True, exist_ok=False)
        fixture_files(self.output / "fixtures")
        self.report["fixture_sha256"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (self.output / "fixtures").iterdir()
        }

        for number, (identity, title, checks) in enumerate(STAGES, 1):
            self.report["stages"].append(
                {
                    "id": identity,
                    "name": title,
                    "status": "not_run" if number in self.selected_stages else "not_requested",
                    "chain": PURPOSES[identity][0],
                    "input_scenario": INPUTS[identity],
                    "not_tested": LIMITS[identity],
                    "checks": [
                        {"name": name, "purpose": PURPOSES[identity][1][name], "status": "not_run"}
                        for name in checks
                    ],
                    "commands": [],
                }
            )

        self.save()

        for stage, execute in zip(
            self.report["stages"],
            (
                self.stage_import,
                self.stage_sigma,
                self.stage_case,
                self.stage_hunt,
                self.stage_regression,
            ),
        ):
            if stage["status"] == "not_requested":
                continue

            self.stage = stage
            self.folder = self.output / stage["id"]
            self.folder.mkdir()
            self.sequence = 0
            stage["status"] = "running"
            print(stage["name"], file=sys.stderr, flush=True)

            try:
                execute()
                stage["status"] = (
                    "passed" if all(c["status"] == "passed" for c in stage["checks"]) else "failed"
                )
            except KeyboardInterrupt:
                stage.update(status="interrupted", reason="User interrupted acceptance")
                self.report["status"] = "interrupted"
                write_json(self.folder / "report.json", stage)
                self.save()

                raise
            except Exception as exc:
                stage.update(status="error", reason=str(exc), error_type=type(exc).__name__)

            write_json(self.folder / "report.json", stage)
            self.save()

        self.report["status"] = (
            "passed"
            if all(s["status"] in ("passed", "not_requested") for s in self.report["stages"])
            else "failed"
        )
        self.save()

        return self.report


def dispatch(project, argv):
    if not argv or argv[0] != "self-test":
        return None

    from handlers.cli_help import HelpfulParser
    from handlers.runtime_paths import data_root
    from displaying.results import emit_result

    parser = HelpfulParser(
        prog="totenkahn self-test",
        description="Five separate synthetic offline stages; no external services, Atomic or host changes.",
    )
    parser.add_argument("mode", choices=["offline", "operations"])
    parser.add_argument(
        "--output-dir", type=Path, help="New directory; existing results are never overwritten"
    )
    parser.add_argument(
        "--stage",
        action="append",
        type=int,
        choices=range(1, 6),
        help="Run only this stage; repeat to select several. Default: all five",
    )
    parser.add_argument(
        "--events", type=int, help="Operations only: generated records, 1000..1000000; default 5000"
    )
    parser.add_argument(
        "--max-peak-mib",
        type=float,
        help="Operations only: traced Python allocation budget per phase; default 256",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv[1:])
    output = args.output_dir or data_root() / "acceptance" / ("offline-" + str(uuid4()))

    if args.mode == "operations":
        if args.stage:
            parser.error("--stage applies only to self-test offline")

        from handlers.operations_acceptance import run_operations

        try:
            report = run_operations(
                project,
                output,
                events=args.events if args.events is not None else 5000,
                max_peak_mib=args.max_peak_mib if args.max_peak_mib is not None else 256,
            )
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

        emit_result(
            {
                "status": report["status"],
                "checks": report["checks"],
                "metrics": report["metrics"],
                "reason": report.get("reason"),
                "html": str(output / "index.html"),
                "report": str(output / "report.json"),
            },
            "Operational acceptance",
            json_output=args.json,
        )

        return (
            0 if report["status"] == "passed" else 130 if report["status"] == "interrupted" else 1
        )

    if args.events is not None or args.max_peak_mib is not None:
        parser.error("--events and --max-peak-mib apply only to self-test operations")

    try:
        report = OfflineAcceptance(project, output, stages=args.stage).run()
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    emit_result(
        {
            "status": report["status"],
            "stages": [
                {
                    "stage": s["name"],
                    "status": s["status"],
                    "reason": s.get("reason"),
                    "checks": {c["name"]: c["status"] for c in s["checks"]},
                }
                for s in report["stages"]
            ],
            "html": str(output / "index.html"),
            "report": str(output / "report.json"),
            "atomic_tests_executed": 0,
            "selected_stages": report["selected_stages"],
            "scope": report["scope"],
        },
        "Five-stage offline acceptance",
        json_output=args.json,
    )

    return 0 if report["status"] == "passed" else 1
