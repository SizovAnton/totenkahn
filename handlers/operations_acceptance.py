import json
from pathlib import Path
import time
import sys
import tracemalloc

from handlers.case_store import add_dataset, create_case
from handlers.case_timeline import build_timeline
from handlers.dump_analysis import analyze_dump
from handlers.evidence import file_hash, import_dump, inspect_dataset, verify_dataset
from handlers.evidence_recovery import recover_dump
from handlers.hunt_runner import run_hunt
from handlers.hunt_store import define_hunt
from handlers.offline_acceptance import fixture_files, read_json, write_json
from reporting.offline_report import document, link, value_html


def run_operations(project, output, *, events=5000, max_peak_mib=256):
    if type(events) is not int or not 1000 <= events <= 1000000:
        raise ValueError("events must be between 1000 and 1000000")

    if not 16 <= max_peak_mib <= 16384:
        raise ValueError("max-peak-mib must be between 16 and 16384")

    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "status": "running",
        "scope": "synthetic_operational_acceptance",
        "events_requested": events,
        "max_traced_peak_mib": max_peak_mib,
        "atomic_tests_executed": 0,
        "host_configuration_changes": False,
        "checks": [],
        "metrics": [],
        "limitations": [
            "Memory is peak traced Python allocation per operation, not total process RSS or a guarantee for arbitrary inputs.",
            "Elapsed times are measurements on this machine, not universal performance targets.",
            "Recovery restarts indexing from complete verified retained originals; it does not resume at a row offset.",
            "Unvisited directory entries and incomplete copied originals cannot be reconstructed.",
            "Synthetic local data only; no real SIEM/EDR, live collection or Atomic execution.",
        ],
    }

    def save():
        write_json(output / "report.json.tmp", report)
        (output / "report.json.tmp").replace(output / "report.json")
        body = "<h1>Operational acceptance — " + report["status"] + "</h1>"
        body += "<p>Scale, bounded report pages, interruption and recovery. Expected interrupted operations are controls, not successful full imports.</p>"
        body += "<h2>Checks</h2>" + value_html(report["checks"])
        body += "<h2>Measurements</h2>" + value_html(report["metrics"])
        body += "<h2>Limits</h2>" + value_html(report["limitations"])
        body += "<h2>Detailed evidence</h2><ul>"

        for path in sorted(output.rglob("report.html")):
            body += "<li>" + link(path.relative_to(output).as_posix()) + "</li>"

        body += "</ul>" + link("report.json")
        (output / "index.html").write_text(
            document("Operational acceptance", body), encoding="utf-8"
        )

    def check(name, expected, observed):
        report["checks"].append(
            {
                "name": name,
                "status": "passed" if expected == observed else "failed",
                "expected": expected,
                "observed": observed,
            }
        )
        save()

    def measured(name, operation):
        print("Operational check: " + name, file=sys.stderr, flush=True)
        started = time.perf_counter()
        tracemalloc.start()

        try:
            return operation()
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            elapsed = time.perf_counter() - started
            peak_mib = peak / 1024 / 1024
            report["metrics"].append(
                {
                    "operation": name,
                    "seconds": round(elapsed, 3),
                    "peak_traced_mib": round(peak_mib, 3),
                }
            )
            check(name + "_memory_budget", True, peak_mib <= max_peak_mib)

    def interrupt_after_checkpoint(message):
        if "500 records read" in message:
            raise KeyboardInterrupt

    save()

    try:
        fixtures = output / "fixtures"
        fixture_files(fixtures)
        source = fixtures / "scale.jsonl"

        with source.open("w", encoding="utf-8", newline="\n") as stream:
            for i in range(events):
                record = {
                    "timestamp": "2026-11-19T10:00:00Z",
                    "host": "lab-" + str(i % 4),
                    "user": "fixture-user",
                    "event_id": "process-start",
                    "process_id": str(i),
                    "command_line": (
                        "example.exe --review" if i % 2 == 0 else "example.exe --benign"
                    ),
                }
                stream.write(json.dumps(record) + "\n")

        report["source_sha256"] = file_hash(source)
        dataset = output / "dataset"
        imported = measured(
            "import", lambda: import_dump(project, source, dataset, profile="generic-v1")
        )
        check("import_count", events, imported["counts"]["accepted"])
        check("import_integrity", "passed", verify_dataset(dataset)["status"])
        seen = 0
        after = 0

        while True:
            page = inspect_dataset(dataset, after=after, limit=137)
            items = page["items"]

            if not items:
                break

            ids = [item["row_id"] for item in items]

            if ids != list(range(after + 1, after + 1 + len(ids))):
                raise ValueError("Pagination duplicated, reordered or omitted row IDs")

            seen += len(items)
            after = ids[-1]

        check("search_pagination_no_loss", events, seen)
        analysis = output / "analysis"
        analyzed = measured(
            "sigma",
            lambda: analyze_dump(
                project,
                dataset,
                analysis,
                rule=fixtures / "baseline.yaml",
                mapping_path=fixtures / "mapping.json",
            ),
        )
        check(
            "sigma_counts",
            {"match": (events + 1) // 2, "no_match": events // 2},
            analyzed["rules"][0]["counts"],
        )
        pages = analyzed["rules"][0]["pages"]
        check("bounded_sigma_pages", (events + 99) // 100, len(pages))
        check(
            "sigma_page_record_limit",
            True,
            all(
                (analysis / "rule-0001" / name)
                .read_text(encoding="utf-8")
                .count('<article id="row-')
                <= 100
                for name in pages
            ),
        )
        case = output / "case"
        create_case(case, "Synthetic operational case")
        add_dataset(case, dataset, label="scale")
        timeline = measured("timeline", lambda: build_timeline(case, output / "timeline"))
        check("timeline_count", events, timeline["events"])
        define_hunt(case, "review", read_json(fixtures / "hunt.json"), "fixture-engineer")
        hunted = measured("hunt", lambda: run_hunt(case, "review", output / "hunt"))
        check(
            "hunt_counts", {"match": (events + 1) // 2, "no_match": events // 2}, hunted["counts"]
        )
        interrupted = output / "interrupted"
        stopped = import_dump(
            project, source, interrupted, profile="generic-v1", progress=interrupt_after_checkpoint
        )
        check("interruption_is_not_success", "interrupted", stopped["status"])
        before = {
            p.relative_to(interrupted).as_posix(): file_hash(p)
            for p in interrupted.rglob("*")
            if p.is_file()
        }
        restored = measured(
            "recovery", lambda: recover_dump(project, interrupted, output / "recovered")
        )
        check("recovered_count", events, restored["counts"]["accepted"])
        check("recovered_integrity", "passed", verify_dataset(output / "recovered")["status"])
        check("recovery_coverage_explicit", "passed_with_warnings", restored["status"])
        after_files = {
            p.relative_to(interrupted).as_posix(): file_hash(p)
            for p in interrupted.rglob("*")
            if p.is_file()
        }
        check("old_evidence_unchanged", before, after_files)
        report["status"] = (
            "passed" if all(c["status"] == "passed" for c in report["checks"]) else "failed"
        )
    except KeyboardInterrupt:
        report.update(
            status="interrupted",
            reason="Operational acceptance interrupted; completed checks and artifacts retained",
        )
    except Exception as exc:
        report.update(status="error", reason=str(exc), error_type=type(exc).__name__)
    finally:
        save()

    return report
