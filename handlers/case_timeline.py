from html import escape
import json
from pathlib import Path
import sqlite3
from handlers.case_store import load_case, verify_case, attachment_paths, case_lock
from handlers.component_inventory import utc_now
from handlers.evidence import canonical, file_hash, parse_time, read_index
from handlers.evidence_selection import load_selection, selected_rows
from reporting.html_report import render_value
from reporting.dump_report import STYLE


def timeline_filters(filters):
    if set(filters) - {"host", "user", "process_id", "start", "end"}:
        raise ValueError("Unknown timeline filter")

    values = {k: v for k, v in filters.items() if v is not None}

    if any((not isinstance(v, str) for v in values.values())):
        raise ValueError("Timeline filters must be strings")

    for key in ("start", "end"):
        if key in values:
            parsed, issue = parse_time(values[key])

            if issue:
                raise ValueError("Timeline bounds require ISO-8601 with timezone")

            values[key] = parsed

    if "start" in values and "end" in values and (values["start"] > values["end"]):
        raise ValueError("Invalid time interval")

    return values


def accepts(event, filters):
    for key in ("host", "user", "process_id"):
        if key in filters and (event.get(key) is None or str(event[key]) != filters[key]):
            return False

    timestamp = event.get("time_utc")

    if "start" in filters and (timestamp is None or timestamp < filters["start"]):
        return False

    if "end" in filters and (timestamp is None or timestamp > filters["end"]):
        return False

    return True


def build_timeline(root, output, filters=None, progress=None):
    root, output = (Path(root).resolve(), Path(output).resolve())

    if output.is_relative_to(root):
        raise ValueError("Timeline output must be outside the case")

    filters = timeline_filters(filters or {})

    with case_lock(root):
        verification = verify_case(root)
        case = load_case(root)
        output.mkdir(parents=True, exist_ok=False)
        report = {
            "schema_version": 1,
            "status": "error",
            "case_id": case["case_id"],
            "case_title": case["title"],
            "case_sha256": file_hash(root / "case.json"),
            "revision": len(case["history"]),
            "created_at": utc_now(),
            "filters": filters,
            "events": 0,
            "unknown_time": 0,
            "excluded": 0,
            "pages": [],
            "limitations": verification["limitations"],
            "scope": "Chronological evidence view; ordering does not establish causation, process identity or a threat verdict",
        }
        (output / "case-snapshot.json").write_bytes((root / "case.json").read_bytes())
        index = sqlite3.connect(output / "timeline.sqlite")

        try:
            index.execute(
                "CREATE TABLE timeline (unknown INTEGER, time_utc TEXT, attachment TEXT, row_id INTEGER, record TEXT, PRIMARY KEY(attachment,row_id))",
            )
            notes_by_event = {}

            for note in case["notes"]:
                notes_by_event.setdefault((note["attachment"], note["row"]), []).append(note)

            for attachment in case["attachments"]:
                if progress:
                    progress("Reading attachment: " + attachment["label"])

                dataset, selection = attachment_paths(root, attachment)
                saved = load_selection(dataset, selection)
                connection, _ = read_index(dataset)

                try:
                    for row in selected_rows(connection, selection, saved):
                        event = json.loads(row[4])

                        if not accepts(event, filters):
                            report["excluded"] += 1
                            continue

                        notes = notes_by_event.get((attachment["id"], row[0]), [])
                        source = saved["sources"][row[2]]
                        record = {
                            "attachment": attachment["id"],
                            "attachment_label": attachment["label"],
                            "dataset_id": attachment["dataset_id"],
                            "row_id": row[0],
                            "event_id": row[1],
                            "time_utc": event.get("time_utc"),
                            "time_status": "known" if event.get("time_utc") else "unknown",
                            "event": event,
                            "raw": row[5],
                            "locator": json.loads(row[6]),
                            "import_mapping": json.loads(row[7]),
                            "warnings": json.loads(row[8]),
                            "source": {
                                "file_id": row[2],
                                "ordinal": row[3],
                                "sha256": source["sha256"],
                                "name": source["name"],
                                "profile": source.get("profile"),
                                "case_path": attachment["directory"]
                                + "/dataset/"
                                + source["stored"],
                            },
                            "notes": notes,
                        }
                        unknown = int(not event.get("time_utc"))
                        index.execute(
                            "INSERT INTO timeline VALUES(?,?,?,?,?)",
                            (
                                unknown,
                                event.get("time_utc"),
                                attachment["id"],
                                row[0],
                                canonical(record),
                            ),
                        )
                        report["events"] += 1
                        report["unknown_time"] += unknown

                        if report["events"] % 1000 == 0:
                            index.commit()

                            if progress:
                                progress(f"Indexed {report['events']} events")
                finally:
                    connection.close()

            index.commit()
            verify_case(root)
            report["status"] = (
                "needs_verification"
                if not report["events"] or report["unknown_time"] or report["limitations"]
                else "passed"
            )
        except KeyboardInterrupt:
            report.update(
                status="interrupted",
                reason="Timeline interrupted; available records are incomplete",
            )
        except Exception as exc:
            report.update(status="error", reason=str(exc), error_type=type(exc).__name__)
        finally:
            try:
                index.commit()
                write_timeline(index, report, output)
            except KeyboardInterrupt:
                report.update(
                    status="interrupted",
                    reason="Timeline export interrupted; retained artifacts are incomplete",
                )
            except Exception as exc:
                report.update(
                    status="error",
                    reason="Timeline export failed: " + str(exc),
                    error_type=type(exc).__name__,
                )
            finally:
                index.close()

            write_summary(report, case, output)
            report["artifacts"] = {
                path.name: file_hash(path)
                for path in output.iterdir()
                if path.is_file() and path.name != "report.json"
            }
            (output / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        return report


def write_timeline(index, report, output):
    page = None
    count = 0

    try:
        with (output / "events.jsonl").open("x", encoding="utf-8") as stream:
            for (encoded,) in index.execute(
                "SELECT record FROM timeline ORDER BY unknown,time_utc,attachment,row_id"
            ):
                record = json.loads(encoded)
                stream.write(encoded + "\n")

                if count % 100 == 0:
                    if page is not None:
                        page.write("</body></html>")
                        page.close()

                    name = f"events-{len(report['pages']) + 1:04d}.html"
                    report["pages"].append(name)
                    page = (output / name).open("x", encoding="utf-8")
                    page.write(
                        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Case timeline</title>'
                        + STYLE
                        + '<body><a href="report.html">Case summary</a>',
                    )

                if page is None:
                    raise RuntimeError("Timeline page missing")

                label = record["time_utc"] or "UNKNOWN TIME — not placed in chronological order"
                page.write(
                    "<article><h2>"
                    + escape(label)
                    + "</h2><p>"
                    + escape(record["attachment_label"])
                    + " / row "
                    + str(record["row_id"])
                    + "</p>",
                )

                for key in (
                    "event",
                    "source",
                    "locator",
                    "import_mapping",
                    "warnings",
                    "raw",
                    "notes",
                ):
                    page.write(
                        "<details><summary>"
                        + key
                        + "</summary>"
                        + render_value(record[key])
                        + "</details>",
                    )

                page.write("</article>")
                count += 1
    finally:
        if page is not None:
            page.write("</body></html>")
            page.close()


def write_summary(report, case, output):
    html = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>totenkahn case</title>'
        + STYLE
        + "<body><h1>"
        + escape(case["title"])
        + "</h1>"
    )
    html += "<p>Status: " + escape(report["status"]) + "</p><p>" + escape(report["scope"]) + "</p>"
    html += render_value({k: v for k, v in report.items() if k != "artifacts"})
    html += "<h2>Evidence pages</h2>" + " ".join(
        ('<a href="' + name + '">' + str(i) + "</a>" for i, name in enumerate(report["pages"], 1)),
    )
    html += "<h2>Analyst annotations (not observed events)</h2>" + render_value(case["notes"])
    html += "<h2>Case activity history</h2>" + render_value(case["history"])
    html += '<p><a href="report.json">JSON report</a>; complete event records: events.jsonl. Exact originals are stored in the case.</p></body></html>'
    (output / "report.html").write_text(html, encoding="utf-8")
