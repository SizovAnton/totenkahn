from collections import Counter
import json
from pathlib import Path
import sqlite3
from handlers.case_store import case_lock, load_case, verify_case, attachment_paths
from handlers.case_timeline import timeline_filters
from handlers.component_inventory import utc_now
from handlers.evidence import canonical, digest, file_hash, read_index
from handlers.evidence_selection import load_selection, selected_rows
from handlers.hunt_definition import evaluate
from handlers.hunt_store import get_hunt
from reporting.hunt_report import write_hunt_report

DIMENSIONS = ("host", "user", "process", "command_line")


def scope_evaluation(definition, event, mapping, filters):
    checks = []

    if "scope" in definition:
        checks.append(evaluate(definition["scope"], event, mapping))

    for key in ("host", "user"):
        if key in filters:
            checks.append(
                evaluate(
                    {"field": "/" + key, "op": "equals", "value": filters[key]}, event, mapping
                ),
            )

    for key in ("start", "end"):
        if key in filters:
            actual = event.get("time_utc")
            result = (
                None
                if actual is None
                else actual >= filters[key] if key == "start" else actual <= filters[key]
            )
            checks.append(
                {
                    "field": "/time_utc",
                    "op": ">=" if key == "start" else "<=",
                    "expected": filters[key],
                    "actual": actual,
                    "result": result,
                    "unknown_checks": int(result is None),
                    "reason": "UTC bound; unknown time is not silently excluded",
                },
            )

    values = [check["result"] for check in checks]
    result = False if False in values else None if None in values else True

    return {
        "operator": "all",
        "result": result,
        "children": checks,
        "unknown_checks": sum((c["unknown_checks"] for c in checks)),
    }


def entities(event):
    result = {}

    for key in ("host", "user", "command_line"):
        value = event.get(key)
        result[key] = value if isinstance(value, str) and value else None

    host = result["host"]
    guid = event.get("process_guid")
    pid = event.get("process_id")

    if host is not None and isinstance(guid, str) and guid:
        process = {"host": host, "process_guid": guid, "basis": "observed_host_and_guid"}
    elif host is not None and type(pid) in {str, int} and (pid != ""):
        process = {
            "host": host,
            "process_id": pid,
            "basis": "pid_observations_not_unique_process_instance",
        }
    else:
        process = None

    result["process"] = process

    return result


def summarize(index, report, output):
    report["matched_unique_evidence_records"] = index.execute(
        "SELECT COUNT(DISTINCT event_id) FROM results WHERE decision='match'"
    ).fetchone()[0]
    report["matching_occurrences_with_unknown_time"] = index.execute(
        "SELECT COUNT(*) FROM results WHERE decision='match' AND time_utc IS NULL",
    ).fetchone()[0]
    report["entities"] = {}

    with (output / "entities.jsonl").open("x", encoding="utf-8") as stream:
        for dimension in DIMENSIONS:
            missing = index.execute(
                f"SELECT COUNT(*) FROM results WHERE decision='match' AND {dimension} IS NULL",
            ).fetchone()[0]
            total_groups = 0
            top = []

            for value, occurrences, unique, first, last in index.execute(
                f"SELECT {dimension},COUNT(*),COUNT(DISTINCT event_id),MIN(time_utc),MAX(time_utc) FROM results WHERE decision='match' AND {dimension} IS NOT NULL GROUP BY {dimension} ORDER BY COUNT(*) DESC,{dimension}",
            ):
                entity = {
                    "dimension": dimension,
                    "value": json.loads(value),
                    "occurrences": occurrences,
                    "unique_evidence_records": unique,
                    "first_known_utc": first,
                    "last_known_utc": last,
                }
                stream.write(canonical(entity) + "\n")
                total_groups += 1

                if len(top) < 50:
                    top.append(entity)

            report["entities"][dimension] = {
                "distinct_observed": total_groups,
                "missing_in_matches": missing,
                "top": top,
                "truncated": total_groups > len(top),
            }


def run_hunt(root, name, output, filters=None, progress=None):
    root, output = (Path(root).resolve(), Path(output).resolve())

    if output.is_relative_to(root):
        raise ValueError("Hunt output must be outside the case")

    filters = timeline_filters(filters or {})

    if "process_id" in filters:
        raise ValueError("Use a typed process_id predicate in the hunt definition")

    with case_lock(root):
        verification = verify_case(root)
        case = load_case(root)
        hunt = get_hunt(case, name)
        output.mkdir(parents=True, exist_ok=False)
        report = {
            "schema_version": 1,
            "report_type": "totenkahn_hunt_v1",
            "status": "error",
            "created_at": utc_now(),
            "case_id": case["case_id"],
            "case_title": case["title"],
            "case_sha256": file_hash(root / "case.json"),
            "case_revision": len(case["history"]),
            "hunt": hunt,
            "filters": filters,
            "counts": {},
            "unknown_predicate_checks": 0,
            "pages": [],
            "entities": {},
            "limitations": verification["limitations"],
            "semantics": "typed_json_three_valued_v1",
            "scope": "Observed evidence in attached selections only; not organization-wide compromise scope, a threat verdict or a SIEM/EDR alert",
            "identity_limitations": "User names are not resolved to accounts; PID groups can contain reused PIDs; overlapping sources are not semantically deduplicated",
        }
        (output / "case-snapshot.json").write_bytes((root / "case.json").read_bytes())
        (output / "hypothesis.json").write_text(
            json.dumps(hunt, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        counts = Counter()
        index = sqlite3.connect(output / "results.sqlite")

        try:
            index.execute(
                "CREATE TABLE results (id INTEGER PRIMARY KEY, decision TEXT, event_id TEXT, time_utc TEXT, host TEXT, user TEXT, process TEXT, command_line TEXT, record TEXT)",
            )
            index.execute("CREATE INDEX decisions ON results(decision,id)")

            with (output / "events.jsonl").open("x", encoding="utf-8") as stream:
                number = 0

                for attachment in case["attachments"]:
                    if progress:
                        progress("Hunting in attachment: " + attachment["label"])

                    dataset, selection = attachment_paths(root, attachment)
                    saved = load_selection(dataset, selection)
                    connection, _ = read_index(dataset)

                    try:
                        for row in selected_rows(connection, selection, saved):
                            number += 1
                            event, mapping = (json.loads(row[4]), json.loads(row[7]))
                            scope = scope_evaluation(hunt["definition"], event, mapping, filters)
                            evaluation = None

                            if scope["result"] is False:
                                decision = "out_of_scope"
                            elif scope["result"] is None:
                                decision = "insufficient_scope"
                            else:
                                evaluation = evaluate(
                                    hunt["definition"]["condition"], event, mapping
                                )
                                decision = (
                                    "insufficient_data"
                                    if evaluation["result"] is None
                                    else "match" if evaluation["result"] else "no_match"
                                )

                            counts[decision] += 1
                            report["unknown_predicate_checks"] += scope["unknown_checks"] + (
                                evaluation["unknown_checks"] if evaluation else 0
                            )
                            source = saved["sources"][row[2]]
                            record = {
                                "result_id": number,
                                "decision": decision,
                                "attachment": attachment["id"],
                                "attachment_label": attachment["label"],
                                "dataset_id": attachment["dataset_id"],
                                "row_id": row[0],
                                "event_id": row[1],
                                "scope_evaluation": scope,
                                "evaluation": evaluation,
                                "entities": entities(event),
                                "event": event,
                                "raw": row[5],
                                "import_mapping": mapping,
                                "locator": json.loads(row[6]),
                                "warnings": json.loads(row[8]),
                                "source": {
                                    "file_id": row[2],
                                    "ordinal": row[3],
                                    "name": source["name"],
                                    "sha256": source["sha256"],
                                    "profile": source.get("profile"),
                                    "case_path": attachment["directory"]
                                    + "/dataset/"
                                    + source["stored"],
                                },
                            }
                            encoded = canonical(record)
                            values = [
                                (
                                    canonical(record["entities"][key])
                                    if record["entities"][key] is not None
                                    else None
                                )
                                for key in DIMENSIONS
                            ]
                            index.execute(
                                "INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?)",
                                (number, decision, row[1], event.get("time_utc"), *values, encoded),
                            )
                            stream.write(encoded + "\n")

                            if number % 1000 == 0:
                                index.commit()

                                if progress:
                                    progress(f"Evaluated {number} evidence occurrences")
                    finally:
                        connection.close()

            index.commit()
            report["counts"] = dict(counts)
            summarize(index, report, output)
            verify_case(root)
            assessed = counts["match"] + counts["no_match"]
            incomplete = (
                (not assessed)
                or counts["insufficient_data"]
                or counts["insufficient_scope"]
                or verification["limitations"]
            )
            report["status"] = "needs_verification" if incomplete else "passed"
            report["hypothesis_result"] = (
                "observed_in_evidence"
                if counts["match"]
                else "undetermined" if incomplete else "not_observed_in_evaluated_records"
            )
            missing_entities = any(
                (
                    report["entities"][key]["missing_in_matches"]
                    for key in ("host", "user", "process")
                ),
            )
            report["scope_status"] = (
                "incomplete"
                if incomplete
                or missing_entities
                or report["matching_occurrences_with_unknown_time"]
                else "observed_entities_summarized"
            )
        except KeyboardInterrupt:
            report.update(
                status="interrupted",
                hypothesis_result="undetermined",
                reason="Hunt interrupted; results are incomplete",
            )
        except Exception as exc:
            report.update(
                status="error",
                hypothesis_result="undetermined",
                reason=str(exc),
                error_type=type(exc).__name__,
            )
        finally:
            report["counts"] = dict(counts)
            index.commit()

            try:
                write_hunt_report(index, report, output)
            finally:
                index.close()

            report["artifacts"] = {
                p.name: file_hash(p)
                for p in output.iterdir()
                if p.is_file() and p.name != "report.json"
            }
            report["finished_at"] = utc_now()
            report["report_sha256"] = digest(canonical(report))
            (output / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        return report


def inspect_scope(output, dimension, value=None, has_value=False, limit=50, after=0):
    if (
        (dimension not in DIMENSIONS)
        or (type(limit) is not int)
        or (not 1 <= limit <= 500)
        or (type(after) is not int)
        or (after < 0)
    ):
        raise ValueError("Invalid scope dimension or pagination")

    output = Path(output).resolve()
    from handlers.dump_readers import DECODER

    report = DECODER.decode((output / "report.json").read_text(encoding="utf-8"))

    if report.get("report_sha256") != digest(
        canonical({k: v for k, v in report.items() if k != "report_sha256"})
    ):
        raise ValueError("Hunt report metadata changed")

    if (report.get("report_type") != "totenkahn_hunt_v1") or (
        report.get("status") not in {"passed", "needs_verification"}
    ):
        raise ValueError("Scope requires a completed hunt report")

    database = output / "results.sqlite"

    if database.is_symlink() or file_hash(database) != report["artifacts"]["results.sqlite"]:
        raise ValueError("Hunt evidence index changed")

    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)

    try:
        if not has_value:
            groups = connection.execute(
                f"SELECT {dimension},COUNT(*),COUNT(DISTINCT event_id) FROM results WHERE decision='match' AND {dimension} IS NOT NULL GROUP BY {dimension} ORDER BY {dimension} LIMIT ? OFFSET ?",
                (limit + 1, after),
            ).fetchall()
            items = [
                {"value": json.loads(v), "occurrences": n, "unique_evidence_records": u}
                for v, n, u in groups[:limit]
            ]
            next_after = after + limit if len(groups) > limit else None
        else:
            if value is None:
                sql, parameters = (f"{dimension} IS NULL", [])
            else:
                sql, parameters = (f"{dimension}=?", [canonical(value)])

            rows = connection.execute(
                f"SELECT id,record FROM results WHERE decision='match' AND {sql} AND id>? ORDER BY id LIMIT ?",
                (*parameters, after, limit + 1),
            ).fetchall()
            items = []
            verified_pages = set()

            for identifier, encoded in rows[:limit]:
                page = f"events-{(identifier - 1) // 100 + 1:04d}.html"

                if page not in verified_pages:
                    if (output / page).is_symlink() or file_hash(output / page) != report[
                        "artifacts"
                    ][page]:
                        raise ValueError("Hunt evidence page changed")

                    verified_pages.add(page)

                record = json.loads(encoded)
                items.append(
                    {
                        "result_id": identifier,
                        "attachment": record["attachment"],
                        "row_id": record["row_id"],
                        "event_id": record["event_id"],
                        "time_utc": record["event"].get("time_utc"),
                        "source": record["source"],
                        "locator": record["locator"],
                        "evidence_page": f"events-{(identifier - 1) // 100 + 1:04d}.html#event-{identifier}",
                    },
                )

            next_after = items[-1]["result_id"] if len(rows) > limit else None

        return {
            "status": "passed",
            "hunt_status": report["status"],
            "scope_status": report.get("scope_status"),
            "dimension": dimension,
            "items": items,
            "next_after": next_after,
            "scope": "Matching occurrences in this saved report only; no new collection or wider-host inference",
        }
    finally:
        connection.close()
