import json
from pathlib import Path
import sqlite3
from handlers.case_store import (
    case_lock,
    load_case,
    save_case,
    verify_case,
    attachment_paths,
)
from handlers.component_inventory import utc_now
from handlers.dump_readers import DECODER
from handlers.evidence import canonical, digest, file_hash, read_index
from handlers.evidence_selection import load_selection, selected_rows
from handlers.finding_contract import seal_finding, validate_findings


def finding_rows(root, case, refs):
    requests = {}

    for attachment, row in refs:
        if type(row) is not int or row <= 0:
            raise ValueError("Evidence row must be a positive integer")

        requests.setdefault(attachment, set()).add(row)

    attachments = {a["id"]: a for a in case["attachments"]}
    found = {}

    for identifier, ids in requests.items():
        if identifier not in attachments:
            raise ValueError("Unknown evidence attachment")

        attachment = attachments[identifier]
        dataset, selection = attachment_paths(Path(root), attachment)
        saved = load_selection(dataset, selection)
        connection, _ = read_index(dataset)

        try:
            for row in selected_rows(connection, selection, saved):
                if row[0] not in ids:
                    continue

                source = saved["sources"][row[2]]
                reference = {
                    "attachment": identifier,
                    "row_id": row[0],
                    "event_id": row[1],
                    "file_id": row[2],
                    "ordinal": row[3],
                    "source_sha256": source["sha256"],
                    "normalized_sha256": digest(row[4]),
                }
                found[identifier, row[0]] = (reference, row, source, attachment)
        finally:
            connection.close()

        if any(((identifier, row) not in found for row in ids)):
            raise ValueError("Requested row is outside the attached evidence selection")

    return found


def hunt_references(path, case, result_ids):
    path = Path(path).resolve()
    report = DECODER.decode((path / "report.json").read_text(encoding="utf-8"))

    if report.get("report_sha256") != digest(
        canonical({k: v for k, v in report.items() if k != "report_sha256"})
    ):
        raise ValueError("Hunt report metadata changed")

    if (report.get("report_type") != "totenkahn_hunt_v1") or (
        report.get("status") not in {"passed", "needs_verification"}
    ):
        raise ValueError("Finding requires a completed hunt report")

    if report["case_id"] != case["case_id"]:
        raise ValueError("Hunt report belongs to another case")

    database = path / "results.sqlite"

    if database.is_symlink() or file_hash(database) != report["artifacts"]["results.sqlite"]:
        raise ValueError("Hunt evidence index changed")

    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    records = []

    try:
        for identifier in result_ids:
            row = connection.execute(
                "SELECT record FROM results WHERE id=?", (identifier,)
            ).fetchone()

            if row is None:
                raise ValueError("Unknown hunt result ID")

            record = DECODER.decode(row[0])

            if record["result_id"] != identifier:
                raise ValueError("Hunt result identity mismatch")

            records.append(record)
    finally:
        connection.close()

    return (
        records,
        {
            "method": "reviewed_hunt_results",
            "hunt": report["hunt"],
            "report_sha256": file_hash(path / "report.json"),
            "case_snapshot_sha256": report["case_sha256"],
            "selected_results": [
                {"result_id": r["result_id"], "decision": r["decision"]} for r in records
            ],
        },
    )


def create_finding(
    root,
    name,
    title,
    author,
    reason,
    expected_match,
    *,
    attachment=None,
    rows=None,
    hunt_report=None,
    results=None,
):
    if (attachment is None) == (hunt_report is None):
        raise ValueError("Select evidence by attachment or hunt report")

    identifiers = rows if attachment is not None else results

    if (
        (not isinstance(identifiers, list))
        or (not 1 <= len(identifiers) <= 500)
        or any((type(i) is not int or i <= 0 for i in identifiers))
    ):
        raise ValueError("Select 1..500 positive evidence IDs")

    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Duplicate evidence IDs")

    if attachment is not None and results or (hunt_report is not None and rows):
        raise ValueError("Do not mix row IDs with hunt result IDs")

    with case_lock(root) as root:
        verify_case(root)
        case = load_case(root)

        if case["state"] != "open":
            raise ValueError("Case is closed; reopen before adding findings")

        findings = case.setdefault("findings", [])

        if any((f["name"] == name for f in findings)):
            raise ValueError("Finding name exists; create a new name for a reviewed revision")

        records = []

        if attachment is not None:
            matches = [
                a for a in case["attachments"] if a["id"] == attachment or a["label"] == attachment
            ]

            if len(matches) != 1:
                raise ValueError("Unknown or ambiguous attachment")

            refs = [(matches[0]["id"], row) for row in identifiers]
            origin = {"method": "manual_evidence_rows"}
        else:
            records, origin = hunt_references(hunt_report, case, identifiers)
            refs = [(r["attachment"], r["row_id"]) for r in records]

        evidence = finding_rows(root, case, refs)

        for record in records:
            reference, row, _, _ = evidence[record["attachment"], record["row_id"]]

            if (
                (reference["event_id"] != record["event_id"])
                or (json.loads(row[4]) != record["event"])
                or (row[5] != record["raw"])
                or (reference["source_sha256"] != record["source"]["sha256"])
                or (json.loads(row[6]) != record["locator"])
            ):
                raise ValueError("Hunt result no longer agrees with attached evidence")

        finding = seal_finding(
            {
                "name": name,
                "title": title,
                "author": author,
                "reason": reason,
                "created_at": utc_now(),
                "expected_match": expected_match,
                "evidence": [evidence[ref][0] for ref in refs],
                "origin": origin,
            },
        )
        validate_findings([finding])
        findings.append(finding)
        save_case(
            root,
            case,
            "finding_created",
            {"name": name, "finding_sha256": finding["sha256"], "author": author},
        )

        return finding


def verify_finding_refs(root, case, findings):
    refs = [(r["attachment"], r["row_id"]) for finding in findings for r in finding["evidence"]]
    loaded = finding_rows(root, case, refs)

    for finding in findings:
        for ref in finding["evidence"]:
            if ref != loaded[ref["attachment"], ref["row_id"]][0]:
                raise ValueError("Finding evidence reference changed")

    return loaded
