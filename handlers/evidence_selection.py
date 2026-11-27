import json
from pathlib import Path
import re
from handlers.component_inventory import utc_now
from handlers.dump_readers import DECODER
from handlers.evidence import canonical, digest, file_hash, parse_time, read_index

FILTER_KEYS = {
    "host",
    "event_type",
    "channel",
    "provider",
    "source",
    "text",
    "start",
    "end",
    "rows",
    "fields",
}


def pointer(value, path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Field paths must be JSON pointers beginning with /")

    if re.search("~(?![01])", path):
        raise ValueError("Invalid JSON pointer escape")

    for part in path[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")

        if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", key):
            index = int(key)

            if index >= len(value):
                return (False, None)

            value = value[index]
        elif isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return (False, None)

    return (True, value)


def validate_filters(filters):
    if not isinstance(filters, dict) or set(filters) - FILTER_KEYS:
        raise ValueError("Unknown selection filter")

    result = {key: value for key, value in filters.items() if value is not None}

    for key in FILTER_KEYS - {"rows", "fields"}:
        if key in result and (not isinstance(result[key], str)):
            raise ValueError(f"{key} must be a string")

    for key in ("start", "end"):
        if key in result:
            value, issue = parse_time(result[key])

            if issue:
                raise ValueError("Time filters require ISO-8601 with timezone")

            result[key] = value

    if "start" in result and "end" in result and (result["start"] > result["end"]):
        raise ValueError("Invalid time interval")

    rows = result.get("rows", [])

    if not isinstance(rows, list) or any((type(row) is not int or row <= 0 for row in rows)):
        raise ValueError("rows must be positive integer IDs")

    if len(rows) > 500:
        raise ValueError("At most 500 explicit row IDs; use filters for larger selections")

    if rows:
        result["rows"] = sorted(set(rows))
    else:
        result.pop("rows", None)

    fields = result.get("fields", [])

    if not isinstance(fields, list):
        raise ValueError("fields must be a list")

    for condition in fields:
        if not isinstance(condition, dict) or set(condition) != {"path", "op", "value"}:
            raise ValueError("Field filter requires path, op and value")

        pointer({}, condition["path"])

        if condition["op"] not in {"equals", "contains", "exists", "text_equals"}:
            raise ValueError("Unsupported field filter operation")

        value = condition["value"]

        if condition["op"] == "exists" and type(value) is not bool:
            raise ValueError("exists requires a boolean")

        if condition["op"] in {"contains", "text_equals"} and (not isinstance(value, str)):
            raise ValueError("Text filter requires a string")

        if isinstance(value, (list, dict)):
            raise ValueError("Field comparisons support scalar values only")

    if not fields:
        result.pop("fields", None)

    return result


def matches_fields(event, filters):
    for condition in filters.get("fields", []):
        present, actual = pointer(event, condition["path"])
        expected, operation = (condition["value"], condition["op"])

        if operation == "exists":
            matched = present == expected
        elif not present:
            matched = False
        elif operation == "equals":
            matched = type(actual) is type(expected) and actual == expected
        elif operation == "contains":
            matched = isinstance(actual, str) and expected in actual
        else:
            matched = not isinstance(actual, (dict, list)) and str(actual) == expected

        if not matched:
            return False

    return True


def checked_index(dataset):
    dataset = Path(dataset).resolve()
    connection, manifest = read_index(dataset)

    try:
        if file_hash(dataset / "index.sqlite") != manifest["index_sha256"]:
            raise ValueError("Dataset index changed; import again from trusted originals")
    except BaseException:
        connection.close()

        raise

    return (connection, manifest)


def query_rows(connection, manifest, filters):
    clauses, parameters = ([], [])

    for key, column in [("host", "host"), ("event_type", "kind"), ("channel", "channel")]:
        if key in filters:
            clauses.append(column + " = ?")
            parameters.append(filters[key])

    for key, operator in [("start", ">="), ("end", "<=")]:
        if key in filters:
            clauses.append("time_utc " + operator + " ?")
            parameters.append(filters[key])

    if "text" in filters:
        clauses.append("instr(lower(raw),lower(?)) > 0")
        parameters.append(filters["text"])

    if "rows" in filters:
        clauses.append("row_id IN (" + ",".join(("?" for _ in filters["rows"])) + ")")
        parameters.extend(filters["rows"])

    if "source" in filters:
        ids = [
            f["file_id"]
            for f in manifest["files"]
            if f["name"] == filters["source"] or f["file_id"] == filters["source"]
        ]

        if not ids:
            return

        clauses.append("file_id IN (" + ",".join(("?" for _ in ids)) + ")")
        parameters.extend(ids)

    sql = (
        "SELECT row_id,event_id,file_id,ordinal,normalized,raw,locator,mapping,warnings FROM events"
    )

    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    sql += " ORDER BY row_id"

    for row in connection.execute(sql, parameters):
        event = json.loads(row[4])

        if "provider" in filters and event.get("provider") != filters["provider"]:
            continue

        if matches_fields(event, filters):
            yield row


def source_check(dataset, source):
    stored = source.get("stored")

    if not isinstance(stored, str) or "sha256" not in source:
        raise ValueError("Selected source has no confirmed snapshot")

    path = dataset / stored

    if path.is_symlink() or not path.resolve().is_relative_to(dataset):
        raise ValueError("Unsafe original source path")

    if not path.is_file() or file_hash(path) != source["sha256"]:
        raise ValueError("Selected original is missing or changed: " + source["name"])


def create_selection(dataset, output, filters):
    dataset, output = (Path(dataset).resolve(), Path(output).resolve())
    filters = validate_filters(filters)
    connection, manifest = checked_index(dataset)
    manifest_hash = file_hash(dataset / "manifest.json")

    try:
        output.mkdir(parents=True, exist_ok=False)
    except BaseException:
        connection.close()

        raise

    sources = {source["file_id"]: source for source in manifest["files"]}
    selected_sources = {}
    count = 0
    found_rows = set()

    try:
        with (output / "members.jsonl").open("x", encoding="utf-8") as stream:
            for row in query_rows(connection, manifest, filters):
                source = sources[row[2]]

                if row[2] not in selected_sources:
                    source_check(dataset, source)
                    selected_sources[row[2]] = source

                member = {
                    "row_id": row[0],
                    "event_id": row[1],
                    "file_id": row[2],
                    "ordinal": row[3],
                    "normalized_sha256": digest(row[4]),
                }
                stream.write(canonical(member) + "\n")
                count += 1

                if "rows" in filters:
                    found_rows.add(row[0])

        if "rows" in filters and found_rows != set(filters["rows"]):
            raise ValueError("Some explicit row IDs were absent or excluded by other filters")

        if (file_hash(dataset / "manifest.json") != manifest_hash) or (
            file_hash(dataset / "index.sqlite") != manifest["index_sha256"]
        ):
            raise ValueError("Dataset changed during selection")

        for source in selected_sources.values():
            source_check(dataset, source)

        result = {
            "schema_version": 1,
            "status": "passed" if count else "needs_verification",
            "created_at": utc_now(),
            "dataset_id": manifest["dataset_id"],
            "dataset_path": str(dataset),
            "dataset_status": manifest["status"],
            "manifest_sha256": manifest_hash,
            "index_sha256": manifest["index_sha256"],
            "filters": filters,
            "count": count,
            "sources": selected_sources,
            "members_sha256": file_hash(output / "members.jsonl"),
            "scope": "Explicit saved evidence selection; not an expectation or detection verdict",
        }
        result["selection_contract_sha256"] = digest(canonical(result))
        (output / "selection.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return result
    finally:
        connection.close()


def load_selection(dataset, selection):
    dataset, selection = (Path(dataset).resolve(), Path(selection).resolve())
    saved = DECODER.decode((selection / "selection.json").read_text(encoding="utf-8"))
    contract_hash = saved.get("selection_contract_sha256")

    if contract_hash != digest(
        canonical({k: v for k, v in saved.items() if k != "selection_contract_sha256"})
    ):
        raise ValueError("Selection contract changed")

    if (saved.get("schema_version") != 1) or (
        saved.get("status") not in {"passed", "needs_verification"}
    ):
        raise ValueError("Selection is incomplete or uses an unsupported schema")

    if (not (selection / "members.jsonl").is_file()) or (
        file_hash(selection / "members.jsonl") != saved["members_sha256"]
    ):
        raise ValueError("Selection membership changed")

    connection, manifest = checked_index(dataset)

    try:
        if (
            (manifest["dataset_id"] != saved["dataset_id"])
            or (manifest["index_sha256"] != saved["index_sha256"])
            or (file_hash(dataset / "manifest.json") != saved["manifest_sha256"])
        ):
            raise ValueError("Selection does not match this dataset snapshot")

        current_sources = {f["file_id"]: f for f in manifest["files"]}

        for key, source in saved["sources"].items():
            if source != current_sources.get(key):
                raise ValueError("Selection source metadata disagrees with the dataset")

            source_check(dataset, source)

        return saved
    finally:
        connection.close()


def selected_rows(connection, selection, saved):
    previous = 0
    count = 0

    with (Path(selection) / "members.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            member = DECODER.decode(line)
            row_id = member["row_id"]

            if type(row_id) is not int or row_id <= previous:
                raise ValueError("Selection rows must be unique and ordered")

            previous = row_id
            row = connection.execute(
                "SELECT row_id,event_id,file_id,ordinal,normalized,raw,locator,mapping,warnings FROM events WHERE row_id=?",
                (row_id,),
            ).fetchone()

            if (row is None) or (
                (row[1], row[2], row[3], digest(row[4]))
                != (
                    member["event_id"],
                    member["file_id"],
                    member["ordinal"],
                    member["normalized_sha256"],
                )
            ):
                raise ValueError("Selected event is absent or changed")

            if row[2] not in saved["sources"]:
                raise ValueError("Selection source snapshot is missing")

            count += 1
            yield row

    if count != saved["count"]:
        raise ValueError("Selection membership count disagrees with snapshot")
