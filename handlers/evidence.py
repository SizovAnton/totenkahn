from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
import zlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from html import escape
from uuid import uuid4
from handlers.component_inventory import utc_now
from handlers.dump_readers import DECODER, json_records, xml_records
from handlers.evidence_normalization import mapped, windows_fields, decode_raw, field_state
from handlers.tabular_input import options as input_options, tabular_records, unpack_gzip

FIELDS = (
    "timestamp",
    "host",
    "event_id",
    "native_record_id",
    "channel",
    "provider",
    "user",
    "process_id",
    "parent_process_id",
    "process_guid",
    "command_line",
)
PROFILES = {
    "generic-v1": {
        "schema_version": 1,
        "id": "generic-v1",
        "time_format": "iso8601",
        "mappings": {key: [key] for key in FIELDS},
    },
    "splunk-v1": {
        "schema_version": 1,
        "id": "splunk-v1",
        "time_format": "splunk",
        "mappings": {
            "timestamp": ["_time"],
            "host": ["host"],
            "event_id": ["EventCode"],
            "native_record_id": ["EventRecordID"],
            "channel": ["Channel"],
            "provider": ["SourceName"],
            "user": ["user"],
            "process_id": ["ProcessId"],
            "parent_process_id": ["ParentProcessId"],
            "process_guid": ["ProcessGuid"],
            "command_line": ["CommandLine"],
        },
    },
    "windows-xml-v1": {
        "schema_version": 1,
        "id": "windows-xml-v1",
        "time_format": "iso8601",
        "mappings": {
            **{key: [key] for key in FIELDS[:7]},
            "process_id": ["fields", "ProcessId"],
            "parent_process_id": ["fields", "ParentProcessId"],
            "process_guid": ["fields", "ProcessGuid"],
            "command_line": ["fields", "CommandLine"],
        },
    },
}

PROFILES["elastic-discover-v1"] = {
    "schema_version": 1,
    "id": "elastic-discover-v1",
    "time_format": "iso8601",
    "mappings": {
        "timestamp": ["fields", "@timestamp"],
        "host": ["fields", "host.name"],
        "event_id": ["fields", "event.id"],
        "native_record_id": ["_id"],
        "user": ["fields", "user.name"],
        "process_id": ["fields", "process.pid"],
        "parent_process_id": ["fields", "process.parent.pid"],
        "command_line": ["fields", "process.command_line"],
    },
}


for profile_id, raw_format in [
    ("splunk-raw-windows-v1", "windows_xml"),
    ("splunk-raw-json-v1", "generic_json"),
]:
    PROFILES[profile_id] = {**PROFILES["splunk-v1"], "id": profile_id, "raw_format": raw_format}

SCHEMA = """
PRAGMA user_version=1;
CREATE TABLE sources(file_id TEXT PRIMARY KEY, relative_path TEXT, original_path TEXT,
 sha256 TEXT, size INTEGER, format TEXT, profile_json TEXT, status TEXT, error TEXT);
CREATE TABLE events(row_id INTEGER PRIMARY KEY, event_id TEXT, file_id TEXT, ordinal INTEGER,
 time_utc TEXT, host TEXT, kind TEXT, channel TEXT, user TEXT, fingerprint TEXT,
 normalized TEXT, raw TEXT, locator TEXT, mapping TEXT, warnings TEXT);
CREATE INDEX events_time ON events(time_utc);
CREATE INDEX events_host ON events(host);
CREATE INDEX events_kind ON events(kind);
CREATE INDEX events_identity ON events(event_id);
CREATE INDEX events_fingerprint ON events(fingerprint);
CREATE TABLE issues(file_id TEXT, ordinal INTEGER, locator TEXT, reason TEXT);
"""


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value):
    return sha256(value.encode("utf-8")).hexdigest()


def file_hash(path):
    hasher = sha256()

    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)

    return hasher.hexdigest()


def profile_for(value):
    if value in PROFILES:
        return PROFILES[value]

    profile = DECODER.decode(Path(value).read_text(encoding="utf-8-sig"))

    if (not isinstance(profile, dict)) or (
        set(profile) != {"schema_version", "id", "time_format", "mappings"}
    ):
        raise ValueError("Profile requires schema_version, id, time_format and mappings")

    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise ValueError("Unsupported profile schema")

    if not isinstance(profile["id"], str) or not profile["id"].strip():
        raise ValueError("Profile id must be a nonempty string")

    if profile["time_format"] not in {"iso8601", "unix_seconds"}:
        raise ValueError("Custom time_format must be iso8601 or unix_seconds")

    mappings = profile["mappings"]

    if not isinstance(mappings, dict) or not mappings or set(mappings) - set(FIELDS):
        raise ValueError("Unsupported mapping fields")

    if any(
        (
            (
                (not isinstance(path, list))
                or (not path)
                or any((not isinstance(k, str) or not k for k in path))
            )
            for path in mappings.values()
        ),
    ):
        raise ValueError("Mapping paths must be nonempty arrays of object keys")

    return profile


def parse_time(value, time_format="iso8601"):
    if value is None or value == "":
        return (None, "missing_timestamp")

    try:
        if (time_format == "unix_seconds") or (
            time_format == "splunk" and str(value).replace(".", "", 1).lstrip("-").isdigit()
        ):
            if isinstance(value, bool):
                raise ValueError("Boolean time")

            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if moment.tzinfo is None:
            return (None, "unknown_timezone")

        return (moment.astimezone(timezone.utc).isoformat(timespec="microseconds"), None)
    except (ValueError, TypeError, OverflowError, OSError):
        return (None, "invalid_timestamp")


def normalize(record, profile):
    if not isinstance(record, dict):
        raise ValueError("Event must be a JSON object")

    prefix = []

    if profile["id"].startswith("splunk") and "result" in record:
        if record.get("preview") is True or str(record.get("preview", "")).lower() == "true":
            raise ValueError("Splunk preview row is not final evidence")

        record = record["result"]
        prefix = ["result"]

        if not isinstance(record, dict):
            raise ValueError("Splunk result must be an object")

    discover = profile["id"] == "elastic-discover-v1"

    if discover and not isinstance(record.get("fields"), dict):
        raise ValueError("Elastic Discover input requires a document with a fields object")

    result, mapping, warnings = ({}, {}, [])

    for field, path in profile["mappings"].items():
        value, trace = mapped(record, path, prefix)

        if discover and path[0] == "fields" and trace["present"]:
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
                trace = {
                    **trace,
                    "state": field_state(True, value),
                    "conversion": "unwrap_singleton_array",
                    "value_path": path + [0],
                }
            elif isinstance(value, list):
                trace = {
                    **trace,
                    "state": "multivalue" if value else "empty",
                    "conversion": "not_converted_ambiguous_array",
                }
                warnings.append("ambiguous_discover_" + field)
                value = None

            if isinstance(value, (dict, list, bool)):
                trace = {**trace, "state": "unsupported_type"}
                warnings.append("unsupported_discover_" + field)
                value = None

        result[field], mapping[field] = value, trace

        if isinstance(value, (dict, list)):
            warnings.append("non_scalar_" + field)

    if discover:
        result["source_metadata"] = {
            key: record[key] for key in ("_index", "_id", "_version") if key in record
        }
        result["source_metadata"]["discover_fields"] = {
            key: record["fields"][key]
            for key in (
                "event.dataset", "event.category", "event.type", "event.action",
                "agent.type", "agent.version", "host.os.type", "process.entity_id",
            )
            if key in record["fields"]
        }

    if profile["id"] == "windows-xml-v1":
        windows_fields(record, result, mapping, warnings)

    if profile["id"].startswith("splunk"):
        result["source_metadata"] = {
            key: record[key] for key in ("sourcetype", "source", "index") if key in record
        }

    if profile.get("raw_format"):
        decoded = decode_raw(record, profile["raw_format"])
        decoded_profile = (
            PROFILES["windows-xml-v1"]
            if profile["raw_format"] == "windows_xml"
            else PROFILES["generic-v1"]
        )
        inner, inner_mapping, inner_warnings = normalize(decoded, decoded_profile)
        result["decoded_raw"] = decoded
        conflicts = []

        for field, trace in inner_mapping.items():
            if not trace["present"]:
                continue

            inner_value = inner.get(field)
            outer = mapping.get(field, {"present": False})
            raw_trace = {
                **trace,
                "path": prefix + ["_raw"],
                "decoded_path": trace["path"],
                "decoder": profile["raw_format"],
            }

            if outer["present"]:
                left, right = result.get(field), inner_value
                equal = type(left) is type(right) and left == right

                if field == "timestamp":
                    left_time, left_issue = parse_time(left, "splunk")
                    right_time, right_issue = parse_time(right, decoded_profile["time_format"])
                    equal = not left_issue and not right_issue and left_time == right_time
                elif (
                    field in {"process_id", "parent_process_id"}
                    and isinstance(left, (str, int))
                    and not isinstance(left, bool)
                ):
                    try:
                        equal = (
                            int(left, 16 if left.lower().startswith("0x") else 10) == right
                            if isinstance(left, str)
                            else left == right
                        )
                    except ValueError:
                        equal = False
                elif (
                    field in {"event_id", "native_record_id"}
                    and isinstance(left, (str, int))
                    and not isinstance(left, bool)
                ):
                    equal = str(left) == str(right)

                if not equal:
                    conflicts.append(
                        {
                            "field": field,
                            "extracted": left,
                            "decoded": right,
                            "extracted_mapping": outer,
                            "decoded_mapping": raw_trace,
                        }
                    )
                    mapping[field] = {
                        **outer,
                        "state": "conflict",
                        "decoded_alternative": raw_trace,
                    }
                else:
                    mapping[field]["corroborated_by"] = raw_trace

                    if field in {"process_id", "parent_process_id"}:
                        result[field] = inner_value
                        mapping[field]["conversion"] = "pid_to_decimal_integer"
            else:
                result[field], mapping[field] = inner_value, raw_trace

        result["normalization_conflicts"] = conflicts

        if conflicts:
            warnings.append("extracted_raw_conflict")

        if profile["raw_format"] == "windows_xml":
            result["source_profile"] = inner["source_profile"]

        warnings.extend(item for item in inner_warnings if item.startswith("invalid_"))

    result["time_utc"], issue = parse_time(result.get("timestamp"), profile["time_format"])

    if issue:
        warnings.append(issue)

    if not result.get("host"):
        warnings.append("missing_host")

    if not result.get("event_id"):
        warnings.append("missing_event_id")

    result["fields"] = record

    return (result, mapping, warnings)


def snapshot_file(source, target, progress=None):
    before = source.stat()

    if source.is_symlink() or not source.is_file():
        raise ValueError("Only regular non-symlink source files are supported")

    hasher = sha256()
    size = 0

    with source.open("rb") as original, target.open("xb") as copied:
        while chunk := original.read(1024 * 1024):
            copied.write(chunk)
            hasher.update(chunk)
            size += len(chunk)

            if progress and size % (16 * 1024 * 1024) == 0:
                progress(f"Copied {size} bytes")

        copied.flush()
        os.fsync(copied.fileno())

    after = source.stat()

    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ):
        raise ValueError("Source changed while copying; retained copy is not accepted")

    return (hasher.hexdigest(), size)


def evtx_export(project, original, derived, timeout):
    if sys.platform != "win32":
        raise ValueError(
            "EVTX decoding requires Windows; original retained for later import on Windows",
        )

    with derived.open("xb") as stream, derived.with_suffix(".stderr.txt").open("xb") as errors:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(project / "scripts/export_evtx.ps1"),
                "-InputPath",
                str(original),
            ],
            stdout=stream,
            stderr=errors,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )

    return result.returncode


def database(path):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(SCHEMA)

    return connection


def scalar(value):
    return str(value) if value is not None and (not isinstance(value, (dict, list))) else None


def input_files(source):

    def fail(error):
        raise error

    for directory, folders, files in os.walk(source, onerror=fail, followlinks=False):
        folders.sort()

        for name in folders:
            path = Path(directory) / name

            if path.is_symlink():
                yield path

        for name in sorted(files):
            yield (Path(directory) / name)


def save_import_manifest(output, report):
    target = Path(output) / "manifest.json"
    temporary = None
    delays = (0.05, 0.1, 0.2, 0.4, 0.8, 1.0)

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output, prefix=".manifest-", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())

        for attempt in range(len(delays) + 1):
            try:
                os.replace(temporary, target)
                return
            except OSError as exc:
                if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == len(delays):
                    raise
                time.sleep(delays[attempt])
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def import_dump(
    project,
    source,
    output,
    *,
    profile=None,
    timeout=600,
    progress=None,
    reader_options=None,
    recovery=None,
):
    source, output = (Path(source).absolute(), Path(output).absolute())

    if not source.exists() or source.is_symlink():
        raise ValueError("Input must be an existing file or directory, not a symlink")

    if source.is_dir() and (output == source or source in output.parents):
        raise ValueError("Output must be outside the input directory")

    source, output = (source.resolve(), output.resolve())

    if source.is_dir() and (output == source or source in output.parents):
        raise ValueError("Output resolves inside the input directory")

    reader_options = input_options(**(reader_options or {}))
    selected_profile = profile_for(profile) if profile else None
    output.mkdir(parents=True, exist_ok=False)
    (output / "originals").mkdir()
    (output / "derived").mkdir()
    report = {
        "schema_version": 1,
        "dataset_id": str(uuid4()),
        "status": "importing",
        "created_at": utc_now(),
        "scope": "import_only_no_detection_or_live_execution",
        "source": str(source),
        "counts": {"read": 0, "accepted": 0, "rejected": 0},
        "files": [],
        "limitations": [
            "Imported data may not cover the full source environment.",
            "Hashes provide integrity checks, not an authenticated legal chain of custody.",
            "A missing mapped field is not proof that the source sensor never collected it.",
        ],
    }

    if recovery is not None:
        report["recovery"] = recovery
        report["limitations"].append(recovery["coverage"])

    connection = database(output / "index.sqlite")
    db_closed = False

    def save():
        save_import_manifest(output, report)

    try:
        save()
        candidates = input_files(source) if source.is_dir() else iter([source])

        for item in candidates:
            if item.is_dir() and (not item.is_symlink()):
                continue

            relative = item.relative_to(source).as_posix() if source.is_dir() else item.name
            file_id = digest(relative)
            compressed = item.suffix.lower() == ".gz"
            kind = (Path(item.stem).suffix if compressed else item.suffix).lower().lstrip(".")
            destination = output / "originals" / file_id
            entry = {
                "file_id": file_id,
                "name": relative,
                "original_path": str(item),
                "stored": destination.relative_to(output).as_posix(),
                "status": "copying",
                "format": kind,
                "compression": "gzip" if compressed else None,
                "reader_options": reader_options,
                "read": 0,
                "accepted": 0,
                "rejected": 0,
            }
            report["files"].append(entry)
            save()

            if progress:
                progress(f"Importing: {relative}")

            ordinal = 0

            try:
                entry["sha256"], entry["size"] = snapshot_file(item, destination, progress)
                chosen = PROFILES["windows-xml-v1"] if kind in {"xml", "evtx"} else selected_profile

                if kind not in {"xml", "evtx", "json", "jsonl", "ndjson", "csv", "tsv"} or (
                    compressed and kind not in {"json", "jsonl", "ndjson", "csv", "tsv"}
                ):
                    raise ValueError("Unsupported extension; original copied but not indexed")

                if chosen is None:
                    raise ValueError(
                        "JSON/tabular input requires an explicit --profile generic-v1, splunk-v1, elastic-discover-v1 or profile file",
                    )

                entry["profile"] = chosen
                entry["profile_sha256"] = digest(canonical(chosen))
                entry["status"] = "reading"
                save()
                connection.execute(
                    "INSERT INTO sources VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        file_id,
                        relative,
                        str(item),
                        entry["sha256"],
                        entry["size"],
                        kind,
                        canonical(chosen),
                        "reading",
                        None,
                    ),
                )
                input_path = destination

                if compressed:
                    input_path = output / "derived" / (file_id + "." + kind)
                    expanded = unpack_gzip(
                        destination,
                        input_path,
                        reader_options["max_expanded_mib"] * 1024 * 1024,
                        progress,
                    )
                    entry["expanded"] = {
                        **expanded,
                        "stored": input_path.relative_to(output).as_posix(),
                    }

                exit_code = 0

                if kind == "xml":
                    records = xml_records(destination)
                elif kind == "evtx":
                    derived = output / "derived" / (file_id + ".jsonl")
                    exit_code = evtx_export(Path(project), destination, derived, timeout)
                    records = json_records(derived, lines=True)
                elif kind in {"csv", "tsv"}:
                    records = tabular_records(input_path, kind, reader_options)
                else:
                    records = json_records(
                        input_path,
                        lines=kind in {"jsonl", "ndjson"},
                        splunk=chosen["id"].startswith("splunk"),
                    )

                for ordinal, row in enumerate(records, 1):
                    entry["read"] += 1
                    report["counts"]["read"] += 1

                    try:
                        if "error" in row:
                            raise ValueError(row["error"])

                        if kind == "evtx":
                            from handlers.dump_readers import xml_record

                            xml = row["record"]["xml"]
                            row["record"] = xml_record(ET.fromstring(xml))
                            row["raw"] = xml
                            row["locator"] = {"evtx_event": ordinal}

                        event, mapping, warnings = normalize(row["record"], chosen)

                        if "original_cells" in row:
                            for trace in mapping.values():
                                path = trace.get("path", [])

                                if path and path[0] in row["original_cells"]:
                                    trace["original_cell"] = row["original_cells"][path[0]]

                                    if trace["original_cell"] == reader_options["null_value"]:
                                        trace["input_conversion"] = "explicit_tabular_null_token"

                        if compressed:
                            row["locator"] = {
                                **row["locator"],
                                "container": "gzip",
                                "expanded_sha256": entry["expanded"]["sha256"],
                            }

                        stable_id = digest(entry["sha256"] + ":" + str(ordinal))
                        connection.execute(
                            "INSERT INTO events VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                stable_id,
                                file_id,
                                ordinal,
                                event["time_utc"],
                                scalar(event.get("host")),
                                scalar(event.get("event_id")),
                                scalar(event.get("channel")),
                                scalar(event.get("user")),
                                digest(canonical(event["fields"])),
                                canonical(event),
                                row["raw"],
                                canonical(row["locator"]),
                                canonical(mapping),
                                canonical(warnings),
                            ),
                        )
                        entry["accepted"] += 1
                        report["counts"]["accepted"] += 1
                    except (ValueError, TypeError, KeyError) as exc:
                        entry["rejected"] += 1
                        report["counts"]["rejected"] += 1
                        connection.execute(
                            "INSERT INTO issues VALUES (?,?,?,?)",
                            (file_id, ordinal, canonical(row.get("locator")), str(exc)),
                        )

                    if ordinal % 500 == 0:
                        connection.commit()
                        save()

                        if progress:
                            progress(f"{relative}: {ordinal} records read")

                if exit_code:
                    raise ValueError(
                        f"EVTX decoder exited {exit_code}; inspect retained derived stderr, coverage incomplete",
                    )

                if not entry["read"]:
                    raise ValueError("No event records found")

                if file_hash(destination) != entry["sha256"]:
                    raise ValueError("Stored original changed during import")

                entry["status"] = "partial" if entry["rejected"] else "passed"
            except (
                OSError,
                ValueError,
                TypeError,
                RuntimeError,
                ET.ParseError,
                subprocess.SubprocessError,
                EOFError,
                zlib.error,
            ) as exc:
                entry.update(
                    status="error",
                    error=str(exc),
                    error_type=type(exc).__name__,
                    errno=getattr(exc, "errno", None),
                    winerror=getattr(exc, "winerror", None),
                )
                connection.execute(
                    "INSERT INTO issues VALUES (?,?,?,?)",
                    (file_id, ordinal, "{}", str(exc)),
                )

            connection.execute(
                "UPDATE sources SET status=?,error=? WHERE file_id=?",
                (entry["status"], entry.get("error"), file_id),
            )
            connection.commit()
            save()

        accepted = report["counts"]["accepted"]
        bad = any((f["status"] != "passed" for f in report["files"]))
        report["status"] = "error" if not accepted else "partial" if bad else "passed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["reason"] = (
            "Import interrupted; retained originals can be reindexed with dump recover into a new directory"
        )
    except Exception as exc:
        report.update(status="error", reason=str(exc))
    finally:
        try:
            connection.commit()
            report["quality"] = quality(connection)

            if report["status"] == "passed" and report["quality"]["events_with_warnings"]:
                report["status"] = "passed_with_warnings"

            connection.close()
            db_closed = True
            report["index_sha256"] = file_hash(output / "index.sqlite")
            report["finished_at"] = utc_now()

            if recovery is not None and report["status"] == "passed":
                report["status"] = "passed_with_warnings"

            report["errors"] = [
                {key: item.get(key) for key in ("name", "error", "error_type", "errno", "winerror")}
                for item in report["files"]
                if item.get("error")
            ]
            if report["errors"] and not report.get("reason"):
                report["reason"] = "; ".join(
                    f"{item['name']}: {item['error']}" for item in report["errors"]
                )
            try:
                save()
            except OSError as exc:
                report.update(
                    status="error",
                    persistence_error=str(exc),
                    reason="Could not persist import manifest: " + str(exc),
                )
            write_import_report(output, report)
        finally:
            if not db_closed:
                connection.close()

    return report


def write_import_report(output, report):
    rows = "".join(
        (
            "<tr><td>"
            + escape(f["name"])
            + "</td><td>"
            + escape(f["status"])
            + "</td><td>"
            + str(f["accepted"])
            + "</td><td>"
            + str(f["rejected"])
            + "</td><td>"
            + escape(f.get("error", ""))
            + "</td></tr>"
            for f in report["files"]
        ),
    )
    html = '<!doctype html><html lang="en"><meta charset="utf-8"><title>totenkahn evidence import</title>'
    html += "<h1>Evidence import: " + escape(report["status"]) + "</h1>"
    html += "<p>Import quality only. No detection, threat or coverage certification.</p>"
    if report.get("reason"):
        html += "<p>Reason: " + escape(report["reason"]) + "</p>"
    html += "<pre>" + escape(json.dumps(report["quality"], indent=2, ensure_ascii=False)) + "</pre>"
    html += (
        "<p>Recovery: " + escape(json.dumps(report["recovery"], ensure_ascii=False)) + "</p>"
        if report.get("recovery")
        else ""
    )
    html += (
        "<table><tr><th>File</th><th>Status</th><th>Accepted</th><th>Rejected</th><th>Reason</th></tr>"
        + rows
        + "</table>"
    )
    html += '<p>Original files and mapping snapshots are listed in <a href="manifest.json">manifest.json</a>.</p></html>'
    (output / "report.html").write_text(html, encoding="utf-8")


def quality(connection):
    count = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    times = connection.execute("SELECT min(time_utc),max(time_utc) FROM events").fetchone()
    duplicate = connection.execute(
        "SELECT coalesce(sum(n-1),0) FROM (SELECT count(*) n FROM events GROUP BY fingerprint HAVING count(*)>1)",
    ).fetchone()[0]
    warnings = connection.execute("SELECT count(*) FROM events WHERE warnings != '[]'").fetchone()[
        0
    ]
    categories = Counter()
    field_quality = {}

    for (encoded,) in connection.execute("SELECT mapping FROM events"):
        for field, trace in json.loads(encoded).items():
            states = field_quality.setdefault(field, Counter())
            states[trace.get("state", "value" if trace.get("present") else "missing")] += 1

    for row in connection.execute("SELECT warnings FROM events WHERE warnings != '[]'"):
        categories.update(json.loads(row[0]))

    return {
        "warning_counts": dict(categories),
        "field_states": {field: dict(states) for field, states in field_quality.items()},
        "events": count,
        "events_with_warnings": warnings,
        "possible_duplicate_occurrences": duplicate,
        "first_time_utc": times[0],
        "last_time_utc": times[1],
        "hosts": [
            list(row)
            for row in connection.execute(
                "SELECT host,count(*) FROM events GROUP BY host ORDER BY count(*) DESC LIMIT 100",
            )
        ],
        "event_types": [
            list(row)
            for row in connection.execute(
                "SELECT kind,count(*) FROM events GROUP BY kind ORDER BY count(*) DESC LIMIT 100",
            )
        ],
        "summary_limit": 100,
        "duplicate_policy": "All occurrences retained; same content is not proof of same activity",
    }


def read_index(dataset):
    dataset = Path(dataset).resolve()
    manifest = DECODER.decode((dataset / "manifest.json").read_text(encoding="utf-8"))

    if manifest.get("schema_version") != 1 or "index_sha256" not in manifest:
        raise ValueError("Dataset is incomplete or uses an unsupported schema")

    index = dataset / "index.sqlite"

    if index.is_symlink() or not index.resolve().is_relative_to(dataset):
        raise ValueError("Unsafe index path")

    uri = index.as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.execute("PRAGMA query_only=ON")

    if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
        connection.close()

        raise ValueError("Unsupported index version")

    return (connection, manifest)


def inspect_dataset(
    dataset,
    *,
    host=None,
    event_type=None,
    text=None,
    start=None,
    end=None,
    limit=50,
    after=0,
    row_id=None,
):
    if not 1 <= limit <= 500 or after < 0:
        raise ValueError("limit must be 1..500 and after must be nonnegative")

    connection, manifest = read_index(dataset)

    try:
        if start is not None and end is not None:
            start_time, start_issue = parse_time(start)
            end_time, end_issue = parse_time(end)

            if (
                start_issue
                or end_issue
                or (start_time is None)
                or (end_time is None)
                or (start_time > end_time)
            ):
                raise ValueError("Invalid time interval")

        filters = ["row_id > ?"]
        parameters: list[object] = [after]

        for column, value in [("host", host), ("kind", event_type), ("row_id", row_id)]:
            if value is not None:
                filters.append(column + " = ?")
                parameters.append(value)

        for operator, value in [(">=", start), ("<=", end)]:
            if value is not None:
                timestamp, issue = parse_time(value)

                if issue:
                    raise ValueError("Time filters require valid ISO-8601 timestamps with timezone")

                filters.append("time_utc " + operator + " ?")
                parameters.append(timestamp)

        if text is not None:
            filters.append("instr(lower(raw),lower(?)) > 0")
            parameters.append(text)

        cursor = connection.execute(
            "SELECT row_id,event_id,file_id,ordinal,normalized,locator,mapping,warnings,raw FROM events WHERE "
            + " AND ".join(filters)
            + " ORDER BY row_id LIMIT ?",
            [*parameters, limit + 1],
        )
        more = False
        items = []

        for number, row in enumerate(cursor):
            if number == limit:
                more = True
                break

            normalized = json.loads(row[4])
            item = {
                "row_id": row[0],
                "event_id": row[1],
                "file_id": row[2],
                "ordinal": row[3],
                "event": normalized,
                "locator": json.loads(row[5]),
                "mapping": json.loads(row[6]),
                "warnings": json.loads(row[7]),
            }

            if row_id is not None:
                item["raw"] = row[8]
                item["source"] = next((f for f in manifest["files"] if f["file_id"] == row[2]))
            else:
                normalized.pop("fields", None)
                truncated = []

                for key, value in list(normalized.items()):
                    if isinstance(value, (dict, list)) or (
                        isinstance(value, str) and len(value) > 1024
                    ):
                        normalized[key] = str(value)[:1024]
                        truncated.append(key)

                item["preview_only"] = True
                item["truncated_fields"] = truncated

            items.append(item)

        return {
            "status": "passed",
            "dataset_status": manifest["status"],
            "integrity": "not_checked_use_dump_verify",
            "items": items,
            "next_after": items[-1]["row_id"] if more else None,
            "query_limit": limit,
            "coverage": "Imported records only; missing timestamps excluded by time filters",
        }
    finally:
        connection.close()


def verify_dataset(dataset):
    dataset = Path(dataset).resolve()
    manifest = DECODER.decode((dataset / "manifest.json").read_text(encoding="utf-8"))
    issues = []

    for entry in manifest["files"]:
        if "sha256" not in entry:
            issues.append({"file": entry["name"], "reason": "No confirmed snapshot hash"})
            continue

        path = dataset / entry["stored"]

        if path.is_symlink() or not path.resolve().is_relative_to(dataset):
            issues.append({"file": entry["name"], "reason": "Unsafe stored path"})
            continue

        if not path.is_file() or file_hash(path) != entry["sha256"]:
            issues.append({"file": entry["name"], "reason": "Original missing or changed"})

        if "expanded" in entry:
            expanded = dataset / entry["expanded"]["stored"]

            if (
                expanded.is_symlink()
                or not expanded.resolve().is_relative_to(dataset)
                or not expanded.is_file()
                or file_hash(expanded) != entry["expanded"]["sha256"]
            ):
                issues.append(
                    {"file": entry["name"], "reason": "Expanded gzip evidence missing or changed"}
                )

    index = dataset / "index.sqlite"

    if (
        index.is_symlink()
        or (not index.is_file())
        or (file_hash(index) != manifest.get("index_sha256"))
    ):
        issues.append({"file": "index.sqlite", "reason": "Index missing or changed"})

    return {
        "status": "failed" if issues else "passed",
        "dataset_status": manifest["status"],
        "issues": issues,
        "scope": "Integrity against local manifest; no authenticated custody or coverage claim",
    }


def list_issues(dataset, *, after=0, limit=50):
    if not 1 <= limit <= 500 or after < 0:
        raise ValueError("limit must be 1..500 and after nonnegative")

    connection, manifest = read_index(dataset)

    try:
        rows = connection.execute(
            "SELECT rowid,file_id,ordinal,locator,reason FROM issues WHERE rowid > ? ORDER BY rowid LIMIT ?",
            (after, limit + 1),
        ).fetchall()
        items = [
            {
                "issue_id": r[0],
                "file_id": r[1],
                "ordinal": r[2],
                "locator": json.loads(r[3]),
                "reason": r[4],
            }
            for r in rows[:limit]
        ]

        return {
            "status": "passed",
            "dataset_status": manifest["status"],
            "items": items,
            "next_after": items[-1]["issue_id"] if len(rows) > limit else None,
        }
    finally:
        connection.close()


def preview_source(source, *, profile=None, limit=5, reader_options=None):
    source = Path(source)

    if not 1 <= limit <= 20:
        raise ValueError("Preview limit must be 1..20")

    if source.is_symlink() or not source.is_file():
        raise ValueError("Preview requires one regular source file")

    reader_options = input_options(**(reader_options or {}))
    kind = source.suffix.lower().lstrip(".")
    chosen = (
        PROFILES["windows-xml-v1"] if kind == "xml" else profile_for(profile) if profile else None
    )

    if kind not in {"xml", "json", "jsonl", "ndjson", "csv", "tsv"}:
        raise ValueError(
            "Preview supports XML/JSON/JSONL/CSV/TSV; for gzip/EVTX use import then dump show"
        )

    if chosen is None:
        raise ValueError("JSON preview requires an explicit profile")

    records = (
        xml_records(source)
        if kind == "xml"
        else (
            tabular_records(source, kind, reader_options)
            if kind in {"csv", "tsv"}
            else json_records(
                source, lines=kind in {"jsonl", "ndjson"}, splunk=chosen["id"].startswith("splunk")
            )
        )
    )
    samples = []

    try:
        for row in records:
            try:
                if "error" in row:
                    raise ValueError(row["error"])

                event, mapping, warnings = normalize(row["record"], chosen)

                if "original_cells" in row:
                    for trace in mapping.values():
                        path = trace.get("path", [])

                        if path and path[0] in row["original_cells"]:
                            trace["original_cell"] = row["original_cells"][path[0]]

                            if trace["original_cell"] == reader_options["null_value"]:
                                trace["input_conversion"] = "explicit_tabular_null_token"

                samples.append(
                    {
                        "status": "passed_with_warnings" if warnings else "passed",
                        "locator": row["locator"],
                        "event": event,
                        "mapping": mapping,
                        "warnings": warnings,
                    }
                )
            except (ValueError, TypeError, KeyError) as exc:
                samples.append(
                    {"status": "error", "locator": row.get("locator"), "reason": str(exc)}
                )

            if len(samples) >= limit:
                break
    finally:
        records.close()

    good = any(item["status"] in {"passed", "passed_with_warnings"} for item in samples)

    return {
        "status": (
            "passed_with_warnings"
            if good and any(item["status"] != "passed" for item in samples)
            else "passed" if good else "error"
        ),
        "source": str(source.resolve()),
        "profile": chosen,
        "reader_options": reader_options,
        "samples": samples,
        "sample_limit": limit,
        "scope": "Read-only sampled mapping preview; not full import, integrity or coverage verification",
    }
