from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
from handlers.component_inventory import utc_now
from handlers.dump_readers import DECODER
from handlers.evidence_normalization import field_state
from handlers.evidence import canonical, digest, file_hash, read_index
from handlers.evidence_selection import (
    create_selection,
    load_selection,
    selected_rows,
    pointer,
)
from handlers.events import config_handler
from handlers.file_handlers import load_configuration, load_sigma_rule
from handlers.matching import report_handler, validate_rule, value_supported
from rule_condition.prepare import prepare_condition
from rule_condition.condition_operand_parsers import parse_condition
from rule_condition.collect_references import collect_references
from reporting.dump_report import EventPages, write_summary

ALIASES = {
    "CommandLine": "command_line",
    "ProcessId": "process_id",
    "ParentProcessId": "parent_process_id",
    "ProcessGuid": "process_guid",
    "User": "user",
}


def load_mapping(path):
    if path is None:
        return {"schema_version": 1, "id": "builtin-dump-v1", "logsource": {}, "fields": {}}

    value = DECODER.decode(Path(path).read_text(encoding="utf-8-sig"))

    if (not isinstance(value, dict)) or (
        set(value) != {"schema_version", "id", "logsource", "fields"}
    ):
        raise ValueError("Analysis mapping requires schema_version, id, logsource and fields")

    if (
        (type(value["schema_version"]) is not int)
        or (value["schema_version"] != 1)
        or (not isinstance(value["id"], str))
        or (not value["id"].strip())
    ):
        raise ValueError("Invalid mapping identity/version")

    source = value["logsource"]

    if not isinstance(source, dict) or set(source) - {"product", "service", "category"}:
        raise ValueError("Unsupported logsource mapping keys")

    if any((not isinstance(v, str) or not v.strip() for v in source.values())):
        raise ValueError("Declared logsource values must be nonempty strings")

    if not isinstance(value["fields"], dict):
        raise ValueError("fields must map Sigma names to JSON pointers")

    for key, path_value in value["fields"].items():
        if not isinstance(key, str) or not key.strip() or "|" in key:
            raise ValueError("Mapping keys must be unmodified Sigma field names")

        pointer({}, path_value)

    return value


def required_fields(rule):
    tree = prepare_condition(rule["detection"], parse_condition, collect_references)
    fields = {}

    for block in sorted(collect_references(tree)):
        for key, expected in rule["detection"][block].items():
            parts = key.split("|")
            fields.setdefault(parts[0], []).append({"modifiers": parts[1:], "expected": expected})

    return fields


def bridge_event(row, source_file, mapping, configuration, requirements):
    event = json.loads(row[4])
    import_mapping = json.loads(row[7])
    source = {}
    source_basis = "unknown"
    windows_source = (
        source_file["format"] in {"xml", "evtx"}
        or source_file.get("profile", {}).get("raw_format") == "windows_xml"
    )

    if windows_source:
        source = config_handler(
            event.get("channel"),
            event.get("provider"),
            configuration,
            event.get("event_id"),
        )
        source_basis = "Windows XML plus snapshotted source configuration"
    else:
        source = {"product": None, "service": None, "category": None}

    conflicts = list(event.get("normalization_conflicts", []))

    for key, value in mapping["logsource"].items():
        observed = source.get(key)

        if observed is not None and observed != value:
            conflicts.append({"field": key, "observed": observed, "declared": value})
        else:
            source[key] = value

    trace, fields, issues = ({}, {}, [])

    for name, existence_modes in requirements.items():
        if name in mapping["fields"]:
            path = mapping["fields"][name]
            basis = "explicit_analysis_mapping"
        elif name == "EventID":
            path, basis = ("/event_id", "canonical_event_id")
        elif name in ALIASES:
            path, basis = ("/" + ALIASES[name], "canonical_import_mapping")
        elif windows_source:
            path, basis = (
                (
                    "/decoded_raw/fields/"
                    if source_file.get("profile", {}).get("raw_format") == "windows_xml"
                    else "/fields/fields/"
                )
                + name.replace("~", "~0").replace("/", "~1"),
                "Windows EventData exact field name",
            )
        else:
            path, basis = (
                "/fields/" + name.replace("~", "~0").replace("/", "~1"),
                "JSON exact field name",
            )

        present, value = pointer(event, path)
        canonical_key = path[1:] if path.count("/") == 1 else None

        if canonical_key in import_mapping and (not import_mapping[canonical_key]["present"]):
            present, value = (False, None)

        trace[name] = {
            "path": path,
            "basis": basis,
            "present": present,
            "original_value": value,
            "conversion": "none",
            "state": field_state(present, value),
            "import_trace": import_mapping.get(canonical_key),
        }
        imported = import_mapping.get(canonical_key, {})

        if imported.get("state") in {"conversion_error", "conflict"}:
            trace[name]["state"] = imported["state"]
            issues.append(
                {"field": name, "reason": "Import conversion or source conflict requires review"}
            )

        for requirement in existence_modes:
            if not value_supported(
                value, requirement["expected"], requirement["modifiers"], present
            ):
                issues.append(
                    {
                        "field": name,
                        "reason": "Missing or unsupported value for the requested operator",
                        "operator": requirement["modifiers"],
                    }
                )

        converted = value

        if type(value) is int and all(
            not (set(req["modifiers"]) & {"gt", "gte", "lt", "lte"}) for req in existence_modes
        ):
            converted = str(value)
            trace[name]["conversion"] = "integer_to_decimal_string"

        if present:
            fields[name] = converted

    result = {
        "record_id": str(row[0]),
        "computer": event.get("host"),
        "channel": event.get("channel"),
        "provider": event.get("provider"),
        "system_time": event.get("time_utc"),
        "source": source,
        "data_fields": {k: v for k, v in fields.items() if k != "EventID"},
    }

    if "EventID" in fields:
        result["event_id"] = fields["EventID"]

    return (
        result,
        {
            "source": source,
            "source_basis": source_basis,
            "declared_logsource": mapping["logsource"],
            "source_conflicts": conflicts,
            "fields": trace,
            "field_issues": issues,
        },
    )


def evaluate_row(row, source_file, rule, mapping, configuration, requirements):
    item, compatibility = bridge_event(row, source_file, mapping, configuration, requirements)
    required_source = {
        key: value for key, value in rule["logsource"].items() if key != "definition"
    }
    unknown = [key for key in required_source if item["source"].get(key) is None]
    mismatch = [
        key
        for key, value in required_source.items()
        if item["source"].get(key) is not None and item["source"][key] != value
    ]
    evaluation = None

    if compatibility["source_conflicts"]:
        status, reason = (
            "insufficient_data",
            "Declared logsource or extracted fields conflict with source evidence",
        )
    elif mismatch:
        status, reason = ("not_applicable", "Known logsource values do not match this rule")
        evaluation = report_handler([item], rule)[0]
    elif unknown:
        status, reason = (
            "insufficient_data",
            "Logsource is unknown; provide a reviewed analysis mapping",
        )
    else:
        evaluation = report_handler([item], rule)[0]

        if compatibility["field_issues"] or evaluation["Selection"] is None:
            status, reason = (
                "insufficient_data",
                "Some referenced fields cannot be fully evaluated; engine result is provisional",
            )
        else:
            status = "match" if evaluation["Selection"] else "no_match"
            reason = evaluation["Selection Reason"]

    compatibility.update(unknown_logsource=unknown, mismatched_logsource=mismatch)

    return {
        "row_id": row[0],
        "event_id": row[1],
        "status": status,
        "reason": reason,
        "compatibility": compatibility,
        "engine_evaluation": evaluation,
        "engine_result_provisional": status == "insufficient_data" and evaluation is not None,
        "event": json.loads(row[4]),
        "raw": row[5],
        "locator": json.loads(row[6]),
        "import_mapping": json.loads(row[7]),
        "import_warnings": json.loads(row[8]),
        "source": {
            "file_id": row[2],
            "ordinal": row[3],
            "name": source_file["name"],
            "sha256": source_file["sha256"],
            "stored": source_file["stored"],
            "profile": source_file.get("profile"),
            "profile_sha256": source_file.get("profile_sha256"),
        },
    }


def readiness(connection, selection, saved, rule, mapping, configuration, requirements):
    fields = {name: Counter() for name in requirements}
    sources = Counter()
    total = eligible = 0

    for row in selected_rows(connection, selection, saved):
        total += 1
        item, compatibility = bridge_event(
            row, saved["sources"][row[2]], mapping, configuration, requirements
        )
        required = {k: v for k, v in rule["logsource"].items() if k != "definition"}

        if compatibility["source_conflicts"]:
            source_state = "conflict"
        elif any(
            item["source"].get(k) is not None and item["source"][k] != v
            for k, v in required.items()
        ):
            source_state = "not_applicable"
        elif any(item["source"].get(k) is None for k in required):
            source_state = "unknown"
        else:
            source_state = "compatible"

        sources[source_state] += 1

        for name, trace in compatibility["fields"].items():
            fields[name][trace["state"]] += 1

        if source_state == "compatible" and not compatibility["field_issues"]:
            eligible += 1

    return {
        "status": (
            "passed"
            if total
            and eligible == total
            and saved["dataset_status"] in {"passed", "passed_with_warnings"}
            else "needs_verification"
        ),
        "events": total,
        "fully_evaluable": eligible,
        "source_states": dict(sources),
        "fields": {name: dict(states) for name, states in fields.items()},
        "scope": "Suitability for this rule only; no matching executed during preflight",
        "dataset_status": saved["dataset_status"],
    }


def summary_reason(result, *, preflight=False):
    ready = result.get("readiness", {})
    counts = result.get("counts", {})
    parts = []
    if preflight:
        parts.append(
            f"Preflight only: {ready.get('fully_evaluable', 0)} of {ready.get('events', 0)} events fully evaluable; matching was not executed."
        )
    elif not sum(counts.values()):
        parts.append("No event decisions were produced.")
    else:
        parts.append(
            f"MATCH: {counts.get('match', 0)}; NO MATCH: {counts.get('no_match', 0)}; INSUFFICIENT DATA: {counts.get('insufficient_data', 0)}."
        )
        if counts.get("insufficient_data"):
            parts.append(
                "Some events could not be fully evaluated; this is not a confirmed negative result."
            )
    for field, states in ready.get("fields", {}).items():
        for state, count in states.items():
            if state not in {"value", "empty", "multivalue"} and count:
                parts.append(f"{field}: {state} in {count} event(s).")
    for state, count in ready.get("source_states", {}).items():
        if state != "compatible" and count:
            parts.append(f"Source suitability: {state} in {count} event(s).")
    if ready.get("dataset_status") not in {None, "passed", "passed_with_warnings"}:
        parts.append(
            f"Input dataset status: {ready['dataset_status']}; source coverage remains limited."
        )
    if not preflight:
        parts.append("See evidence pages for individual field checks and condition explanations.")
    return " ".join(parts)


def run_rule(
    connection,
    selection,
    saved,
    rule_path,
    output,
    mapping,
    configuration,
    progress=None,
    preflight_only=False,
):
    output.mkdir()
    result = {"path": str(rule_path), "status": "error", "counts": {}, "pages": []}
    counts = Counter()

    try:
        rule, snapshot = load_sigma_rule(rule_path, with_snapshot=True)
        result["rule"] = snapshot
        rule_bytes = Path(rule_path).read_bytes()

        if sha256(rule_bytes).hexdigest() != snapshot["sha256"]:
            raise ValueError("Rule changed during snapshot")

        (output / "rule.yaml").write_bytes(rule_bytes)
        validate_rule(rule)

        if set(rule["logsource"]) - {"product", "service", "category", "definition"}:
            raise ValueError("Unsupported logsource keys")

        if any((not isinstance(v, str) for v in rule["logsource"].values())):
            raise ValueError("Logsource values must be strings")

        requirements = required_fields(rule)
        result["required_fields"] = sorted(requirements)

        if progress:
            progress(f"{rule_path.name}: checking source and field suitability")

        result["readiness"] = readiness(
            connection, selection, saved, rule, mapping, configuration, requirements
        )

        if progress:
            progress(
                f"{rule_path.name}: {result['readiness']['fully_evaluable']}/{result['readiness']['events']} events fully evaluable"
            )

        if preflight_only:
            result.update(status=result["readiness"]["status"], scope="preflight_only_no_matching")
            result["reason"] = summary_reason(result, preflight=True)
            (output / "report.json").write_text(
                json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
            )

            return result

        with (
            (output / "events.jsonl").open("x", encoding="utf-8") as events,
            EventPages(output) as pages,
        ):
            try:
                for row in selected_rows(connection, selection, saved):
                    record = evaluate_row(
                        row, saved["sources"][row[2]], rule, mapping, configuration, requirements
                    )
                    events.write(canonical(record) + "\n")
                    pages.append(record)
                    counts[record["status"]] += 1

                    if progress and sum(counts.values()) % 1000 == 0:
                        progress(f"{rule_path.name}: {sum(counts.values())} events evaluated")
            finally:
                result["pages"] = pages.names

        assessed = counts["match"] + counts["no_match"]
        result["status"] = (
            "needs_verification" if not assessed or counts["insufficient_data"] else "passed"
        )
        result["scope"] = (
            "Rule decisions on selected evidence, not test expectations, threat verdicts or SIEM alerts"
        )
    except KeyboardInterrupt:
        result.update(
            status="interrupted",
            reason="Analysis interrupted; only completed records are included",
        )
    except Exception as exc:
        result.update(status="error", reason=str(exc), error_type=type(exc).__name__)

    result["counts"] = dict(counts)
    if not result.get("reason"):
        result["reason"] = summary_reason(result)

    if (output / "events.jsonl").is_file():
        result["events_sha256"] = file_hash(output / "events.jsonl")

    result["html_sha256"] = {
        name: file_hash(output / name) for name in result["pages"] if (output / name).is_file()
    }
    (output / "report.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def analyze_dump(
    project,
    dataset,
    output,
    *,
    rule=None,
    rules_dir=None,
    selection=None,
    filters=None,
    mapping_path=None,
    progress=None,
    preflight_only=False,
):
    if (rule is None) == (rules_dir is None):
        raise ValueError("Choose exactly one rule or rules directory")

    dataset, output = (Path(dataset).resolve(), Path(output).resolve())

    if selection is not None and filters:
        raise ValueError("Saved selection cannot be combined with new filters")

    mapping = load_mapping(mapping_path)
    configuration = load_configuration(
        Path(project) / "config/default.config",
        Path(project) / "config/config.json",
    )

    if rule is not None:
        paths = [Path(rule).resolve()]
    else:
        if rules_dir is None:
            raise ValueError("Rules directory is required")

        folder = Path(rules_dir).resolve()

        if not folder.is_dir() or output == folder or folder in output.parents:
            raise ValueError("Rules directory must exist and output must be outside it")

        paths = []

        def fail_walk(error):
            raise error

        for directory, subdirectories, filenames in os.walk(folder, onerror=fail_walk):
            if any(((Path(directory) / name).is_symlink() for name in subdirectories)):
                raise ValueError("Symlinked rule directories are unsupported")

            for name in filenames:
                path = Path(directory) / name

                if path.suffix.lower() in {".yaml", ".yml"}:
                    if path.is_symlink():
                        raise ValueError("Symlinked rules are unsupported")

                    paths.append(path)

        paths.sort()

    if not paths:
        raise ValueError("No YAML rules found")

    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "status": "error",
        "created_at": utc_now(),
        "rules": [],
        "engine_contract": "totenkahn_sigma_values_v2",
        "preflight_only": preflight_only,
        "mapping": mapping,
        "mapping_sha256": digest(canonical(mapping)),
        "source_configuration": configuration,
        "configuration_sha256": digest(canonical(configuration)),
        "limitations": [
            "No Atomic or live collection was executed.",
            "Match is not an external SIEM alert or confirmed threat.",
            "Missing or unsupported referenced values make engine decisions provisional.",
            "Explicit logsource mappings are engineer declarations, not sensor observations.",
        ],
    }
    connection = None

    try:
        if progress:
            progress("Verifying dataset and preparing evidence selection")

        local_selection = output / "selection"

        if selection is None:
            saved = create_selection(dataset, local_selection, filters or {})
        else:
            saved = load_selection(dataset, selection)
            local_selection.mkdir()
            shutil.copy2(Path(selection) / "selection.json", local_selection / "selection.json")
            shutil.copy2(Path(selection) / "members.jsonl", local_selection / "members.jsonl")
            load_selection(dataset, local_selection)

        report["selection"] = saved
        report["selection_manifest_sha256"] = file_hash(local_selection / "selection.json")
        connection, _ = read_index(dataset)

        for index, path in enumerate(paths, 1):
            folder_name = f"rule-{index:04d}"

            if progress:
                progress(
                    f"Analyzing rule {index}/{len(paths)}: {path.name}; events: {saved['count']}"
                )

            result = run_rule(
                connection,
                local_selection,
                saved,
                path,
                output / folder_name,
                mapping,
                configuration,
                progress,
                preflight_only,
            )
            result["directory"] = folder_name
            report["rules"].append(result)

            if result["status"] == "interrupted":
                break

        statuses = {r["status"] for r in report["rules"]}
        report["status"] = (
            "interrupted"
            if "interrupted" in statuses
            else (
                "error"
                if "error" in statuses
                else (
                    "needs_verification"
                    if (
                        ("needs_verification" in statuses)
                        or (saved["dataset_status"] not in {"passed", "passed_with_warnings"})
                    )
                    else "passed"
                )
            )
        )
        load_selection(dataset, local_selection)
    except KeyboardInterrupt:
        report.update(status="interrupted", reason="Analysis interrupted")
    except Exception as exc:
        report.update(status="error", reason=str(exc), error_type=type(exc).__name__)
    finally:
        if connection is not None:
            connection.close()

        report["finished_at"] = utc_now()
        write_summary(report, output)

    return report
