import json
from pathlib import Path
from uuid import uuid4
from handlers.case_store import (
    case_lock,
    load_case,
    verify_case,
    attachment_paths,
    safe_file,
    copy_checked,
)
from handlers.component_inventory import utc_now
from handlers.dump_analysis import load_mapping, required_fields, evaluate_row
from handlers.dump_readers import DECODER
from handlers.evidence import canonical, digest, file_hash
from handlers.file_handlers import load_configuration, load_sigma_rule
from handlers.finding_store import verify_finding_refs
from handlers.matching import validate_rule


def read_rule(path):
    path = Path(path)
    rule, snapshot = load_sigma_rule(path, with_snapshot=True)
    validate_rule(rule)

    if (set(rule["logsource"]) - {"product", "service", "category", "definition"}) or any(
        (not isinstance(v, str) for v in rule["logsource"].values())
    ):
        raise ValueError("Unsupported rule logsource")

    if file_hash(path) != snapshot["sha256"]:
        raise ValueError("Rule changed during snapshot")

    return (rule, snapshot)


def select_findings(case, names):
    if not isinstance(names, list) or not names or len(names) != len(set(names)):
        raise ValueError("Choose unique finding names explicitly")

    by_name = {finding["name"]: finding for finding in case.get("findings", [])}

    if any((name not in by_name for name in names)):
        raise ValueError("Unknown finding name")

    findings = [by_name[name] for name in names]
    decisions = {}
    total = 0

    for finding in findings:
        for ref in finding["evidence"]:
            key = ref["event_id"]

            if key in decisions and decisions[key] != finding["expected_match"]:
                raise ValueError("Conflicting expectations for the same evidence occurrence")

            decisions[key] = finding["expected_match"]
            total += 1

    if total > 500:
        raise ValueError(
            "A curated finding suite supports at most 500 selected evidence references"
        )

    return findings


def case_files(root, case):
    files = {root / "case.json"}

    for attachment in case["attachments"]:
        dataset, selection = attachment_paths(root, attachment)
        manifest = DECODER.decode((dataset / "manifest.json").read_text(encoding="utf-8"))
        files.update(
            (
                dataset / "manifest.json",
                dataset / "index.sqlite",
                selection / "selection.json",
                selection / "members.jsonl",
            ),
        )
        files.update((safe_file(dataset, item["stored"]) for item in manifest["files"]))
        files.update(
            safe_file(dataset, item["expanded"]["stored"])
            for item in manifest["files"]
            if "expanded" in item
        )

    return sorted(files)


def export_suite(project, root, names, baseline, candidate, output, mapping_path=None):
    root, output = (Path(root).resolve(), Path(output).resolve())

    if output.is_relative_to(root):
        raise ValueError("Regression bundle must be outside the case")

    mapping = load_mapping(mapping_path)
    configuration = load_configuration(
        Path(project) / "config/default.config",
        Path(project) / "config/config.json",
    )
    rules = {
        label: (Path(path), read_rule(path)[1])
        for label, path in (("baseline", baseline), ("candidate", candidate))
    }

    with case_lock(root):
        verify_case(root)
        case = load_case(root)
        findings = select_findings(case, names)
        verify_finding_refs(root, case, findings)
        original_hash = file_hash(root / "case.json")
        output.mkdir(parents=True, exist_ok=False)
        (output / "EXPORT-INCOMPLETE.txt").write_text(
            "Export in progress; do not use this bundle.",
            encoding="utf-8",
        )

        try:
            pinned = {}

            for path in case_files(root, case):
                relative = "case/" + path.relative_to(root).as_posix()
                checksum = file_hash(path)
                copy_checked(path, output / relative, checksum)
                pinned[relative] = checksum

            for name, value in [("mapping.json", mapping), ("source-config.json", configuration)]:
                (output / name).write_text(
                    json.dumps(value, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                pinned[name] = file_hash(output / name)

            for label, (path, snapshot) in rules.items():
                copy_checked(path, output / (label + ".yaml"), snapshot["sha256"])

            suite = {
                "schema_version": 2,
                "suite_id": "findings-" + uuid4().hex[:12],
                "description": "Reviewed per-event expectations on immutable case evidence",
                "case_dir": "case",
                "findings": names,
                "mapping": "mapping.json",
                "configuration": "source-config.json",
                "integrity": "evidence-lock.json",
            }
            (output / "suite.json").write_text(
                json.dumps(suite, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            pinned["suite.json"] = file_hash(output / "suite.json")
            lock = {
                "schema_version": 1,
                "created_at": utc_now(),
                "source_case_sha256": original_hash,
                "files": pinned,
                "initial_rules": {
                    label: snapshot["sha256"] for label, (_, snapshot) in rules.items()
                },
                "scope": "Evidence/mapping/configuration pinned; baseline and candidate deliberately editable and snapshotted at each run",
            }
            lock["sha256"] = digest(canonical(lock))
            (output / "evidence-lock.json").write_text(
                json.dumps(lock, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            pipeline = {
                "schema_version": 1,
                "gates": {
                    "max_regressed": 0,
                    "max_not_met": 0,
                    "max_insufficient": 0,
                    "min_cases": len(findings),
                },
                "jobs": [
                    {
                        "id": "reviewed-findings",
                        "suite": "suite.json",
                        "baseline": "baseline.yaml",
                        "candidate": "candidate.yaml",
                    },
                ],
            }
            (output / "pipeline.json").write_text(json.dumps(pipeline, indent=2), encoding="utf-8")
            verify_case(root)
            verify_case(output / "case")

            if file_hash(root / "case.json") != original_hash:
                raise ValueError("Case changed during export")

            (output / "README.txt").write_text(
                """Finding regression bundle. Run: totenkahn.exe ci --config pipeline.json --output-dir NEW_DIR
Edit candidate.yaml to test a rule change; never edit pinned evidence/mapping/expectations. Re-export for a reviewed change.
Includes the full case and all attached originals, not only selected rows; review data before sharing.
Each selected event must meet the explicit expected decision. Missing compatibility or partial dataset is insufficient, never a successful negative.
Local hashes are not signatures. No live collection or Atomic is executed.
""",
                encoding="utf-8",
            )
            (output / "EXPORT-INCOMPLETE.txt").unlink()

            return {
                "status": "passed",
                "output": str(output),
                "pipeline": str(output / "pipeline.json"),
                "findings": len(findings),
                "selected_events": sum((len(f["evidence"]) for f in findings)),
                "scope": "Export completed; expectations are not automatically validated or inferred from the current rule",
            }
        except BaseException:
            (output / "EXPORT-INCOMPLETE.txt").write_text(
                "Export did not complete. Do not use this directory as a regression bundle. Export again to a new directory.",
                encoding="utf-8",
            )

            raise


def load_evidence_suite(suite_path):
    path = Path(suite_path).resolve()
    root = path.parent

    if (root / "EXPORT-INCOMPLETE.txt").exists():
        raise ValueError("Evidence bundle export is incomplete")

    suite = DECODER.decode(path.read_text(encoding="utf-8-sig"))

    if (not isinstance(suite, dict)) or (
        set(suite)
        != {
            "schema_version",
            "suite_id",
            "description",
            "case_dir",
            "findings",
            "mapping",
            "configuration",
            "integrity",
        }
    ):
        raise ValueError("Invalid evidence regression suite")

    if type(suite["schema_version"]) is not int or suite["schema_version"] != 2:
        raise ValueError("Unsupported evidence suite version")

    if any(
        (
            not isinstance(suite[k], str) or not suite[k].strip()
            for k in ("suite_id", "description")
        ),
    ):
        raise ValueError("Evidence suite identity is required")

    lock_path = safe_file(root, suite["integrity"])
    lock = DECODER.decode(lock_path.read_text(encoding="utf-8"))

    if (lock.get("schema_version") != 1) or (
        lock.get("sha256") != digest(canonical({k: v for k, v in lock.items() if k != "sha256"}))
    ):
        raise ValueError("Evidence integrity contract changed")

    for relative, expected in lock["files"].items():
        if file_hash(safe_file(root, relative)) != expected:
            raise ValueError("Pinned evidence file changed: " + relative)

    case_root = safe_file(root, suite["case_dir"])
    case = load_case(case_root)
    required = {path.relative_to(root).as_posix(), suite["mapping"], suite["configuration"]}
    required.update((p.relative_to(root).as_posix() for p in case_files(case_root, case)))

    if set(lock["files"]) != required:
        raise ValueError("Evidence lock must cover every case, mapping and configuration input")

    if file_hash(case_root / "case.json") != lock["source_case_sha256"]:
        raise ValueError("Source case identity changed")

    verification = verify_case(case_root)
    findings = select_findings(case, suite["findings"])
    mapping = load_mapping(safe_file(root, suite["mapping"]))
    configuration = DECODER.decode(
        safe_file(root, suite["configuration"]).read_text(encoding="utf-8")
    )

    return (suite, case_root, case, findings, mapping, configuration, verification, lock)


def run_evidence_regression(suite_path, baseline_path, candidate_path):
    from reporting.regression import classify_comparison

    suite, root, case, findings, mapping, configuration, verification, lock = load_evidence_suite(
        suite_path
    )
    loaded = verify_finding_refs(root, case, findings)
    rules = {
        label: read_rule(path)
        for label, path in (("baseline", baseline_path), ("candidate", candidate_path))
    }
    report = {
        "schema_version": 1,
        "report_type": "evidence_regression",
        "Report ID": str(uuid4()),
        "created_at": utc_now(),
        "status": "completed",
        "suite": suite,
        "suite_path": str(Path(suite_path).resolve()),
        "case_id": case["case_id"],
        "case_sha256": file_hash(root / "case.json"),
        "rules": {label: snapshot for label, (_, snapshot) in rules.items()},
        "mapping": mapping,
        "configuration": configuration,
        "evidence_lock": lock,
        "cases": [],
        "summary": {
            key: 0
            for key in (
                "improved",
                "regressed",
                "unchanged_met",
                "unchanged_not_met",
                "insufficient_data",
            )
        },
        "limitations": verification["limitations"],
        "basis": "Same pinned case records, explicit per-event expectations and mapping for both Sigma rules; no live collection, Atomic or external alert claim",
    }

    for finding in findings:
        item = {
            "case_id": finding["name"],
            "finding": finding,
            "events": [],
            "test_case": {"expectation": {"expected_rule_match": finding["expected_match"]}},
        }

        for ref in finding["evidence"]:
            _, row, source, attachment = loaded[ref["attachment"], ref["row_id"]]
            evaluations = {}

            for label, (rule, _) in rules.items():
                evaluations[label] = evaluate_row(
                    row, source, rule, mapping, configuration, required_fields(rule)
                )

            item["events"].append(
                {
                    "reference": ref,
                    "attachment_label": attachment["label"],
                    "dataset_status": attachment["dataset_status"],
                    **evaluations,
                },
            )

        for label in ("baseline", "candidate"):
            decisions = [record[label]["status"] for record in item["events"]]
            sufficient = all((d in {"match", "no_match"} for d in decisions)) and all(
                (r["dataset_status"] in {"passed", "passed_with_warnings"} for r in item["events"])
            )
            expected = "match" if finding["expected_match"] else "no_match"
            met = all((d == expected for d in decisions))
            status = "insufficient_data" if not sufficient else "met" if met else "not_met"
            item[label] = {
                "status": status,
                "expected_rule_match": finding["expected_match"],
                "selected_event_count": len(decisions),
                "selected_results": {key: decisions.count(key) for key in sorted(set(decisions))},
                "reason": (
                    "Compatibility or dataset completeness is insufficient"
                    if not sufficient
                    else (
                        "Every selected event met the expectation"
                        if met
                        else "At least one selected event violated the expectation"
                    )
                ),
                "rule_sha256": rules[label][1]["sha256"],
            }

        item["comparison"] = classify_comparison(item["baseline"], item["candidate"])
        report["summary"][item["comparison"]] += 1
        report["cases"].append(item)

    load_evidence_suite(suite_path)

    return report
