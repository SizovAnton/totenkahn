"""Evaluate candidate rule data against an immutable baseline evidence contract."""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
from importlib.metadata import version
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

from handlers.ci import run_ci
from handlers.cli_result import status_code
from handlers.component_inventory import reject_duplicate_keys, reject_json_constant

MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, timeout=30, check=False
    )
    if result.returncode:
        raise ValueError("Git object unavailable or command failed: " + args[0])
    return result.stdout


def commit_id(repo, value):
    if not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        raise ValueError("Supply a full immutable commit SHA, not a branch or abbreviated ID")
    resolved = git(repo, "rev-parse", "--verify", value + "^{commit}").decode().strip()
    if resolved.lower() != value.lower():
        raise ValueError("Reference must identify a commit directly")
    return resolved


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("Expected a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in {".", ".."} for p in value.split("/")):
        raise ValueError("Paths cannot escape the reviewed contract directory")
    if any(ord(c) < 32 for c in value):
        raise ValueError("Control characters are not allowed in paths")
    return path.as_posix()


def tree(repo, commit, path):
    entries = {}
    raw = git(repo, "ls-tree", "-r", "-z", commit, "--", ":(literal)" + path)
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, oid = header.decode().split()
        name = name.decode("utf-8")
        relative_path(name)
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("Only regular Git blobs are allowed; no links or submodules")
        entries[name] = oid
    if not entries:
        raise ValueError("Reviewed path is absent in Git revision: " + path)
    return entries


def blob(repo, oid):
    size = int(git(repo, "cat-file", "-s", oid))
    if size > MAX_BLOB:
        raise ValueError("Git input exceeds the per-file size limit")
    return git(repo, "cat-file", "blob", oid)


def read_json(path):
    return json.loads(
        path.read_text(encoding="utf-8-sig"),
        object_pairs_hook=reject_duplicate_keys, parse_constant=reject_json_constant,
    )


def confined(root, parent, value):
    relative_path(value)
    target = (parent / value).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("Evidence reference escapes the reviewed contract")
    return target


def validate_suite(root, suite):
    data = read_json(suite)
    if data.get("schema_version") != 1:
        raise ValueError("Revision gate currently requires a saved-session suite v1")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Reviewed suite must contain cases")
    expectations = set()
    for case in cases:
        test = read_json(confined(root, suite.parent, case["test_case"]))
        session = confined(root, suite.parent, case["session"])
        if not (session / "events.json").is_file():
            raise ValueError("Reviewed session events are missing")
        expected = test.get("expectation", {}).get("expected_rule_match")
        if type(expected) is not bool:
            raise ValueError("Each reviewed case needs an explicit boolean expectation")
        expectations.add(expected)
    if expectations != {False, True}:
        raise ValueError("Both positive and negative controls are required")


def field_readiness(snapshot, suite_path, rules):
    from handlers.dump_analysis import required_fields
    from handlers.file_handlers import load_sigma_rule
    from handlers.matching import value_supported

    issues = []
    suite = read_json(suite_path)
    for label, rule_path in rules.items():
        rule = load_sigma_rule(rule_path)
        if not isinstance(rule, dict):
            raise ValueError("Rule must be a YAML object")
        requirements = required_fields(rule)
        for entry in suite["cases"]:
            case = read_json(confined(snapshot, suite_path.parent, entry["test_case"]))
            session = confined(snapshot, suite_path.parent, entry["session"])
            selected = set(case["evidence"]["record_ids"])
            for event in read_json(session / "events.json"):
                if event["record_id"] not in selected:
                    continue
                for name, expected in rule["logsource"].items():
                    if name != "definition" and event.get("source", {}).get(name) is None:
                        issues.append({"rule": label, "case": case["case_id"], "record_id": event["record_id"],
                                       "field": "logsource." + name, "reason": "Source identity is unknown for the requested rule"})
                for name, checks in requirements.items():
                    values = event if name == "EventID" else event["data_fields"]
                    key = "event_id" if name == "EventID" else name
                    if any(not value_supported(values.get(key), check["expected"], check["modifiers"], key in values) for check in checks):
                        issues.append({"rule": label, "case": case["case_id"], "record_id": event["record_id"], "field": name,
                                       "reason": "Missing or unsupported field for the requested comparison"})
    return issues


def evaluate_revisions(repo, baseline, candidate, contract, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1, "status": "error", "decision": "not_evaluated",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": "versioned_rule_on_frozen_baseline_evidence",
        "atomic_tests_executed": 0,
        "limitations": ["No endpoint actions or Elastic access", "Candidate code and candidate expectations are not executed or adopted"],
    }
    try:
        repo = Path(repo).resolve()
        baseline = commit_id(repo, baseline)
        candidate = commit_id(repo, candidate)
        contract = relative_path(contract)
        prefix = PurePosixPath(contract).parent.as_posix()
        if prefix == ".":
            raise ValueError("Contract must be in a dedicated subdirectory")
        report.update(baseline_commit=baseline, candidate_commit=candidate, contract_path=contract)
        snapshot = output / "baseline-inputs"
        hashes = {}
        total = 0
        entries = tree(repo, baseline, prefix)
        if len(entries) > 500:
            raise ValueError("Too many files in the contract directory")
        for name, oid in entries.items():
            relative = PurePosixPath(name).relative_to(prefix).as_posix()
            payload = blob(repo, oid)
            total += len(payload)
            if total > MAX_TOTAL:
                raise ValueError("Contract snapshot exceeds total size limit")
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            hashes[relative] = {"git_blob": oid, "sha256": sha256(payload).hexdigest()}
        definition = read_json(snapshot / PurePosixPath(contract).name)
        if set(definition) != {"schema_version", "rule", "suite", "mapping", "gates"} or definition["schema_version"] != 1:
            raise ValueError("Invalid versioned rule contract")
        for key in ("rule", "suite", "mapping"):
            relative_path(definition[key])
        rule_name = prefix + "/" + definition["rule"]
        candidate_entries = tree(repo, candidate, rule_name)
        if set(candidate_entries) != {rule_name}:
            raise ValueError("Candidate rule must be a regular file")
        candidate_bytes = blob(repo, candidate_entries[rule_name])
        (output / "candidate.yaml").write_bytes(candidate_bytes)
        validate_suite(snapshot, snapshot / definition["suite"])
        mapping = read_json(snapshot / definition["mapping"])
        from handlers.dump_analysis import load_mapping
        load_mapping(snapshot / definition["mapping"])
        engine = Path(__file__).resolve().parents[1]
        engine_files = {}
        for directory in ("handlers", "reporting", "rule_condition"):
            for file in sorted((engine / directory).glob("*.py")):
                engine_files[file.relative_to(engine).as_posix()] = sha256(file.read_bytes()).hexdigest()
        report.update(
            inputs=hashes, candidate_rule={"path": rule_name, "git_blob": candidate_entries[rule_name], "sha256": sha256(candidate_bytes).hexdigest()},
            engine_files_sha256=engine_files,
            runtime={"python": sys.version, "PyYAML": version("PyYAML"), "rich": version("rich")},
            baseline_policy="Suite, mapping and gates are read only from the baseline commit",
            mapping=mapping,
        )
        config = {
            "schema_version": 1, "gates": definition["gates"],
            "jobs": [{"id": "versioned-rule", "suite": "baseline-inputs/" + definition["suite"],
                      "baseline": "baseline-inputs/" + definition["rule"], "candidate": "candidate.yaml"}],
        }
        (output / "pipeline.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        result = run_ci(output / "pipeline.json", output / "evaluation")
        jobs = result["jobs"]
        counts = jobs[0].get("counts", {})
        baseline_ok = bool(jobs[0].get("cases")) and all(c["baseline"]["status"] == "met" for c in jobs[0].get("cases", []))
        issues = []
        if result["status"] != "error":
            issues = field_readiness(snapshot, snapshot / definition["suite"],
                                     {"baseline": snapshot / definition["rule"], "candidate": output / "candidate.yaml"})
        report["field_issues"] = issues
        report["evaluation_provisional"] = bool(issues)
        if issues:
            report.update(status="needs_verification", decision="insufficient_evidence", reason="Rule fields cannot be fully evaluated; raw comparison is provisional")
        elif not baseline_ok and result["status"] != "error":
            report.update(status="needs_verification", decision="baseline_not_accepted", reason="The baseline must satisfy every reviewed control")
        elif counts.get("insufficient", 0):
            report.update(status="needs_verification", decision="insufficient_evidence", reason="At least one rule comparison lacks sufficient evidence")
        else:
            report.update(status=result["status"], decision={"passed": "candidate_accepted", "failed": "candidate_rejected"}.get(result["status"], "execution_error"))
        report.update(counts=counts, evaluation="evaluation/report.json", evaluation_sha256=sha256((output / "evaluation/report.json").read_bytes()).hexdigest())
        if report["status"] == "passed":
            bundle = output / "live-bundle"
            bundle.mkdir()
            files = {"baseline.yaml": (snapshot / definition["rule"]).read_bytes(), "candidate.yaml": candidate_bytes,
                     "mapping.json": (snapshot / definition["mapping"]).read_bytes()}
            for name, content in files.items():
                (bundle / name).write_bytes(content)
            manifest = {"schema_version": 1, "baseline_commit": baseline, "candidate_commit": candidate,
                        "contract": contract, "contract_sha256": hashes[PurePosixPath(contract).name]["sha256"],
                        "files": {name: sha256(content).hexdigest() for name, content in files.items()},
                        "offline_gate": "passed", "scope": "two_controlled_process_markers_not_general_detection_coverage"}
            (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status="error", decision="execution_error", reason=str(exc), error_type=type(exc).__name__)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / "index.html").write_text(
        '<!doctype html><meta charset="utf-8"><title>Rule revision gate</title><h1>Rule revision gate</h1><pre>'
        + escape(json.dumps(report, indent=2, ensure_ascii=False))
        + '</pre><a href="evaluation/report.html">Rule decisions and evidence</a>', encoding="utf-8",
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare immutable rule revisions against baseline-controlled saved evidence; no network or endpoint actions.")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--baseline", required=True, help="Full baseline commit SHA")
    parser.add_argument("--candidate", required=True, help="Full candidate commit SHA")
    parser.add_argument("--contract", default="examples/rule-ci/contract.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = evaluate_revisions(args.repo, args.baseline, args.candidate, args.contract, args.output_dir)
    print(json.dumps({k: report.get(k) for k in ("status", "decision", "baseline_commit", "candidate_commit", "reason", "counts")}, indent=2))
    return 1 if report["status"] == "failed" else status_code(report["status"])
