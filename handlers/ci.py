from handlers.cli_help import HelpfulParser
from displaying.results import emit_result

import argparse
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from handlers.component_inventory import reject_duplicate_keys, reject_json_constant
from reporting.regression import run_regression, save_regression_report

DEFAULT_GATES = {"max_regressed": 0, "max_not_met": 0, "max_insufficient": 0, "min_cases": 1}


def load_config(path):
    config = json.loads(
        path.read_text(encoding="utf-8-sig"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_json_constant,
    )

    if not isinstance(config, dict) or set(config) != {"schema_version", "gates", "jobs"}:
        raise ValueError("CI config requires exactly schema_version, gates and jobs")

    if type(config["schema_version"]) is not int or config["schema_version"] != 1:
        raise ValueError("Unsupported CI schema_version")

    gates = config["gates"]

    if not isinstance(gates, dict) or set(gates) - set(DEFAULT_GATES):
        raise ValueError("Unknown CI gate")

    gates = {**DEFAULT_GATES, **gates}

    if any((type(v) is not int or v < 0 for v in gates.values())) or gates["min_cases"] < 1:
        raise ValueError("Gate limits must be nonnegative integers; min_cases must be positive")

    jobs = config["jobs"]

    if not isinstance(jobs, list) or not jobs:
        raise ValueError("CI jobs must be a nonempty list")

    ids = set()

    for job in jobs:
        if not isinstance(job, dict) or set(job) != {"id", "suite", "baseline", "candidate"}:
            raise ValueError("Each job requires id, suite, baseline and candidate")

        if any((not isinstance(v, str) or not v.strip() for v in job.values())):
            raise ValueError("Job values must be nonempty strings")

        if job["id"] in ids:
            raise ValueError("Duplicate CI job id")

        ids.add(job["id"])

    return {**config, "gates": gates}


def assess(report, gates):
    cases = report["cases"]
    counts = {
        "regressed": sum((c["comparison"] == "regressed" for c in cases)),
        "not_met": sum((c["candidate"]["status"] == "not_met" for c in cases)),
        "insufficient": sum((c["comparison"] == "insufficient_data" for c in cases)),
        "cases": len(cases),
    }
    violations = [
        f"{key}={counts[key]} exceeds {gates['max_' + key]}"
        for key in ("regressed", "not_met", "insufficient")
        if counts[key] > gates["max_" + key]
    ]

    if counts["cases"] < gates["min_cases"]:
        violations.append(f"cases={counts['cases']} below {gates['min_cases']}")

    return (counts, violations)


def xml_text(value):
    return "".join(
        (
            (
                c
                if (
                    (c in "\t\n\r")
                    or (32 <= ord(c) <= 55295)
                    or (57344 <= ord(c) <= 65533)
                    or (65536 <= ord(c) <= 1114111)
                )
                else "�"
            )
            for c in str(value)
        ),
    )


def write_reports(report, output):
    root = ET.Element("testsuites")
    rows = []

    for job in report["jobs"]:
        cases = job.get("cases", [])
        suite = ET.SubElement(root, "testsuite", name=xml_text(job["id"]))
        failures = errors = skipped = 0

        for case in cases:
            node = ET.SubElement(
                suite,
                "testcase",
                name=xml_text(case["case_id"]),
                classname=xml_text(job["id"]),
            )
            reason = case["candidate"].get("reason", case["candidate"]["status"])

            if case["comparison"] == "insufficient_data":
                skipped += 1
                ET.SubElement(node, "skipped", message=xml_text(reason))
            elif case["candidate"]["status"] == "not_met" or case["comparison"] == "regressed":
                failures += 1
                ET.SubElement(node, "failure", message=xml_text(reason))

            ET.SubElement(node, "system-out").text = xml_text(json.dumps(case, ensure_ascii=False))

        gate = ET.SubElement(suite, "testcase", name="CI policy", classname=xml_text(job["id"]))

        if job["status"] == "error":
            errors += 1
            ET.SubElement(gate, "error", message=xml_text(job.get("reason", "Job incomplete")))
        elif job["status"] == "failed":
            failures += 1
            ET.SubElement(gate, "failure", message=xml_text("; ".join(job["violations"])))

        suite.attrib.update(
            tests=str(len(cases) + 1),
            failures=str(failures),
            errors=str(errors),
            skipped=str(skipped),
        )
        detail = (
            job.get("reason")
            or "; ".join(job.get("violations", []))
            or ("All configured gates passed" if job["status"] == "passed" else "Job incomplete")
        )
        link = (
            '<a href="' + escape(job["html"], quote=True) + '">Evidence and explanations</a>'
            if "html" in job
            else ""
        )
        rows.append(
            "<tr><td>"
            + escape(job["id"])
            + "</td><td>"
            + job["status"]
            + "</td><td>"
            + escape(detail)
            + "</td><td>"
            + link
            + "</td></tr>",
        )

    for key in ("tests", "failures", "errors", "skipped"):
        root.set(key, str(sum((int(s.get(key, "0")) for s in root))))

    ET.ElementTree(root).write(output / "junit.xml", encoding="utf-8", xml_declaration=True)
    (output / "report.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>TOTENKAHN CI</title><h1>TOTENKAHN CI: '
        + report["status"]
        + "</h1><p>Saved evidence only; no live readiness certification.</p><p>JUnit records raw case failures even when a configured threshold permits them.</p><pre>"
        + escape(json.dumps(report.get("gates", {}), indent=2))
        + "</pre><table><tr><th>Job</th><th>Status</th><th>Reason</th><th>Details</th></tr>"
        + "".join(rows)
        + "</table></html>",
        encoding="utf-8",
    )
    report["artifacts"] = {
        p.name: sha256(p.read_bytes()).hexdigest()
        for p in (output / "report.html", output / "junit.xml")
    }
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False),
        encoding="utf-8",
    )


def run_ci(config_path, output):
    config_path = Path(config_path).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema_version": 1,
        "report_type": "ci",
        "status": "error",
        "jobs": [],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "atomic_tests_executed": 0,
        "scope": "saved_evidence_only",
        "config": str(config_path),
    }

    try:
        config = load_config(config_path)
        report["config_sha256"] = sha256(config_path.read_bytes()).hexdigest()
        report["gates"] = config["gates"]

        for number, job in enumerate(config["jobs"], 1):
            item = {"id": job["id"], "status": "error"}
            report["jobs"].append(item)

            try:
                paths = [
                    (config_path.parent / job[key]).resolve()
                    for key in ("suite", "baseline", "candidate")
                ]
                result = run_regression(*paths)
                counts, violations = assess(result, config["gates"])
                json_path, html_path = save_regression_report(result, output / f"job-{number}")
                item.update(
                    status="failed" if violations else "passed",
                    counts=counts,
                    violations=violations,
                    cases=result["cases"],
                    json=json_path.relative_to(output).as_posix(),
                    html=html_path.relative_to(output).as_posix(),
                    report_sha256=sha256(json_path.read_bytes()).hexdigest(),
                    html_sha256=sha256(html_path.read_bytes()).hexdigest(),
                )
            except Exception as exc:
                item.update(reason=str(exc), error_type=type(exc).__name__)

        report["status"] = (
            "error"
            if any((j["status"] == "error" for j in report["jobs"]))
            else "failed" if any((j["status"] == "failed" for j in report["jobs"])) else "passed"
        )
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["jobs"].append(
            {
                "id": "interrupted",
                "status": "error",
                "reason": "CI interrupted; results incomplete",
            },
        )
    except Exception as exc:
        report["jobs"].append({"id": "configuration", "status": "error", "reason": str(exc)})

    write_reports(report, output)

    return report


def dispatch(arguments):
    if not arguments or arguments[0] != "ci":
        return None

    parser = HelpfulParser(
        prog="totenkahn ci",
        description="Noninteractive saved-evidence CI. Never prepares dependencies or runs Atomic.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory; existing evidence is never overwritten",
    )
    args = parser.parse_args(arguments[1:])
    report = run_ci(args.config, args.output_dir)
    summary = {"status": report["status"], "report": str(args.output_dir.resolve() / "report.json")}
    emit_result(
        summary,
        "CI / regression gates",
        json_output=args.json,
        human_payload={
            **summary,
            "gates": report.get("gates"),
            "jobs": [
                {
                    key: job[key]
                    for key in ("id", "status", "counts", "violations", "reason", "html")
                    if key in job
                }
                for job in report["jobs"]
            ],
        },
    )

    return {"passed": 0, "failed": 1, "error": 2, "interrupted": 130}[report["status"]]
