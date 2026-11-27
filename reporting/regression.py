from handlers.detection_context import build_detection_context
from reporting.context_view import CONTEXT_STYLES, source_view, render_detection_tree
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from pathlib import Path
import json
import yaml
from uuid import uuid4
from handlers.file_handlers import (
    load_regression_suite,
    load_regression_session,
    load_test_case,
    load_sigma_rule,
)
from handlers.matching import validate_rule, report_handler
from reporting.visuals import (
    VISUAL_STYLES,
    badge,
    decision,
    metrics,
    legend,
    comparison_table,
)
from reporting.report import evaluate_test_case, resolve_test_evidence
from reporting.html_report import (
    render_value,
    render_event_evaluation,
    render_event_fields,
    render_event_search,
)


def data_fingerprint(value):
    data = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode(
        "utf-8",
    )

    return sha256(data).hexdigest()


def classify_comparison(baseline, candidate):
    before, after = (baseline["status"], candidate["status"])

    if "insufficient_data" in (before, after):
        return "insufficient_data"

    if before == "not_met" and after == "met":
        return "improved"

    if before == "met" and after == "not_met":
        return "regressed"

    if before == after == "met":
        return "unchanged_met"

    if before == after == "not_met":
        return "unchanged_not_met"

    raise ValueError("Unsupported case evaluation status")


def run_regression(suite_path, baseline_path, candidate_path):
    from handlers.dump_readers import DECODER

    header = DECODER.decode(Path(suite_path).read_text(encoding="utf-8-sig"))

    if (
        isinstance(header, dict)
        and type(header.get("schema_version")) is int
        and header["schema_version"] == 2
    ):
        from handlers.finding_suite import run_evidence_regression

        return run_evidence_regression(suite_path, baseline_path, candidate_path)

    suite, entries = load_regression_suite(suite_path)
    rules, snapshots = ({}, {})

    for label, path in (("baseline", baseline_path), ("candidate", candidate_path)):
        try:
            rule, snapshot = load_sigma_rule(path, with_snapshot=True)
            validate_rule(rule)
        except (OSError, ValueError, yaml.YAMLError) as error:
            raise ValueError(f"Invalid {label} rule {path}: {error}") from error

        rules[label] = rule
        snapshots[label] = {**snapshot, "path": str(path.resolve())}

    sessions, paths, loaded_cases, case_ids = ({}, {}, [], set())

    for entry in entries:
        case = load_test_case(entry["case_path"])

        if case["case_id"] in case_ids:
            raise ValueError(f"Duplicate regression case_id: {case['case_id']}")

        case_ids.add(case["case_id"])
        session_path = entry["session_dir"]

        if session_path not in paths:
            metadata, events = load_regression_session(session_path)
            session_id = metadata["session_id"]

            if session_id in sessions:
                raise ValueError("The same session_id is supplied from different directories")

            sessions[session_id] = {
                "path": str(session_path),
                "session_metadata": metadata,
                "events": events,
                "events_sha256": data_fingerprint(events),
                "profiles_sha256": data_fingerprint(metadata["profiles_snapshot"]),
            }
            paths[session_path] = session_id

        session = sessions[paths[session_path]]
        resolve_test_evidence(case, session["session_metadata"], session["events"])
        loaded_cases.append((case, entry))

    for session in sessions.values():
        session["results"] = {}

        for label, rule in rules.items():
            session["results"][label] = report_handler(deepcopy(session["events"]), deepcopy(rule))

    for session in sessions.values():
        session["detection_context"] = build_detection_context(
            session["events"],
            {
                label: {result["Log Record ID"]: result["Selection"] for result in results}
                for label, results in session["results"].items()
            },
        )

    cases = []
    summary = {
        key: 0
        for key in (
            "improved",
            "regressed",
            "unchanged_met",
            "unchanged_not_met",
            "insufficient_data",
        )
    }

    for case, entry in loaded_cases:
        session = sessions[case["session_id"]]
        evaluations = {}

        for label in rules:
            evaluations[label] = evaluate_test_case(
                case,
                session["session_metadata"],
                session["events"],
                session["results"][label],
            )
            evaluations[label]["rule_sha256"] = snapshots[label]["sha256"]

        comparison = classify_comparison(evaluations["baseline"], evaluations["candidate"])
        summary[comparison] += 1
        selected_ids = set(case["evidence"]["record_ids"])
        before = {r["Log Record ID"]: r for r in session["results"]["baseline"]}
        after = {r["Log Record ID"]: r for r in session["results"]["candidate"]}
        changes = [
            {
                "record_id": record_id,
                "selected": record_id in selected_ids,
                "baseline": before[record_id]["Selection"],
                "candidate": after[record_id]["Selection"],
            }
            for record_id in before
            if before[record_id]["Selection"] is not after[record_id]["Selection"]
        ]
        cases.append(
            {
                "case_id": case["case_id"],
                "session_id": case["session_id"],
                "case_path": str(entry["case_path"]),
                "test_case": deepcopy(case),
                "test_case_sha256": data_fingerprint(case),
                "comparison": comparison,
                "baseline": evaluations["baseline"],
                "candidate": evaluations["candidate"],
                "changed_events": changes,
            },
        )

    return {
        "schema_version": 1,
        "report_type": "regression",
        "Report ID": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "engine_version": 1,
        "comparison_version": 1,
        "basis": "Same saved events, profiles, test cases and engine for both rules.",
        "suite": deepcopy(suite),
        "suite_path": str(suite_path.resolve()),
        "rules": snapshots,
        "summary": summary,
        "cases": cases,
        "sessions": sessions,
        "limitations": "Telemetry v1 remains not_assessed. Sufficient means only declared requirements passed. Rule matches do not prove external SIEM alerts or causality.",
    }


def regression_event_anchor(session_id, record_id):
    return "event-" + session_id.encode().hex() + "-" + record_id.encode().hex()


def decision_label(value):
    return "Skipped" if value is None else "Match" if value else "Unmatch"


def build_regression_html(report):
    if report.get("report_type") == "evidence_regression":
        from reporting.finding_report import build_finding_report

        return build_finding_report(report)

    case_links, case_blocks, changes_blocks, context_blocks = ([], [], [], [])

    for number, case in enumerate(report["cases"], 1):
        case_anchor = f"case-{number}"
        safe_id = escape(case["case_id"], quote=True)
        case_links.append(
            f"""<tr><th scope="row"><a href="#{case_anchor}">{safe_id}</a></th><td>{badge(case['comparison'])}</td><td>{badge(case['baseline']['status'])}</td><td>{badge(case['candidate']['status'])}</td></tr>""",
        )
        case_blocks.append(
            f"""<article id="{case_anchor}"><h3>{safe_id}</h3><p>Comparison: {badge(case['comparison'])}</p>""",
        )
        case_blocks.append(
            '<div class="trace-row"><div class="trace-node"><small>Baseline expectation</small>'
            + badge(case["baseline"]["status"])
            + '</div><span class="trace-arrow">→</span>'
            + '<div class="trace-node"><small>Candidate expectation</small>'
            + badge(case["candidate"]["status"])
            + '</div><span class="trace-arrow">→</span>'
            + '<div class="trace-node"><small>Comparison</small>'
            + badge(case["comparison"])
            + "</div></div>",
        )
        case_blocks.append(
            "<p>Expected rule decision on selected evidence: "
            + decision(case["test_case"]["expectation"]["expected_rule_match"])
            + "</p>",
        )

        for label in ("baseline", "candidate"):
            assessment = case[label]
            case_blocks.append(
                "<p><strong>"
                + label.title()
                + ":</strong> "
                + escape(str(assessment.get("reason", "No reason recorded.")))
                + "<br>Telemetry: "
                + badge(assessment.get("telemetry_status"))
                + "; selected event results: "
                + " / ".join(
                    (
                        badge(key) + " " + escape(str(value))
                        for key, value in assessment.get("selected_results", {}).items()
                    ),
                )
                + "</p>",
            )

        case_blocks.append("<h4>Selected evidence</h4>")

        for record_id in case["test_case"]["evidence"]["record_ids"]:
            anchor = regression_event_anchor(case["session_id"], record_id)
            case_blocks.append(f'<p><a href="#{anchor}">{escape(record_id)}</a></p>')

        if not case["test_case"]["evidence"]["record_ids"]:
            case_blocks.append("<p>No test evidence was selected.</p>")

        for label in ("baseline", "candidate"):
            case_blocks.append(
                "<details><summary>"
                + label.title()
                + " evaluation</summary>"
                + render_value(case[label], semantic=True)
                + "</details>",
            )

        case_blocks.append("</article>")
        changes_blocks.append(f"<h3>{safe_id}</h3>")

        if not case["changed_events"]:
            changes_blocks.append("<p>No event decisions changed.</p>")

        for change in case["changed_events"]:
            anchor = regression_event_anchor(case["session_id"], change["record_id"])
            membership = (
                "Selected test evidence" if change["selected"] else "Outside selected evidence"
            )
            changes_blocks.append(
                f"""<p><a href="#{anchor}">{escape(change['record_id'])}</a>: {decision(change['baseline'])} → {decision(change['candidate'])}. {membership}.</p>""",
            )

        context_blocks.append(
            "<details><summary>"
            + safe_id
            + "</summary>"
            + render_value(case["test_case"])
            + "</details>",
        )

    cards = []

    for session_id, session in report["sessions"].items():
        indexes = {
            label: {r["Log Record ID"]: r for r in session["results"][label]}
            for label in ("baseline", "candidate")
        }

        for event in session["events"]:
            record_id = event["record_id"]
            anchor = regression_event_anchor(session_id, record_id)
            categories = [
                label.title() + ": " + decision_label(indexes[label][record_id]["Selection"])
                for label in indexes
            ]
            search = json.dumps(
                {
                    "Event": event,
                    "Evaluations": {label: indexes[label][record_id] for label in indexes},
                },
                ensure_ascii=False,
            )
            memberships = [
                c["case_id"]
                for c in report["cases"]
                if c["session_id"] == session_id
                and record_id in c["test_case"]["evidence"]["record_ids"]
            ]
            cards.append(
                f'<article class="event-card" id="{anchor}" data-search="{escape(search, quote=True)}" data-results="{escape(json.dumps(categories), quote=True)}"><h3>Event {escape(record_id)}</h3><p>Session: {escape(session_id)}</p>'
                + source_view(event)
                + render_value({"Selected by cases": memberships})
                + "<p>"
                + escape("; ".join(categories))
                + "</p>",
            )
            comparison_keys = (
                "Checks",
                "Block Results",
                "Condition",
                "Condition Explanation",
                "Selection",
            )
            cards.append(
                "<details><summary>Baseline → Candidate: evaluation changes</summary>"
                + comparison_table(
                    {k: indexes["baseline"][record_id].get(k) for k in comparison_keys},
                    {k: indexes["candidate"][record_id].get(k) for k in comparison_keys},
                    "Changed evaluation fields",
                )
                + "</details>",
            )

            for label in indexes:
                result = indexes[label][record_id]
                cards.append(
                    '<section class="event-evaluation"><h4>'
                    + label.title()
                    + " rule evaluation</h4>"
                    + render_event_evaluation(
                        [{"Result": decision_label(result["Selection"]), "Evaluation": result}],
                    )
                    + "</section>",
                )

            cards.append(
                '<details class="event-details"><summary>Event fields</summary>'
                + render_event_fields({k: v for k, v in event.items() if k != "raw_xml"})
                + "</details><details><summary>Raw XML</summary>"
                + (
                    render_value(event["raw_xml"])
                    if event.get("raw_xml") is not None
                    else "<p>Raw XML is unavailable.</p>"
                )
                + "</details></article>",
            )

    summary_table = (
        '<table class="fields"><thead><tr><th>Case</th><th>Comparison</th><th>Baseline</th><th>Candidate</th></tr></thead><tbody>'
        + "".join(case_links)
        + "</tbody></table>"
    )
    overview = (
        render_value(
            {
                "Report ID": report["Report ID"],
                "Created at": report["created_at"],
                "Suite": report["suite"]["suite_id"],
                "Description": report["suite"]["description"],
                "Basis": report["basis"],
                "Engine version": report["engine_version"],
                "Sessions": {
                    sid: {k: session[k] for k in ("events_sha256", "profiles_sha256")}
                    for sid, session in report["sessions"].items()
                },
                "Summary": report["summary"],
                "Limitations": report["limitations"],
            },
        )
        + "<details><summary>Exact rule snapshots</summary>"
        + render_value(report["rules"])
        + "</details>"
    )
    rule_views = {
        label: yaml.safe_load(report["rules"][label]["text"]) for label in ("baseline", "candidate")
    }
    rule_diff = comparison_table(rule_views["baseline"], rule_views["candidate"], "Rule changes")
    overview = metrics(report["summary"]) + legend() + overview + rule_diff
    trees = "".join(
        (
            "<h3>Session: "
            + escape(sid)
            + "</h3>"
            + render_detection_tree(
                session.get("detection_context"),
                lambda rid, sid=sid: regression_event_anchor(sid, rid),
            )
            for sid, session in report["sessions"].items()
        ),
    )
    sections = [
        ("passport", "1. Test Overview", overview),
        (
            "evaluation",
            "2. Evaluation Summary and Reasons",
            summary_table + "".join(case_blocks),
        ),
        ("events", "3. Events with Context", trees + "".join(changes_blocks)),
        ("details", "4. Detailed Event Cards", "".join(cards)),
        ("manual-test", "5. Manual Test Context", "".join(context_blocks)),
    ]
    navigation = (
        '<nav aria-label="Report navigation">'
        + "".join((f'<a href="#{sid}">{title}</a> ' for sid, title, _ in sections))
        + "</nav>"
    )
    content = []

    for sid, title, body in sections:
        content.append(f'<section id="{sid}"><h2>{title}</h2>{body}</section>')

        if sid == "passport":
            content.append(navigation + render_event_search())

    return (
        """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TOTENKAHN — Regression report</title><style>
body {font:16px/1.5 system-ui,sans-serif;color:#172033;background:#f3f5f8;margin:0;padding-bottom:80px}
main {max-width:1200px;margin:auto;padding:24px}
section, nav, #event-search-panel {background:white;padding:20px;border:1px solid #dce2ea;border-radius:8px;margin-bottom:24px}
nav {display:flex;flex-wrap:wrap;gap:12px}
a {color:#174ea6} h2 {margin-top:0} h3,summary {overflow-wrap:anywhere}
article {border:1px solid #dce2ea;padding:16px;margin:16px 0;scroll-margin-top:16px}
article:target {border:2px solid #174ea6}
details {margin:12px 0} summary {cursor:pointer;font-weight:600}
.fields {width:100%;border-collapse:collapse} th,td {border:1px solid #dce2ea;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th {background:#f7f9fc} .value {white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.event-details>.fields>tbody>tr>th {width:24%;min-width:120px}
.checks-scroll {max-width:100%;overflow-x:auto}.checks-table {min-width:760px}
.missing,.empty {color:#596579}.values {padding-left:24px}
#event-search-panel label {display:block;margin-top:12px}
#event-search-panel input,#event-search-panel select {box-sizing:border-box;width:100%;padding:8px}
button {margin-top:12px;padding:8px;cursor:pointer}[hidden] {display:none!important}
.back-to-top {position:fixed;right:16px;bottom:16px;padding:10px;background:#174ea6;color:white;border-radius:6px}
a:focus-visible,summary:focus-visible {outline:3px solid #b45309;outline-offset:3px}
@media print {nav,.back-to-top,#event-search-panel {display:none}}
"""
        + VISUAL_STYLES
        + CONTEXT_STYLES
        + '</style></head><body><main id="report-top"><h1>TOTENKAHN — Regression report</h1>'
        + "".join(content)
        + '\n</main><a class="back-to-top" href="#report-top">Back to top</a></body></html>'
    )


def save_regression_report(report, output_dir):
    payload = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
    html = build_regression_html(report)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = output_dir / ("regression-" + report["Report ID"])
    run_dir.mkdir(exist_ok=False)
    json_path, html_path = (run_dir / "report.json", run_dir / "report.html")
    json_path.write_text(payload, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")

    return (json_path, html_path)
