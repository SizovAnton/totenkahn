from html import escape
import json

INPUTS = {
    "01-import": "Three generic events encoded as JSON, JSONL, CSV, TSV and gzip variants; three Windows Event XML records. Separate copies contain one malformed row and a deliberately changed original.",
    "02-sigma": "Three basic control events plus four investigation events on lab-a/lab-b. Rules: selection, and selection AND NOT filter. Mapping explicitly maps command_line to CommandLine.",
    "03-case": "The basic three-event case plus a two-attachment case containing six events, two hosts, two users and one unknown timestamp. Notes are explicitly authored fixture statements.",
    "04-hunt": "Basic and two-host cases. Hypothesis: command_line contains --review AND NOT --excluded, within process-start events. This is a synthetic marker hypothesis, not an attack claim.",
    "05-regression": "Explicit positive, negative and missing-field expectations; unchanged and deliberately regressed candidates. An additional finding is created from reviewed hunt result 1.",
}

LIMITS = {
    "01-import": [
        "Real Splunk/Elastic exports and EVTX are not tested.",
        "Large files, interrupted imports and recovery are not tested.",
    ],
    "02-sigma": [
        "Only the fixture rules and explicit mapping are tested; this is not full Sigma certification."
    ],
    "03-case": [
        "Chronological order does not establish causation or process identity.",
        "No endpoint response or real incident investigation is performed.",
    ],
    "04-hunt": [
        "Scope refers only to attached evidence, not the whole environment.",
        "No live SIEM query, EDR alert or compromise verdict is tested.",
    ],
    "05-regression": [
        "Expectations are explicitly supplied by the fixture analyst.",
        "CI success does not establish detection coverage against real attacks.",
    ],
}

STYLE = """body{font:16px/1.55 system-ui;margin:2rem auto;max-width:1150px;padding:0 1rem;color:#182638;background:#f5f7fb}article,section{background:white;border:1px solid #cbd5e1;border-radius:8px;padding:1rem;margin:1rem 0}h1,h2,h3{line-height:1.25}a{color:#174c9b}table{border-collapse:collapse;width:100%}th,td{padding:.6rem;border:1px solid #d3dce8;text-align:left;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere} .passed{color:#126039}.failed,.error{color:#a01929}.not_run,.not_requested,.running{color:#755005}.notice{border-left:5px solid #bc850b;padding:.8rem;background:#fff5d9}.chain{border-left:3px solid #3376b9;padding-left:1.5rem}summary{cursor:pointer;color:#174c9b}code{overflow-wrap:anywhere}nav a{margin-right:1rem} .muted{color:#526176}"""


def value_html(value):
    if isinstance(value, dict):
        return (
            "<table>"
            + "".join(
                "<tr><th>" + escape(str(k)) + "</th><td>" + value_html(v) + "</td></tr>"
                for k, v in value.items()
            )
            + "</table>"
        )

    if isinstance(value, list):
        return (
            "<ol>" + "".join("<li>" + value_html(v) + "</li>" for v in value) + "</ol>"
            if value
            else "None recorded"
        )

    return escape("Unknown / not available" if value is None else str(value))


def link(path, prefix=""):
    path = str(path).replace("\\", "/")

    return '<a href="' + escape(prefix + path, quote=True) + '">' + escape(path) + "</a>"


def render_stage(stage, prefix=""):
    status = stage["status"]
    body = (
        '<section id="'
        + stage["id"]
        + '"><h2>'
        + escape(stage["name"])
        + '</h2><p>Acceptance: <strong class="'
        + escape(status, quote=True)
        + '">'
        + escape(status.upper())
        + "</strong></p>"
    )
    body += "<p>" + escape(stage.get("chain", "")) + "</p>"

    if stage.get("reason"):
        body += '<p class="notice">' + escape(stage["reason"]) + "</p>"

    body += (
        "<h3>Input and scenario</h3><p>"
        + escape(stage.get("input_scenario", INPUTS[stage["id"]]))
        + "</p>"
    )
    body += (
        "<h3>Coverage and limits</h3><p>Each requirement below is confirmed only by its listed fixture check.</p><ul>"
        + "".join(
            "<li>" + escape(s) + "</li>" for s in stage.get("not_tested", LIMITS[stage["id"]])
        )
        + "</ul>"
    )

    if status in ("not_requested", "not_run"):
        return body + "<p>No result is claimed for this stage.</p></section>"

    body += "<h3>Requirement → scenario → result → evidence</h3>"

    for check in stage["checks"]:
        body += (
            "<article><h3>"
            + escape(check["name"])
            + ' — <span class="'
            + escape(check["status"], quote=True)
            + '">'
            + escape(check["status"].upper())
            + "</span></h3><p>"
            + escape(check.get("purpose", ""))
            + "</p>"
        )
        body += (
            "<p>"
            + escape(
                check.get(
                    "explanation", "This check has not completed; no conclusion is available."
                )
            )
            + "</p>"
        )

        if "observed" in check:
            observations = value_html(check["observed"])

            if isinstance(check["observed"], list) or (
                isinstance(check["observed"], dict)
                and any(isinstance(v, list) for v in check["observed"].values())
            ):
                body += (
                    "<details><summary>Recorded observations — all rows and values</summary>"
                    + observations
                    + "</details>"
                )
            else:
                body += "<h4>Recorded observations</h4>" + observations

        for item in check.get("stories", []):
            body += (
                "<article><h4>"
                + escape(item["title"])
                + "</h4><p>"
                + escape(item["explanation"])
                + '</p><ol class="chain">'
                + "".join("<li>" + escape(str(x)) + "</li>" for x in item["chain"])
                + "</ol></article>"
            )

        body += (
            "<h4>Evidence and detailed reports</h4><ul>"
            + "".join("<li>" + link(p, prefix) + "</li>" for p in check.get("evidence", []))
            + "</ul>"
        )
        body += (
            "<details><summary>Expected values and machine-readable check</summary><pre>"
            + escape(json.dumps(check, ensure_ascii=False, indent=2))
            + "</pre></details></article>"
        )

    return body + "</section>"


def document(title, body):
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'
        + escape(title)
        + "</title><style>"
        + STYLE
        + "</style></head><body>"
        + body
        + "</body></html>"
    )


def save_html(output, report):
    intro = (
        "<h1>Totenkahn — five-stage offline acceptance</h1><p>Acceptance result: <strong>"
        + escape(report["status"].upper())
        + '</strong></p><p class="notice">PASS means the recorded outcome matches the fixture expectation. A negative control may correctly produce FAILED; missing evidence may correctly produce NEEDS_VERIFICATION. Neither is automatically a failed acceptance check. Unselected stages are not tested.</p><p>Synthetic local evidence only. No Atomic execution, live collection, host changes, real Splunk/Elastic integration or EDR validation.</p>'
    )
    intro += (
        "<h2>How to read this report</h2><p>Read the requirement and observed facts, then follow the recorded explanation to the source and detailed report. Evaluation dependencies are not causal links between processes.</p><p>Inputs: "
        + link("fixtures/events.jsonl")
        + " · "
        + link("fixtures/investigation.jsonl")
        + " · "
        + link("fixtures/secondary.jsonl")
        + " · "
        + link("report.json")
        + " (includes source SHA-256 hashes)</p>"
    )
    intro += (
        "<nav>"
        + "".join(
            '<a href="#' + s["id"] + '">' + escape(s["name"]) + "</a>" for s in report["stages"]
        )
        + "</nav>"
    )
    intro += "<h2>Stage summary</h2><table><tr><th>Stage</th><th>Acceptance</th><th>Completed checks</th><th>Stage report</th></tr>"

    for stage in report["stages"]:
        completed = sum(c["status"] in ("passed", "failed") for c in stage["checks"])
        report_link = (
            link(stage["id"] + "/index.html") if (output / stage["id"]).is_dir() else "Not run"
        )
        intro += (
            "<tr><td>"
            + escape(stage["name"])
            + "</td><td>"
            + escape(stage["status"])
            + "</td><td>"
            + str(completed)
            + "/"
            + str(len(stage["checks"]))
            + "</td><td>"
            + report_link
            + "</td></tr>"
        )

    intro += "</table>"
    sections = []

    for stage in report["stages"]:
        sections.append(render_stage(stage))
        folder = output / stage["id"]

        if folder.is_dir():
            body = (
                "<p>" + link("index.html", "../") + " — All stages</p>" + render_stage(stage, "../")
            )
            (folder / "index.html").write_text(document(stage["name"], body), encoding="utf-8")

    (output / "index.html").write_text(
        document("Totenkahn offline acceptance", intro + "".join(sections)), encoding="utf-8"
    )


def explain_check(name, observed, passed):
    if not passed:
        return "The recorded outcome differs from the expectation. This check failed; review the observed facts and evidence. No success is claimed."

    explanations = {
        "formats": "All eight imports retained the expected records and passed integrity verification. This verifies counts and integrity, not universal format compatibility.",
        "normalization": "The seven generic formats preserved the expected values. Missing JSON fields remain absent; empty CSV/TSV cells remain empty strings. These states are intentionally different.",
        "malformed": "The importer retained three valid rows and rejected one invalid row. Its PARTIAL status is the required outcome, so this acceptance check passes.",
        "integrity": "Verification detected the deliberately changed original. FAILED belongs to the integrity operation; this acceptance check passes because it detected the intended change.",
        "decisions": "Recorded outcomes include a match, a non-match and insufficient data. NEEDS_VERIFICATION in the detailed report preserves the missing-field limitation; it does not mean this expected-outcome check failed.",
        "trace": "The recorded evaluation was checked against the fixture expectations and original source hashes. Follow the detailed event report for every field and logical operand.",
        "selection": "Only fixture row 1 was selected. The single confirmed match concerns that selection, not the unselected records.",
        "compound": "Row 1 matches; row 2 lacks the marker; row 3 has the marker but is excluded by NOT filter. Row 4 lacks CommandLine and remains insufficient, despite provisional false checks.",
        "timeline": "All three source events remain traceable and are ordered by their recorded timestamps. This does not assert that one process caused another.",
        "notes": "The analyst note is stored separately, and case integrity passed. A note is interpretation, not an additional observed event.",
        "export": "The exported archive was extracted into a new directory and its case evidence passed verification after relocation. Source files were not replaced.",
        "multi_source": "Two attachments contribute six events. One has no timestamp and remains unknown. The host filter selects three lab-a events; one row retains its analyst note. Known times are sorted and all source hashes match.",
        "scope": "The requested host scope retains the expected matching record. Scope remains incomplete because another event cannot be fully evaluated.",
        "multi_host": "Two events match on lab-a. The lab-b command containing the marker is excluded by NOT; lab-b has no confirmed matches. One missing command keeps the overall evidence scope incomplete.",
        "positive": "Both explicit fixture expectations hold for the evaluated rules. CI passed for these two cases only.",
        "negative": "The deliberately changed candidate loses one expected match. CI FAILED with exactly one regression; detecting this intended regression makes the acceptance control pass.",
        "insufficient": "A missing command line cannot establish NO MATCH. CI rejected the expectation with one insufficient case; this is the intended protective behavior.",
        "hunt_to_ci": "A reviewed hunt result was saved as a finding with an explicit MATCH expectation. The exported evidence bundle passed verification and the one-case CI run satisfied that expectation.",
    }

    return explanations.get(name, "The observed values match the explicit fixture expectation.")
