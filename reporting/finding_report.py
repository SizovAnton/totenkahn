from html import escape
from reporting.dump_report import STYLE
from reporting.html_report import render_value
from reporting.explanation import render_explanation


def build_finding_report(report):
    html = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Finding regression</title>'
        + STYLE
        + "<body><h1>Reviewed findings: baseline vs candidate</h1>"
    )
    html += "<p>" + escape(report["basis"]) + "</p>"
    html += render_value(
        {
            "summary": report["summary"],
            "case_id": report["case_id"],
            "case_sha256": report["case_sha256"],
            "limitations": report["limitations"],
        },
    )
    html += "<h2>Exact rule snapshots</h2>" + render_value(report["rules"])
    html += (
        "<details><summary>Mapping and source configuration</summary>"
        + render_value({"mapping": report["mapping"], "configuration": report["configuration"]})
        + "</details>"
    )

    for number, case in enumerate(report["cases"], 1):
        html += (
            '<article id="finding-'
            + str(number)
            + '"><h2>'
            + escape(case["case_id"])
            + ": "
            + escape(case["comparison"])
            + "</h2>"
        )
        html += "<p>Expectation applies to EACH selected event. Insufficient compatibility is never a successful negative test.</p>"
        html += (
            "<details open><summary>Reviewed finding and evidence references</summary>"
            + render_value(case["finding"])
            + "</details>"
        )
        html += render_value({"baseline": case["baseline"], "candidate": case["candidate"]})

        for index, event in enumerate(case["events"], 1):
            html += (
                '<section id="finding-'
                + str(number)
                + "-event-"
                + str(index)
                + '"><h3>Evidence '
                + str(index)
                + "</h3>"
            )
            html += render_value(
                {
                    "reference": event["reference"],
                    "attachment": event["attachment_label"],
                    "dataset_status": event["dataset_status"],
                },
            )

            for label in ("baseline", "candidate"):
                result = event[label]
                html += (
                    "<h4>"
                    + label.title()
                    + ": "
                    + escape(result["status"])
                    + "</h4><p>"
                    + escape(result["reason"])
                    + "</p>"
                )

                if result["engine_result_provisional"]:
                    html += '<p class="notice">Provisional engine result: insufficient evidence prevents a confirmed decision.</p>'

                html += render_value(result["compatibility"])

                if result["engine_evaluation"] is not None:
                    html += render_explanation(result["engine_evaluation"])

            reference = event["baseline"]
            html += (
                "<details><summary>Source, raw record and mappings</summary>"
                + render_value(
                    {
                        key: reference[key]
                        for key in (
                            "source",
                            "locator",
                            "event",
                            "raw",
                            "import_mapping",
                            "import_warnings",
                        )
                    },
                )
                + "</details></section>"
            )

        html += "</article>"

    return (
        html
        + "<p>Evidence hashes detect accidental change; they are not digital signatures. No external SIEM/EDR detection or organization-wide coverage is asserted.</p></body></html>"
    )
