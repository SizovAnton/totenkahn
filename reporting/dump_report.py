from html import escape
import json
from handlers.evidence import file_hash
from reporting.explanation import render_explanation
from reporting.html_report import render_value, render_event_evaluation

STYLE = "<style>body{font:16px/1.5 system-ui;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#172033}article{border:1px solid #ccc;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.5rem;text-align:left;overflow-wrap:anywhere}details{margin:.8rem 0}a{color:#174ea6}.notice{background:#fff4cc;padding:.8rem}.checks-scroll{overflow:auto}</style>"


class EventPages:

    def __init__(self, output):
        self.output = output
        self.stream = None
        self.names = []
        self.count = 0

    def __enter__(self):
        return self

    def append(self, record):
        if self.count % 100 == 0:
            if self.stream is not None:
                self.stream.write("</body></html>")
                self.stream.close()

            name = f"events-{len(self.names) + 1:04d}.html"
            self.names.append(name)
            self.stream = (self.output / name).open("x", encoding="utf-8")
            self.stream.write(
                '<!doctype html><html lang="en"><meta charset="utf-8"><title>totenkahn dump evidence</title>'
                + STYLE
                + '<body><a href="../report.html">Analysis summary</a>',
            )

        if self.stream is None:
            raise RuntimeError("Report page was not opened")

        self.stream.write(
            '<article id="row-'
            + str(record["row_id"])
            + '"><h2>Row '
            + str(record["row_id"])
            + ": "
            + escape(record["status"])
            + "</h2>",
        )
        self.stream.write("<p>" + escape(record["reason"]) + "</p>")

        if record["engine_result_provisional"]:
            self.stream.write(
                '<p class="notice">INSUFFICIENT DATA: the engine calculation below is provisional. It must not be read as a confirmed match or no-match.</p>',
            )

        self.stream.write(
            "<details open><summary>Compatibility and field mappings</summary>"
            + render_value(record["compatibility"])
            + "</details>",
        )
        evaluation = record["engine_evaluation"]

        if evaluation is not None:
            self.stream.write(render_explanation(evaluation))
            self.stream.write(
                render_event_evaluation([{"Result": record["status"], "Evaluation": evaluation}]),
            )
        else:
            self.stream.write("<p>Fields, blocks and condition were not evaluated.</p>")

        for title, key in [
            ("Source and locator", "source"),
            ("Original record locator", "locator"),
            ("Normalized event", "event"),
            ("Import mappings", "import_mapping"),
            ("Raw record representation", "raw"),
        ]:
            self.stream.write(
                "<details><summary>"
                + title
                + "</summary>"
                + render_value(record[key])
                + "</details>",
            )

        self.stream.write("</article>")
        self.count += 1

    def __exit__(self, *arguments):
        if self.stream is not None:
            self.stream.write("</body></html>")
            self.stream.close()


def write_summary(report, output):
    rows = []

    for rule in report["rules"]:
        links = " ".join(
            (
                '<a href="' + rule["directory"] + "/" + page + '">' + str(index) + "</a>"
                for index, page in enumerate(rule["pages"], 1)
            ),
        )
        rows.append(
            "<tr><td>"
            + escape(rule["path"])
            + "</td><td>"
            + escape(rule["status"])
            + "</td><td>"
            + render_value(rule["counts"])
            + "</td><td>"
            + escape(
                rule.get("reason") or "No summary explanation was recorded; see evidence pages."
            )
            + "</td><td>"
            + links
            + "</td></tr>",
        )

    html = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>totenkahn dump analysis</title>'
        + STYLE
    )
    html += "<h1>Dump analysis: " + escape(report["status"]) + "</h1>"
    html += "<p>Processing status is not a detection-expectation verdict. Zero matches alone do not fail this command.</p>"

    if report.get("reason"):
        html += '<p class="notice">' + escape(report["reason"]) + "</p>"

    html += (
        "<table><tr><th>Rule</th><th>Status</th><th>Event decisions</th><th>Reason</th><th>Evidence pages</th></tr>"
        + "".join(rows)
        + "</table>"
    )

    for rule in report["rules"]:
        if "readiness" in rule:
            html += (
                "<details open><summary>Source and field suitability: "
                + escape(rule["path"])
                + "</summary>"
                + render_value(rule["readiness"])
                + "</details>"
            )

    for title, key in [
        ("Selection and provenance", "selection"),
        ("Analysis mapping", "mapping"),
        ("Limitations", "limitations"),
    ]:
        html += (
            "<details open><summary>"
            + title
            + "</summary>"
            + render_value(report.get(key))
            + "</details>"
        )

    html += '<p><a href="report.json">Machine-readable report</a>. Complete per-event results: rule-NNNN/events.jsonl.</p></html>'
    (output / "report.html").write_text(html, encoding="utf-8")
    report["html_sha256"] = file_hash(output / "report.html")
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
