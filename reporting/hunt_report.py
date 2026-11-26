from html import escape
import json
from reporting.dump_report import STYLE
from reporting.html_report import render_value


def explanation(check, depth=0):
    if check is None:
        return "Not evaluated: scope was false or unknown."

    result = "UNKNOWN" if check["result"] is None else "TRUE" if check["result"] else "FALSE"
    prefix = "  " * depth

    if "operator" in check:
        line = prefix + check["operator"].upper() + " -> " + result

        return "\n".join([line] + [explanation(child, depth + 1) for child in check["children"]])

    actual = json.dumps(check.get("actual"), ensure_ascii=False)
    expected = json.dumps(check["expected"], ensure_ascii=False)
    line = f"{prefix}{check['field']}: {actual}; {check['op']} {expected} -> {result}"

    return line + "\n" + prefix + check.get("reason", "")


def write_hunt_report(index, report, output):
    stream = None

    try:
        for identifier, encoded in index.execute("SELECT id,record FROM results ORDER BY id"):
            record = json.loads(encoded)

            if (identifier - 1) % 100 == 0:
                if stream is not None:
                    stream.write("</body></html>")
                    stream.close()

                name = f"events-{(identifier - 1) // 100 + 1:04d}.html"
                report["pages"].append(name)
                stream = (output / name).open("x", encoding="utf-8")
                stream.write(
                    '<!doctype html><html lang="en"><meta charset="utf-8"><title>Hunt evidence</title>'
                    + STYLE
                    + '<body><a href="report.html">Hunt summary</a>',
                )

            if stream is None:
                raise RuntimeError("Hunt report page missing")

            stream.write(
                '<article id="event-'
                + str(identifier)
                + '"><h2>'
                + escape(record["decision"])
                + " — evidence "
                + str(identifier)
                + "</h2>",
            )
            stream.write(
                "<p>"
                + escape(record["attachment_label"])
                + " / row "
                + str(record["row_id"])
                + "</p>",
            )
            stream.write(
                "<h3>Scope</h3><pre>" + escape(explanation(record["scope_evaluation"])) + "</pre>",
            )
            stream.write(
                "<h3>Hypothesis condition</h3><pre>"
                + escape(explanation(record["evaluation"]))
                + "</pre>",
            )

            for key in (
                "source",
                "locator",
                "event_id",
                "entities",
                "event",
                "import_mapping",
                "warnings",
                "raw",
            ):
                stream.write(
                    "<details><summary>"
                    + key
                    + "</summary>"
                    + render_value(record[key])
                    + "</details>",
                )

            stream.write("</article>")
    finally:
        if stream is not None:
            stream.write("</body></html>")
            stream.close()

    html = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>totenkahn hunt</title>'
        + STYLE
        + "<body>"
    )
    html += "<h1>" + escape(report["hunt"]["name"]) + ": " + escape(report["status"]) + "</h1>"
    html += "<p>" + escape(report["hunt"]["definition"]["hypothesis"]) + "</p>"
    html += '<p class="notice">' + escape(report["scope"]) + "</p>"

    if report.get("reason"):
        html += '<p class="notice">' + escape(report["reason"]) + "</p>"

    for title, keys in [
        (
            "Assessment",
            (
                "hypothesis_result",
                "scope_status",
                "counts",
                "unknown_predicate_checks",
                "matched_unique_evidence_records",
                "matching_occurrences_with_unknown_time",
            ),
        ),
        ("Observed entities (top 50 per dimension)", ("entities",)),
        (
            "Scope and limitations",
            ("filters", "limitations", "identity_limitations", "semantics"),
        ),
        ("Reproducibility", ("case_id", "case_sha256", "case_revision", "hunt")),
    ]:
        html += "<h2>" + title + "</h2>" + render_value({k: report.get(k) for k in keys})

    html += (
        "<h2>Per-event evidence</h2><p>"
        + " ".join(
            (
                '<a href="' + name + '">' + str(i) + "</a>"
                for i, name in enumerate(report["pages"], 1)
            ),
        )
        + "</p>"
    )
    html += '<p><a href="report.json">JSON report</a>; all decisions: events.jsonl; all entity groups: entities.jsonl. Original files stay in the case. Use hunt scope to follow an entity to its evidence records.</p></body></html>'
    (output / "report.html").write_text(html, encoding="utf-8")
