import os
import json
import sys
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

STATUSES = {
    "passed": ("PASS", "bold green"),
    "completed": ("COMPLETED", "bold green"),
    "passed_with_warnings": ("PASS WITH WARNINGS", "bold yellow"),
    "match": ("MATCH", "bold green"),
    "no_match": ("NO MATCH", "bold yellow"),
    "met": ("EXPECTATION MET", "bold green"),
    "not_met": ("EXPECTATION NOT MET", "bold red"),
    "unchanged_met": ("UNCHANGED / MET", "green"),
    "unchanged_not_met": ("UNCHANGED / NOT MET", "red"),
    "improved": ("IMPROVED", "bold green"),
    "regressed": ("REGRESSED", "bold red"),
    "failed": ("FAILED", "bold red"),
    "error": ("ERROR", "bold red"),
    "blocked": ("BLOCKED", "bold red"),
    "needs_verification": ("NEEDS VERIFICATION", "bold yellow"),
    "needs_action": ("NEEDS ACTION", "yellow"),
    "insufficient_data": ("INSUFFICIENT DATA", "bold yellow"),
    "insufficient_scope": ("UNKNOWN SCOPE", "bold yellow"),
    "not_applicable": ("NOT APPLICABLE", "dim"),
    "out_of_scope": ("OUT OF SCOPE", "dim"),
    "interrupted": ("INTERRUPTED", "yellow"),
    "not_ready": ("NOT READY", "yellow"),
    "planned": ("PLANNED", "cyan"),
    "available": ("AVAILABLE", "green"),
    "not_requested": ("NOT REQUESTED", "dim"),
    "not_started": ("NOT STARTED", "dim"),
    "unmatch": ("NO MATCH", "yellow"),
    "field_missing": ("FIELD MISSING", "yellow"),
    "skipped": ("SKIPPED", "dim"),
    "pass": ("PASS", "green"),
    "fail": ("FAIL", "red"),
    "observed_in_evidence": ("OBSERVED IN EVIDENCE", "green"),
    "not_observed_in_evaluated_records": ("NOT OBSERVED IN EVALUATED RECORDS", "yellow"),
    "undetermined": ("UNDETERMINED", "yellow"),
    "incomplete": ("INCOMPLETE", "yellow"),
}
LABELS = {
    "counts": "Counts",
    "checks": "Checks",
    "compatibility": "Evidence compatibility",
    "engine_evaluation": "Rule evaluation",
    "scope_evaluation": "Scope evaluation",
    "import_mapping": "Import mapping / provenance",
    "mappings": "Mapping paths (not event values)",
    "locator": "Original record location",
    "source": "Evidence source",
    "case": "Case",
    "jobs": "CI jobs",
    "rules": "Rules",
    "items": "Records",
    "violations": "Gate violations",
    "limitations": "Limitations",
    "failures": "Failures",
    "raw": "Raw record",
    "sha256": "SHA-256",
}


def clean(value):
    return "".join(
        (
            f"\\u{ord(c):04x}" if ((ord(c) < 32 and c not in """
	""") or (ord(c) == 127) or (c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")) else c
            for c in str(value)
        ),
    )


def interactive(stream):
    return stream is not None and bool(getattr(stream, "isatty", lambda: False)())


def label_text(key):
    return clean(LABELS.get(key, key.replace("_", " ").capitalize()))


def value_text(value, key="", limit=600):
    text = (
        "unknown / not available"
        if value is None
        else "true" if value is True else "false" if value is False else clean(value)
    )
    style = ""

    if (
        key.lower().replace(" ", "_")
        in {"status", "decision", "comparison", "result", "hypothesis_result", "scope_status"}
    ) and isinstance(value, str):
        text, style = STATUSES.get(value.lower().replace(" ", "_"), (text, "cyan"))
    elif key.lower().replace(" ", "_") in {"matched", "selection", "field_present", "result"}:
        style = "green" if value is True else "yellow" if value is False or value is None else ""
    elif key in {"reason", "error_type"}:
        style = "yellow"

    if len(text) > limit:
        text = (
            text[:limit] + f" ... [{len(text) - limit} more characters; full value in JSON/report]"
        )

    return Text(text, style=style)


def render_result(payload, title, console, *, full=False, legend=True):
    status = payload.get("status") if isinstance(payload, dict) else None
    heading = Text(clean(title), style="bold cyan")

    if status is not None:
        heading.append("  |  ")
        heading.append_text(value_text(status, "status"))

    console.print(Panel(heading, box=box.ASCII, border_style="cyan", padding=(0, 1)))
    budget = [sys.maxsize if full else 180]
    entry_limit = sys.maxsize if full else 12
    omitted = [False]

    def node(parent, key, value, depth=0):
        if budget[0] <= 0:
            omitted[0] = True

            return

        budget[0] -= 1

        if isinstance(value, (dict, list)):
            if not value:
                parent.add(Text(label_text(key) + ": none", style="dim"))

                return

            if not full and depth >= 7:
                parent.add(
                    Text(label_text(key) + ": details available in JSON/report", style="dim")
                )
                omitted[0] = True

                return

            heading = Text(label_text(key), style="bold cyan")
            heading.append(f" ({len(value)})", style="dim")
            branch = parent.add(heading, guide_style="blue")
            entries = (
                list(value.items())
                if isinstance(value, dict)
                else [(str(i + 1), item) for i, item in enumerate(value)]
            )

            for child_key, child in entries[:entry_limit]:
                node(branch, str(child_key), child, depth + 1)

            if len(entries) > entry_limit:
                branch.add(
                    Text(f"... {len(entries) - 12} more entries; see JSON/report", style="yellow"),
                )
                omitted[0] = True
        else:
            key_style = STATUSES.get(key.lower().replace(" ", "_"), ("", ""))[1]
            line = Text(
                label_text(key) + ": ",
                style=key_style
                or ("bold" if key in {"field", "condition", "path", "report", "html"} else ""),
            )
            line.append_text(value_text(value, key, limit=sys.maxsize if full else 600))
            parent.add(line)

    if not isinstance(payload, dict):
        root = Tree(Text("Details", style="bold cyan"), guide_style="blue")
        node(root, "result", payload)
        console.print(root)

        return

    scalars = Table(box=None, show_header=False, padding=(0, 1), expand=False)
    scalars.add_column(style="bold cyan", max_width=28)
    scalars.add_column(overflow="fold")

    for key, value in payload.items():
        if key != "status" and (not isinstance(value, (dict, list))):
            scalars.add_row(
                label_text(str(key)),
                value_text(value, str(key), limit=sys.maxsize if full else 1200),
            )

    if scalars.row_count:
        console.print(scalars)

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            root = Tree(Text(label_text(str(key)), style="bold cyan"), guide_style="blue")
            entries = (
                list(value.items())
                if isinstance(value, dict)
                else [(str(i + 1), item) for i, item in enumerate(value)]
            )

            if not entries:
                root.add(Text("none", style="dim"))

            for child_key, child in entries[:entry_limit]:
                node(root, str(child_key), child)

            if len(entries) > entry_limit:
                root.add(
                    Text(f"... {len(entries) - 12} more entries; see JSON/report", style="yellow")
                )
                omitted[0] = True

            console.print(root)

    if omitted[0]:
        console.print(
            Text(
                "Summary view is limited. Use --json or the saved report for complete details.",
                style="yellow",
            ),
        )

    if legend:
        console.print(
            Text(
                "MATCH / NO MATCH = rule decision; PASS / FAIL = check or expectation. UNKNOWN is not NO MATCH.",
                style="dim",
            ),
        )


def emit_result(
    payload,
    title="totenkahn",
    *,
    json_output=False,
    stream=None,
    human_payload=None,
    full=False,
    legend=True,
):
    stream = sys.stdout if stream is None else stream

    if json_output or not interactive(stream):
        print(
            json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False),
            file=stream,
            flush=True,
        )

        return

    from displaying.console import configure_standard_streams

    configure_standard_streams()
    console = Console(
        file=stream,
        legacy_windows=False,
        highlight=False,
        markup=False,
        color_system=None if "NO_COLOR" in os.environ else "auto",
    )
    render_result(
        human_payload if human_payload is not None else payload,
        title,
        console,
        full=full,
        legend=legend,
    )
