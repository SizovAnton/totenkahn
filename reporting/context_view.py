from html import escape
from hashlib import sha256
from reporting.visuals import badge, decision
from handlers.detection_context import source_context

CONTEXT_STYLES = """
.context-source {color:#566477;font-size:14px;overflow-wrap:anywhere}
.graph-access>summary {display:inline-block;padding:10px 16px;background:#174ea6;color:white;border-radius:6px;cursor:pointer}
.graph-access[open]>summary {margin-bottom:12px}
.graph-viewport {overflow:auto;max-height:65vh;border:1px solid #cdd7e4;background:#f8fafc;border-radius:8px}
.graph-viewport svg {display:block;max-width:none;font:14px system-ui,sans-serif}
.graph-viewport rect {fill:white;stroke:#718096;stroke-width:1.5}
.graph-viewport .detected rect {fill:#e0f2fe;stroke:#075985;stroke-width:2.5}
.graph-viewport a:hover rect,.graph-viewport a:focus rect {stroke:#b45309;stroke-width:3}
.graph-viewport text {fill:#172033;pointer-events:none}
.graph-viewport .graph-edge {fill:none;stroke:#64748b;stroke-width:2}
.graph-node-detail {display:none;padding:16px;border:1px solid #cdd7e4;border-radius:8px;margin-top:16px;scroll-margin-top:20px}
.graph-node-detail:target {display:block}
@media print {.graph-access {display:none}}
"""


def source_view(event=None, context=None):
    context = context if context is not None else source_context(event)
    host = escape(str(context["host"] or "Unavailable"))
    ips = (
        ", ".join(
            (
                escape(entry["value"])
                + " <small>["
                + escape(" → ".join(entry["path"]))
                + "]</small>"
                for entry in context["ips"]
            ),
        )
        or "Unavailable"
    )

    return (
        '<div class="context-source"><strong>Source host:</strong> '
        + host
        + " <small>["
        + escape(" → ".join(context["host_path"]))
        + "]</small><br>"
        + "<strong>Source host IP:</strong> "
        + ips
        + "<br><strong>Channel / Provider:</strong> "
        + escape(str(context["channel"] or "Unavailable"))
        + " / "
        + escape(str(context["provider"] or "Unavailable"))
        + "</div>"
    )


def render_detection_tree(graph, anchor):
    if graph is None:
        return "<p>Detection context is unavailable in this saved report.</p>"

    nodes = {node["record_id"]: node for node in graph["nodes"]}

    if not nodes:
        return "<p>No matched events available for a detection graph.</p>"

    children = {key: [] for key in nodes}
    parent = {}

    for edge in graph["edges"]:
        children[edge["parent"]].append(edge["child"])
        parent[edge["child"]] = edge

    prefix = (
        "graph-" + sha256("\x00".join((anchor(key) for key in nodes)).encode()).hexdigest()[:20]
    )
    ids = {key: prefix + "-node-" + str(number) for number, key in enumerate(nodes, 1)}
    numbers = {key: number for number, key in enumerate(nodes, 1)}
    roots = [key for key in nodes if key not in parent]
    order = []
    depth = {}
    stack = [(key, 0) for key in reversed(roots)]

    while stack:
        key, level = stack.pop()
        order.append(key)
        depth[key] = level
        stack.extend(((child, level + 1) for child in reversed(children[key])))

    positions = {}
    lane = 0

    for key in reversed(order):
        if children[key]:
            y = sum((positions[child][1] for child in children[key])) / len(children[key])
        else:
            y = 30 + lane * 150
            lane += 1

        positions[key] = (30 + depth[key] * 330, y)

    width = 300 + max((x for x, y in positions.values()))
    height = 140 + max((y for x, y in positions.values()))
    parts = [
        '<details class="graph-access"><summary>View detection graph</summary>',
        "<p>Select a node to view its details below the diagram. Blue nodes matched at least one rule. Solid arrows show parent ancestry; dashed arrows connect a process creation event to another event of that process. Unconfirmed candidates are listed only in node details.</p>",
        f'<div class="graph-viewport" id="{prefix}-canvas" tabindex="0" role="region" aria-label="Detection graph; scroll to explore">',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="group" aria-label="Detection relationships">',
        f'<defs><marker id="{prefix}-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"/></marker></defs>',
    ]

    for edge in graph["edges"]:
        x, y = positions[edge["parent"]]
        cx, cy = positions[edge["child"]]
        dash = ' stroke-dasharray="6 4"' if edge["method"] == "process_event_context" else ""
        parts.append(
            f'<path class="graph-edge" d="M {x + 250} {y + 50} C {x + 290} {y + 50}, {cx - 40} {cy + 50}, {cx} {cy + 50}" marker-end="url(#{prefix}-arrow)"{dash}><title>'
            + escape(edge["method"])
            + "</title></path>",
        )

    for key, node in nodes.items():
        x, y = positions[key]
        title = (
            ("Detected event" if node["matched"] else "Parent context") + " " + str(numbers[key])
        )
        host = str(node["source"]["host"] or "Host unavailable")
        short_host = host if len(host) <= 29 else host[:26] + "…"
        label = lambda value: (
            "Match" if value is True else "Unmatch" if value is False else "Skipped"
        )
        outcomes = " → ".join((label(value) for value in node["decisions"].values()))
        parts.append(
            f'<a href="#{ids[key]}" class="'
            + ("detected" if node["matched"] else "context")
            + '" aria-label="'
            + escape(title + ": " + key, quote=True)
            + '">'
            + "<title>"
            + escape(key + " | " + host)
            + "</title>"
            + f'<rect x="{x}" y="{y}" width="250" height="100" rx="8"/>'
            + f'<text x="{x + 14}" y="{y + 25}" font-weight="700">'
            + escape(title)
            + "</text>"
            + f'<text x="{x + 14}" y="{y + 49}">'
            + escape(short_host)
            + "</text>"
            + f'<text x="{x + 14}" y="{y + 76}">'
            + escape(outcomes)
            + "</text></a>",
        )

    parts.append(
        '</svg></div><p class="trace-note">' + escape(graph["limitations"]) + "</p>",
    )

    if any((len(node["decisions"]) > 1 for node in nodes.values())):
        parts.append("<p>Node results are shown in order: Baseline → Candidate.</p>")

    for key, node in nodes.items():
        parts.append(
            f'<div class="graph-node-detail" id="{ids[key]}"><h4>Event '
            + str(numbers[key])
            + "</h4>"
            + "<p>"
            + escape(key)
            + "</p>"
            + source_view(context=node["source"])
            + "<p>Time: "
            + escape(str(node["time"]))
            + "</p>"
            + "<p>"
            + " → ".join(
                (
                    escape(label.title()) + ": " + decision(value)
                    for label, value in node["decisions"].items()
                ),
            )
            + "</p>",
        )

        if key in parent:
            edge = parent[key]
            parts.append(
                "<p>Connection: "
                + escape(edge["method"])
                + " — "
                + escape(str(edge["checks"]["parent_field"]))
                + " = "
                + escape(str(edge["checks"]["identity_field"]))
                + " ("
                + escape(str(edge["checks"]["parent_guid"]))
                + ")</p>",
            )

        parts.append(
            "<p>Parent status: "
            + badge(node["parent_status"])
            + " — "
            + escape(node["reason"])
            + "</p>",
        )

        if node["candidates"] and node["parent_status"] != "linked":
            parts.append(
                "<details><summary>Unconfirmed parent candidates</summary>"
                + "".join(
                    (
                        '<p><a href="#'
                        + escape(anchor(candidate), quote=True)
                        + '">'
                        + escape(candidate)
                        + "</a></p>"
                        for candidate in node["candidates"]
                    ),
                )
                + "</details>",
            )

        parts.append(
            '<a href="#'
            + escape(anchor(key), quote=True)
            + '">Open full event evidence</a> · '
            + f'<a href="#{prefix}-canvas">Back to graph</a></div>',
        )

    parts.append("</details>")

    return "".join(parts)
