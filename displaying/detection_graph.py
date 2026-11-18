from rich.text import Text
from rich.tree import Tree

def build_detection_graph(graph, max_nodes=40):
    if max_nodes < 1:
        raise ValueError("max_nodes must be positive")

    tree = Tree(
        Text("Detection graph", style="bold cyan"),
        guide_style="dim",
    )

    if graph is None:
        tree.add(Text("Detection context is unavailable.", style="dim"))
        return tree
    
    nodes = {
        node["record_id"]: node for node in graph["nodes"]
    }

    if not nodes:
        tree.add(Text("No matched events.", style="dim"))
        return tree

    children = {record_id: [] for record_id in nodes}
    incoming = {}

    for edge in graph["edges"]:
        children[edge["parent"]].append(edge["child"])
        incoming[edge["child"]] = edge

    roots = [
        record_id for record_id in nodes if record_id not in incoming
    ]

    tree.add(
        Text(
            "Branches between events represent recorded relationships.\n"
            "Top-level events are not necessarily related.\n"
            "Baseline / Candidate show rule decisions, not relationships.",
            style="dim",
        )
    )

    linked_roots = [record_id for record_id in roots if children[record_id]]
    standalone_roots = [record_id for record_id in roots if not children[record_id]]
    root_entries = []

    if linked_roots:
        linked_section = tree.add(
            Text("Recorded relationship chains", style="bold cyan")
        )
        for record_id in linked_roots:
            root_entries.append((record_id, linked_section))

    if standalone_roots:
        standalone_section = tree.add(
            Text(
                "Events without confirmed links "
                "(grouping only; no relationship implied)",
                style="bold yellow",
            )
        )
        for record_id in standalone_roots:
            root_entries.append((record_id, standalone_section))

    pending = list(reversed(root_entries))

    visited = set()

    while pending and len(visited) < max_nodes:
        record_id, parent_branch = pending.pop()

        if record_id in visited:
            continue

        visited.add(record_id)
        node = nodes[record_id]

        label = Text()
        role = "Detected" if node["matched"] else "Context"

        label.append(role, style="bold cyan" if node["matched"] else "dim")
        label.append(f" | {record_id}")

        edge = incoming.get(record_id)

        if edge is not None:

            if edge["method"] == "process_event_context":
                relation = "event of the process created above"
            else:
                relation = "child process of the event above"

            label.append(f"\nRelation: {relation}", style="cyan")
            label.append(f" | Method: {edge['method']}", style="dim")

        for name, value in node["decisions"].items():
            if value is True:
                status, color = "Match", "cyan"
            elif value is False:
                status, color = "Unmatch", "yellow"
            else:
                status, color = "Skipped", "dim"

            label.append(f" | {name.title()}: ")
            label.append(status, style=color)

        host = node["source"]["host"] or "Unavailable"
        label.append(f"\nHost: {host}", style="dim")

        if node["parent_status"] != "linked":

            label.append(f"\nParent link: {node['parent_status']}", style="yellow")
            label.append(f" — {node['reason']}", style="dim")

        branch = parent_branch.add(label)

        for child_id in reversed(children[record_id]):
            pending.append((child_id, branch))

    remaining = len(nodes) - len(visited)

    if remaining:
        tree.add(Text(f"{remaining} nodes not shown. "
                      "Open the HTML report for the full graph.",
                      style="yellow"))

    return tree