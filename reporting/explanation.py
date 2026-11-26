import json
from html import escape


def truth(value):
    return "True" if value is True else "False" if value is False else "Not recorded"


def outcome(value):
    return "Match" if value is True else "Unmatch" if value is False else "Skipped / not evaluated"


def literal(value, limit=140):
    text = json.dumps(value, ensure_ascii=False, default=str)

    return text if len(text) <= limit else text[:limit] + "… [see recorded details]"


def node(label, children=()):
    return {"label": label, "children": list(children)}


def field_sentence(name, check):
    if not isinstance(check, dict):
        return f"{name}: field check unavailable."

    field = str(check.get("Field", name))
    presence = check.get("Field Present")

    if presence is False:
        description = f"{field} is absent"
    elif presence is True:
        if "Actual" not in check:
            description = f"{field} is present; its value was not recorded"
        elif check["Actual"] is None:
            description = f"{field} is present with a null value"
        elif check["Actual"] == "":
            description = f"{field} is present with an empty string"
        else:
            description = f"{field} is present: {literal(check['Actual'])}"
    else:
        description = f"{field}: presence was not recorded"

        if "Actual" in check:
            description += f"; recorded value {literal(check['Actual'])}"

    modifiers = check.get("Modifiers")

    if not isinstance(modifiers, list) or not all((isinstance(m, str) for m in modifiers)):
        operation = "operator not recorded"
    else:
        operators = [m for m in modifiers if m != "all"]
        operation = "|".join(operators) if operators else "equals (Sigma pattern)"

    expected = literal(check["Expected"]) if "Expected" in check else "not recorded"
    mode = ""

    if isinstance(check.get("Expected"), list) and isinstance(modifiers, list):
        mode = (
            "; all expected values required"
            if "all" in modifiers
            else "; any expected value sufficient"
        )

    if check.get("Unknown"):
        return f"{description}. Some values are unsupported for the operator; no confirmed decision. See per-element checks."

    if isinstance(check.get("Actual"), list):
        mode += "; actual values checked individually (any element per expected value)"

    return (
        f"{description}. Check {operation} against {expected}{mode}: {truth(check.get('Matched'))}."
    )


def explain_evaluation(evaluation):
    if not isinstance(evaluation, dict):
        return {
            "summary": "No rule evaluation was recorded.",
            "tree": node("Evaluation unavailable"),
            "notes": [],
            "complete": False,
        }

    result = evaluation.get("Selection")
    source = evaluation.get("Logsource")

    if result is None:
        if isinstance(source, dict) and source.get("Status") is False:
            checks = source.get("Checks")
            failures = [
                node(
                    f"{key}: actual {literal(value.get('Actual'))}; expected {literal(value.get('Expected'))}; False",
                )
                for key, value in (checks.items() if isinstance(checks, dict) else [])
                if isinstance(value, dict) and value.get("Matched") is False
            ]

            return {
                "summary": "The event logsource does not match the rule requirements. Field checks and the rule condition were not evaluated; this is Skipped, not Unmatch.",
                "tree": node(
                    "Event decision: Skipped",
                    [node("Logsource: False", failures), node("Fields / condition: not evaluated")],
                ),
                "notes": [],
                "complete": True,
            }

        unsupported = [
            field_sentence(name, check)
            for fields in evaluation.get("Checks", {}).values()
            for name, check in fields.items()
            if check.get("Unknown")
        ]

        if unsupported:
            return {
                "summary": " ".join(unsupported) + " No confirmed rule decision.",
                "tree": node(
                    "Event decision: insufficient data", [node(text) for text in unsupported]
                ),
                "notes": ["Unsupported values must not be treated as negative evidence."],
                "complete": True,
            }

        return {
            "summary": "No evaluated rule decision was recorded. This is not a confirmed negative result.",
            "tree": node("Event decision: not evaluated / unavailable"),
            "notes": [
                "Insufficient test evidence is assessed separately from this event decision."
            ],
            "complete": False,
        }

    checks = evaluation.get("Checks")
    checks = checks if isinstance(checks, dict) else {}
    blocks = evaluation.get("Block Results")
    blocks = blocks if isinstance(blocks, dict) else {}
    notes = []
    sentences = []

    for block, fields in list(checks.items())[:2]:
        if not isinstance(fields, dict):
            continue

        for name, check in list(fields.items())[:2]:
            sentences.append(field_sentence(name, check))

        if len(fields) > 2:
            sentences.append(
                f"{len(fields) - 2} more field checks are available in recorded details.",
            )

        sentences.append(
            f"Block {block}: {truth(blocks.get(block))}; all field checks in the block are required.",
        )

    if len(checks) > 2:
        sentences.append(f"{len(checks) - 2} more blocks are available in recorded details.")

    budget = [80]

    def walk(recorded, depth=0):
        budget[0] -= 1

        if depth > 20 or budget[0] < 0:
            raise ValueError("Condition tree exceeds the compact explanation limit.")

        if not isinstance(recorded, dict) or type(recorded.get("Result")) is not bool:
            raise ValueError("Condition tree is missing a Boolean result.")

        kind, value = (recorded.get("Type"), recorded["Result"])

        if kind == "reference":
            name = recorded.get("Name")

            if (
                (not isinstance(name, str))
                or (name not in blocks)
                or (type(blocks[name]) is not bool)
                or (blocks[name] != value)
            ):
                raise ValueError("Condition references do not agree with recorded block results.")

            fields = checks.get(name)
            children = []

            if isinstance(fields, dict):
                for key, check in list(fields.items())[:4]:
                    children.append(node(field_sentence(key, check)))

                if len(fields) > 4:
                    children.append(node(f"{len(fields) - 4} more checks: see recorded details"))

                known = [c.get("Matched") for c in fields.values() if isinstance(c, dict)]

                if (
                    fields
                    and (len(known) == len(fields))
                    and all((type(v) is bool for v in known))
                    and (all(known) != value)
                ):
                    raise ValueError(
                        "Field results do not agree with the recorded AND block result."
                    )

            if not children:
                children.append(node("Field checks not recorded"))

            return (
                node(f"Block {name}: {truth(value)} (all field checks required)", children),
                value,
            )

        if kind == "not":
            child, operand = walk(recorded.get("Operand"), depth + 1)

            if value != (not operand):
                raise ValueError("Recorded NOT result is inconsistent.")

            return (node(f"NOT: {truth(operand)} → {truth(value)}", [child]), value)

        if kind in ("and", "or"):
            left, a = walk(recorded.get("Left"), depth + 1)
            right, b = walk(recorded.get("Right"), depth + 1)

            if value != (a and b if kind == "and" else a or b):
                raise ValueError("Recorded logical result is inconsistent.")

            requirement = (
                "both operands required" if kind == "and" else "at least one operand sufficient"
            )

            return (
                node(
                    f"{kind.upper()}({truth(a)}, {truth(b)}): {truth(value)}; {requirement}",
                    [left, right],
                ),
                value,
            )

        raise ValueError("Condition tree has an unsupported node type.")

    complete = True

    try:
        tree, recorded_result = walk(evaluation.get("Condition Explanation"))

        if type(result) is not bool or recorded_result != result:
            raise ValueError("Recorded condition result and event decision disagree.")

        if isinstance(source, dict) and source.get("Status") is False:
            raise ValueError("Evaluated decision conflicts with the failed logsource check.")

        condition = (
            literal(evaluation.get("Condition")) if "Condition" in evaluation else "not recorded"
        )
        sentences.append(
            f"Condition {condition}: {truth(result)}. Event decision: {outcome(result)}.",
        )

        if evaluation["Condition Explanation"].get("Type") in ("and", "or", "not"):
            sentences.append(tree["label"] + ".")
    except ValueError as error:
        complete = False
        notes.append(str(error))
        sentences = [
            f"Recorded event decision: {outcome(result)}. A complete explanation cannot be reconstructed from this record.",
        ]
        tree = node(
            "Condition explanation unavailable or inconsistent",
            [
                node(f"Recorded block {name}: {truth(value)}")
                for name, value in list(blocks.items())[:8]
            ],
        )

    if not checks:
        notes.append("Field checks were not recorded; field-level reasoning is unavailable.")
        complete = False

    if complete and isinstance(evaluation.get("Condition"), str):
        tree = node(f"Condition {literal(evaluation['Condition'])}: {truth(result)}", [tree])

    return {
        "summary": " ".join(sentences),
        "tree": node(f"Event decision: {outcome(result)}", [tree]),
        "notes": notes,
        "complete": complete,
    }


def render_explanation(evaluation):
    model = explain_evaluation(evaluation)

    def draw(branch):
        children = (
            "<ul>" + "".join((draw(c) for c in branch["children"])) + "</ul>"
            if branch["children"]
            else ""
        )

        return "<li><span>" + escape(branch["label"]) + "</span>" + children + "</li>"

    notes = "".join(('<p class="trace-note">' + escape(n) + "</p>" for n in model["notes"]))

    return (
        '<section class="decision-explanation" aria-label="Rule decision explanation"><p class="decision-summary">'
        + escape(model["summary"])
        + "</p>"
        + notes
        + '<details class="decision-chain" open><summary>Why this decision — evidence chain</summary><p class="trace-note">Read from the decision down to its recorded inputs. Links show evaluation dependencies, not relationships between processes. An event decision is not a test-expectation verdict.</p><ul class="decision-tree">'
        + draw(model["tree"])
        + "</ul></details></section>"
    )


def terminal_explanation(evaluation, title="Rule decision explanation"):
    from rich.console import Group
    from rich.text import Text
    from rich.tree import Tree

    model = explain_evaluation(evaluation)
    tree = Tree(Text(model["tree"]["label"]))

    def append(parent, branch):
        item = parent.add(Text(branch["label"]))

        for child in branch["children"]:
            append(item, child)

    for child in model["tree"]["children"]:
        append(tree, child)

    return Group(
        Text(title, style="bold"),
        Text(model["summary"]),
        tree,
        *(Text(n, style="yellow") for n in model["notes"]),
        Text("Event decision only; test expectations are evaluated separately.", style="dim"),
    )


def regression_terminal_explanations(session, limit=10):
    from rich.console import Group
    from rich.text import Text

    sections = []

    for label in ("baseline", "candidate"):
        results = session.get("results", {}).get(label, [])

        for result in results[:limit]:
            sections.append(
                terminal_explanation(
                    result,
                    f"{label.title()} — event {result.get('Log Record ID', 'unknown')}",
                ),
            )

        if len(results) > limit:
            sections.append(
                Text(
                    f"{label}: {len(results) - limit} additional event explanations are available in HTML.",
                ),
            )

    return Group(*sections)
