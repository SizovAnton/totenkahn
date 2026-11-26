import re
from pathlib import Path
from handlers.case_store import case_lock, load_case, save_case
from handlers.component_inventory import utc_now
from handlers.evidence import canonical, digest
from handlers.hunt_definition import validate_definition, validate_saved


def define_hunt(root, name, definition, author):
    if not re.fullmatch("[A-Za-z0-9_-]{1,80}", name) or not author.strip():
        raise ValueError("Hunt requires a valid name and nonempty author")

    validate_definition(definition)

    with case_lock(root) as root:
        case = load_case(root)

        if case["state"] != "open":
            raise ValueError("Case is closed; reopen it before defining a hunt")

        hunts = case.setdefault("hunts", [])
        validate_saved(hunts)

        if any((h["name"] == name for h in hunts)):
            raise ValueError("Hunt name already exists; use a new name for a revised hypothesis")

        entry = {
            "name": name,
            "author": author,
            "created_at": utc_now(),
            "definition": definition,
            "definition_sha256": digest(canonical(definition)),
        }
        hunts.append(entry)
        save_case(
            Path(root),
            case,
            "hunt_defined",
            {"name": name, "definition_sha256": entry["definition_sha256"], "author": author},
        )

        return entry


def get_hunt(case, name):
    hunts = case.get("hunts", [])
    validate_saved(hunts)
    matches = [hunt for hunt in hunts if hunt["name"] == name]

    if len(matches) != 1:
        raise ValueError("Unknown hunt name")

    return matches[0]
