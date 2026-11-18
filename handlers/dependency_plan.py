import json

from pathlib import Path

from handlers.component_inventory import (
    reject_duplicate_keys,
    reject_json_constant,
    require_choice,
    require_fields,
    require_text,
    utc_now,
)
from handlers.environment_check import SUPPORTED_MODES

def load_component_catalog(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        catalog = json.load(
            file,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )

    return validate_component_catalog(catalog)

def validate_component_catalog(catalog: dict) -> dict:
    require_fields(
        catalog,
        {"schema_version", "components"},
        "Component catalog",
    )

    version = catalog["schema_version"]
    if type(version) is not int or version != 1:
        raise ValueError("Unsupported component catalog schema_version")

    components = catalog["components"]
    if not isinstance(components, list) or not components:
        raise ValueError("Component catalog must contain components")

    ids = set()
    check_ids = set()

    for component in components:
        require_fields(
            component,
            {"id", "modes", "check_id", "delivery"},
            "Catalog component",
        )

        require_text(component["id"], "Component ID")
        require_text(component["check_id"], "Component check_id")
        require_choice(
            component["delivery"],
            {"system", "release", "external"},
            "Component delivery",
        )

        if component["id"] in ids:
            raise ValueError(f"Duplicate component ID: {component['id']}")

        if component["check_id"] in check_ids:
            raise ValueError(
                f"Duplicate component check_id: {component['check_id']}"
            )

        ids.add(component["id"])
        check_ids.add(component["check_id"])

        modes = component["modes"]
        if not isinstance(modes, list) or not modes:
            raise ValueError("Component modes must be a non-empty array")

        seen_modes = set()
        for mode in modes:
            require_choice(mode, SUPPORTED_MODES, "Component mode")

            if mode in seen_modes:
                raise ValueError(f"Duplicate component mode: {mode}")

            seen_modes.add(mode)

    return catalog

def choose_action(component: dict, check: dict | None) -> tuple[str, str]:
    if check is None:
        return (
            "inspect",
            "No observation was produced for this component",
        )

    if check["status"] == "passed":

        return (
            "retain",
            "Keep the detected component; do not reinstall it based on this check",
        )

    details = check.get("details")
    presence = (
        details.get("presence")
        if isinstance(details, dict)
        else None
    )

    if presence != "absent":
        return (
            "inspect",
            "Absence is not confirmed; resolve the diagnostic result first",
        )

    if component["delivery"] == "release":
        return (
            "restore_release",
            "Restore the missing file from a verified DVP release",
        )

    if component["delivery"] == "system":
        return (
            "repair_system",
            "Determine the supported Windows component recovery procedure",
        )

    return (
        "prepare_install",
        "Component is absent; a verified package and installer are still required",
    )

def build_dependency_plan(environment: dict, catalog: dict) -> dict:
    validate_component_catalog(catalog)

    if not isinstance(environment, dict):
        raise ValueError("Environment report must be an object")

    mode = environment.get("mode")
    require_choice(mode, SUPPORTED_MODES, "Environment mode")

    checks = environment.get("checks")
    if not isinstance(checks, list):
        raise ValueError("Environment checks must be an array")

    checks_by_id = {}

    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("Environment check must be an object")

        check_id = check.get("id")
        require_text(check_id, "Check ID")
        require_choice(
            check.get("status"),
            {"passed", "failed", "unknown"},
            "Check status",
        )
        require_text(check.get("reason"), "Check reason")

        if check_id in checks_by_id:
            raise ValueError(f"Duplicate environment check ID: {check_id}")

        checks_by_id[check_id] = check

    items = []
    mapped_checks = set()

    for component in catalog["components"]:
        if mode not in component["modes"]:
            continue

        check_id = component["check_id"]
        check = checks_by_id.get(check_id)
        action, reason = choose_action(component, check)
        mapped_checks.add(check_id)

        items.append({
            "component_id": component["id"],
            "delivery": component["delivery"],
            "check_id": check_id,
            "observed_status": (
                check["status"] if check is not None else "unknown"
            ),
            "action": action,
            "reason": reason,
        })

    unresolved_checks = [
        {
            "id": check["id"],
            "status": check["status"],
            "reason": check["reason"],
        }
        for check in checks
        if check["id"] not in mapped_checks
        and check["status"] != "passed"
    ]

    needs_work = (
        any(item["action"] != "retain" for item in items)
        or bool(unresolved_checks)
    )

    return {
        "schema_version": 1,
        "mode": mode,
        "created_at": utc_now(),
        "status": "needs_action" if needs_work else "no_action",
        "executable": False,
        "items": items,
        "unresolved_checks": unresolved_checks,
    }

def validate_lock_coverage(catalog: dict, lock: dict) -> None:
    from handlers.package_cache import validate_package

    validate_component_catalog(catalog)
    require_fields(lock, {"schema_version", "packages"}, "Dependency lock")

    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ValueError("Unsupported dependency lock schema_version")

    packages = lock["packages"]
    if not isinstance(packages, list):
        raise ValueError("Locked packages must be an array")

    locked_ids = set()

    for package in packages:
        validate_package(package)
        component_id = package["component_id"]

        if component_id in locked_ids:
            raise ValueError(f"Duplicate locked component: {component_id}")

        locked_ids.add(component_id)

    external_ids = {
        component["id"]
        for component in catalog["components"]
        if component["delivery"] == "external"
    }

    missing = external_ids - locked_ids
    unexpected = locked_ids - external_ids

    if missing or unexpected:
        raise ValueError(
            f"Dependency lock does not match the component catalog: "
            f"missing={sorted(missing)!r}; "
            f"unexpected={sorted(unexpected)!r}"
        )