from copy import deepcopy
from datetime import datetime, timezone

from uuid import UUID, uuid4

INVENTORY_SCHEMA_VERSION = 1
PRESENCE_VALUES = {"unknown", "present", "absent"}
ORIGIN_VALUES = {"unknown", "preexisting", "bundled", "installed_by_totenkahn"}
SOURCE_KINDS = {"unknown", "release", "url", "local", "system"}
OPERATION_ACTIONS = {"install", "configure", "remove", "cleanup"}
OPERATION_STATUSES = {"pending", "succeeded", "failed", "interrupted"}
REMOVAL_STATUSES = {"not_assessed", "blocked", "manual_required"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_inventory() -> dict:
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "installation_id": str(uuid4()),
        "created_at": utc_now(),
        "components": [],
        "operations": [],
    }


def create_component_record(component_key: str) -> dict:
    require_text(component_key, "component_key")

    return {
        "component_id": str(uuid4()),
        "component_key": component_key.strip(),
        "presence": "unknown",
        "version": None,
        "path": None,
        "last_checked_at": None,
        "origin": "unknown",
        "installation_operation_id": None,
        "source": {"kind": "unknown", "location": None, "revision": None, "sha256": None},
        "resources": [],
        "shared": None,
        "removal": {
            "method": None,
            "status": "not_assessed",
            "reason": "Removal has not been assessed",
        },
    }


def require_fields(value, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")

    actual = set(value)
    missing = expected - actual
    unknown = actual - expected

    if missing or unknown:
        raise ValueError(
            f"{label}: missing fields={sorted(missing)!r}; unknown fields={sorted(unknown, key=str)!r}",
        )


def require_text(value, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def require_choice(value, choices: set[str], label: str) -> None:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{label} has an unsupported value: {value!r}")


def require_uuid(value, label: str) -> None:
    require_text(value, label)

    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be a UUID") from exc

    if parsed.int == 0 or str(parsed) != value:
        raise ValueError(f"{label} must be a canonical non-zero UUID")


def require_time(value, label: str) -> datetime:
    require_text(value, label)

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO datetime") from exc

    offset = parsed.utcoffset()

    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{label} must include a UTC timezone")

    return parsed


def require_sha256(value, label: str) -> None:
    if value is None:
        return

    if (
        (not isinstance(value, str))
        or (len(value) != 64)
        or any((char not in "0123456789abcdef" for char in value))
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")


def validate_component(component: dict) -> None:
    require_fields(
        component,
        {
            "component_id",
            "component_key",
            "presence",
            "version",
            "path",
            "last_checked_at",
            "origin",
            "installation_operation_id",
            "source",
            "resources",
            "shared",
            "removal",
        },
        "Component",
    )
    require_uuid(component["component_id"], "component_id")
    require_text(component["component_key"], "component_key")
    require_choice(component["presence"], PRESENCE_VALUES, "presence")
    require_choice(component["origin"], ORIGIN_VALUES, "origin")

    for field in ("version", "path"):
        require_text(component[field], field, nullable=True)

    if component["last_checked_at"] is not None:
        require_time(component["last_checked_at"], "last_checked_at")

    operation_id = component["installation_operation_id"]

    if operation_id is not None:
        require_uuid(operation_id, "installation_operation_id")

    if component["shared"] is not None and type(component["shared"]) is not bool:
        raise ValueError("shared must be a boolean or null")

    source = component["source"]
    require_fields(source, {"kind", "location", "revision", "sha256"}, "Component source")
    require_choice(source["kind"], SOURCE_KINDS, "source.kind")

    for field in ("location", "revision"):
        require_text(source[field], f"source.{field}", nullable=True)

    require_sha256(source["sha256"], "source.sha256")
    resources = component["resources"]

    if not isinstance(resources, list):
        raise ValueError("resources must be a JSON array")

    seen_resources = set()

    for resource in resources:
        require_fields(
            resource,
            {"kind", "identifier", "created_by_operation_id", "shared"},
            "Resource",
        )
        require_choice(resource["kind"], {"file", "directory", "service"}, "resource.kind")
        require_text(resource["identifier"], "resource.identifier")
        creator = resource["created_by_operation_id"]

        if creator is not None:
            require_uuid(creator, "resource.created_by_operation_id")

        if resource["shared"] is not None and type(resource["shared"]) is not bool:
            raise ValueError("resource.shared must be a boolean or null")

        key = (resource["kind"], resource["identifier"])

        if key in seen_resources:
            raise ValueError(f"Duplicate resource: {key!r}")

        seen_resources.add(key)

    removal = component["removal"]
    require_fields(removal, {"method", "status", "reason"}, "Removal")
    require_text(removal["method"], "removal.method", nullable=True)
    require_choice(removal["status"], REMOVAL_STATUSES, "removal.status")
    require_text(removal["reason"], "removal.reason")


def validate_operation(operation: dict) -> None:
    require_fields(
        operation,
        {
            "operation_id",
            "component_id",
            "action",
            "status",
            "started_at",
            "finished_at",
            "before_presence",
            "verification",
            "details",
        },
        "Operation",
    )
    require_uuid(operation["operation_id"], "operation_id")
    require_uuid(operation["component_id"], "operation.component_id")
    require_choice(operation["action"], OPERATION_ACTIONS, "action")
    require_choice(operation["status"], OPERATION_STATUSES, "status")
    require_choice(operation["before_presence"], PRESENCE_VALUES, "before_presence")
    require_choice(
        operation["verification"],
        {"not_checked", "passed", "failed", "unknown"},
        "verification",
    )
    require_text(operation["details"], "details", nullable=True)
    started_at = require_time(operation["started_at"], "started_at")

    if operation["status"] == "pending":
        if operation["finished_at"] is not None:
            raise ValueError("A pending operation cannot have finished_at")

        if operation["verification"] != "not_checked":
            raise ValueError("A pending operation must have not_checked verification")

        return

    finished_at = require_time(operation["finished_at"], "finished_at")

    if finished_at < started_at:
        raise ValueError("finished_at cannot precede started_at")

    require_text(operation["details"], "Completed operation details")

    if operation["status"] == "succeeded" and operation["verification"] != "passed":
        raise ValueError("A succeeded operation requires passed verification")


def validate_inventory(inventory: dict) -> dict:
    require_fields(
        inventory,
        {"schema_version", "installation_id", "created_at", "components", "operations"},
        "Inventory",
    )
    version = inventory["schema_version"]

    if type(version) is not int or version != INVENTORY_SCHEMA_VERSION:
        raise ValueError(f"Unsupported inventory schema_version: {version!r}")

    require_uuid(inventory["installation_id"], "installation_id")
    require_time(inventory["created_at"], "created_at")
    components = inventory["components"]
    operations = inventory["operations"]

    if not isinstance(components, list) or not isinstance(operations, list):
        raise ValueError("components and operations must be JSON arrays")

    components_by_id = {}

    for component in components:
        validate_component(component)
        component_id = component["component_id"]

        if component_id in components_by_id:
            raise ValueError(f"Duplicate component_id: {component_id}")

        components_by_id[component_id] = component

    operations_by_id = {}
    pending_components = set()

    for operation in operations:
        validate_operation(operation)
        operation_id = operation["operation_id"]
        component_id = operation["component_id"]

        if operation_id in operations_by_id:
            raise ValueError(f"Duplicate operation_id: {operation_id}")

        if component_id not in components_by_id:
            raise ValueError(f"Unknown operation component_id: {component_id}")

        if operation["status"] == "pending":
            if component_id in pending_components:
                raise ValueError(f"Multiple pending operations for: {component_id}")

            pending_components.add(component_id)

        operations_by_id[operation_id] = operation

    for component in components:
        component_id = component["component_id"]
        installation_id = component["installation_operation_id"]

        if component["origin"] == "installed_by_totenkahn":
            operation = operations_by_id.get(installation_id)

            if (
                (operation is None)
                or (operation["component_id"] != component_id)
                or (operation["action"] != "install")
                or (operation["status"] != "succeeded")
                or (operation["verification"] != "passed")
                or (operation["before_presence"] != "absent")
            ):
                raise ValueError(
                    "installed_by_totenkahn requires a verified installation of a previously absent component",
                )
        elif installation_id is not None:
            raise ValueError("installation_operation_id requires installed_by_totenkahn origin")

        for resource in component["resources"]:
            creator_id = resource["created_by_operation_id"]

            if creator_id is None:
                continue

            creator = operations_by_id.get(creator_id)

            if (
                (creator is None)
                or (creator["component_id"] != component_id)
                or (creator["action"] not in {"install", "configure"})
            ):
                raise ValueError("Resource references an invalid creation operation")

    return inventory


def reject_duplicate_keys(pairs: list) -> dict:
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key!r}")

        result[key] = value

    return result


def reject_json_constant(value: str):
    raise ValueError(f"Unsupported JSON constant: {value}")





def begin_operation(inventory: dict, component_id: str, action: str) -> tuple[dict, str]:
    validate_inventory(inventory)
    require_choice(action, OPERATION_ACTIONS, "action")
    updated = deepcopy(inventory)
    component = next(
        (item for item in updated["components"] if item["component_id"] == component_id),
        None,
    )

    if component is None:
        raise ValueError(f"Unknown component_id: {component_id}")

    if any(
        (
            item["component_id"] == component_id and item["status"] == "pending"
            for item in updated["operations"]
        ),
    ):
        raise ValueError("Component already has a pending operation")

    operation_id = str(uuid4())
    updated["operations"].append(
        {
            "operation_id": operation_id,
            "component_id": component_id,
            "action": action,
            "status": "pending",
            "started_at": utc_now(),
            "finished_at": None,
            "before_presence": component["presence"],
            "verification": "not_checked",
            "details": None,
        },
    )
    validate_inventory(updated)

    return (updated, operation_id)


def finish_operation(
    inventory: dict, operation_id: str, *, status: str, verification: str, details: str
) -> dict:
    validate_inventory(inventory)
    require_choice(status, {"succeeded", "failed", "interrupted"}, "Final operation status")
    require_text(details, "details")
    updated = deepcopy(inventory)
    operation = next(
        (item for item in updated["operations"] if item["operation_id"] == operation_id),
        None,
    )

    if operation is None:
        raise ValueError(f"Unknown operation_id: {operation_id}")

    if operation["status"] != "pending":
        raise ValueError("Only pending operations can be finished")

    operation.update(
        {
            "status": status,
            "finished_at": utc_now(),
            "verification": verification,
            "details": details,
        },
    )
    validate_inventory(updated)

    return updated
