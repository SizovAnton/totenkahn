import math
import re
from handlers.value_operations import NUMERIC, number, network, advanced
from handlers.evidence import canonical, digest
from handlers.evidence_selection import pointer

OPERATIONS = {
    "equals",
    "contains",
    "starts_with",
    "ends_with",
    "in",
    "exists",
    "gt",
    "gte",
    "lt",
    "lte",
    "cidr",
}


def scalar(value):
    return (
        (value is None)
        or (type(value) in {str, int, bool})
        or (type(value) is float and math.isfinite(value))
    )


def validate_expression(expression, depth=0, budget=None):
    budget = [0] if budget is None else budget
    budget[0] += 1

    if depth > 16 or budget[0] > 128 or (not isinstance(expression, dict)):
        raise ValueError("Hunt expression must be an object with at most 128 nodes and depth 16")

    operators = set(expression) & {"all", "any", "not"}

    if operators:
        if len(expression) != 1:
            raise ValueError("Logical node must contain exactly one operator")

        operation = next(iter(operators))
        children = expression[operation] if operation != "not" else [expression[operation]]

        if not isinstance(children, list) or not children:
            raise ValueError("all/any require a nonempty list")

        for child in children:
            validate_expression(child, depth + 1, budget)

        return

    if (set(expression) - {"field", "op", "value", "case_sensitive", "values"}) or (
        not {"field", "op", "value"} <= set(expression)
    ):
        raise ValueError("Predicate requires field, op, value; optional case_sensitive")

    pointer({}, expression["field"])
    operation, value = (expression["op"], expression["value"])

    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError("Unsupported hunt operation")

    if "case_sensitive" in expression and type(expression["case_sensitive"]) is not bool:
        raise ValueError("case_sensitive must be boolean")

    if "values" in expression and expression["values"] not in ("any", "all"):
        raise ValueError("values must be any or all")

    if operation in NUMERIC or operation == "cidr":
        if "case_sensitive" in expression:
            raise ValueError("Numeric/CIDR operators do not accept case_sensitive")

        number(value) if operation in NUMERIC else network(value)
    elif operation == "exists":
        if "values" in expression:
            raise ValueError("exists tests the field, not array elements")

        if type(value) is not bool or "case_sensitive" in expression:
            raise ValueError("exists requires boolean value and no case_sensitive")
    elif operation == "in":
        if (
            (not isinstance(value, list))
            or (not 1 <= len(value) <= 100)
            or any((not scalar(v) for v in value))
        ):
            raise ValueError("in requires 1..100 scalar values")
    elif operation in {"contains", "starts_with", "ends_with"}:
        if not isinstance(value, str) or not value:
            raise ValueError("Text predicates require a nonempty string")
    elif not scalar(value):
        raise ValueError("equals requires a finite JSON scalar")


def validate_definition(value):
    if (not isinstance(value, dict)) or (
        set(value) - {"schema_version", "hypothesis", "condition", "scope"}
    ):
        raise ValueError("Definition keys: schema_version, hypothesis, condition, optional scope")

    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported hunt definition version")

    if not isinstance(value.get("hypothesis"), str) or not value["hypothesis"].strip():
        raise ValueError("A human-readable hypothesis is required")

    validate_expression(value.get("condition"))

    if "scope" in value:
        validate_expression(value["scope"])

    return value


def validate_saved(hunts):
    names = set()

    if not isinstance(hunts, list):
        raise ValueError("Saved hunts must be a list")

    for hunt in hunts:
        name = hunt["name"]

        if (
            (not isinstance(name, str))
            or (not re.fullmatch("[A-Za-z0-9_-]{1,80}", name))
            or (name in names)
        ):
            raise ValueError("Invalid or duplicate hunt name")

        names.add(name)
        validate_definition(hunt["definition"])

        if digest(canonical(hunt["definition"])) != hunt["definition_sha256"]:
            raise ValueError("Hunt definition checksum changed")


def field_value(event, mapping, path):
    present, value = pointer(event, path)

    if path.count("/") == 1:
        key = path[1:].replace("~1", "/").replace("~0", "~")

        if key in mapping and (not mapping[key]["present"]):
            return (False, None)

    return (present, value)


def evaluate(expression, event, mapping):
    for operator in ("all", "any", "not"):
        if operator not in expression:
            continue

        items = expression[operator] if operator != "not" else [expression[operator]]
        children = [evaluate(item, event, mapping) for item in items]
        values = [c["result"] for c in children]

        if operator == "all":
            result = False if False in values else None if None in values else True
        elif operator == "any":
            result = True if True in values else None if None in values else False
        else:
            result = None if values[0] is None else not values[0]

        return {
            "operator": operator,
            "result": result,
            "children": children,
            "unknown_checks": sum((c["unknown_checks"] for c in children)),
            "reason": "Three-valued logic: unknown is not converted to false",
        }

    path, operation, expected = (expression["field"], expression["op"], expression["value"])
    present, actual = field_value(event, mapping, path)
    reason = "Typed scalar comparison"
    result = None
    key = path[1:].replace("~1", "/").replace("~0", "~") if path.count("/") == 1 else None
    import_state = mapping.get(key, {}).get("state")

    if import_state in {"conflict", "conversion_error"} and operation != "exists":
        reason = "Import mapping has a conflict or conversion error; review original values"
    elif present and "values" in expression:
        if not isinstance(actual, list) or not actual:
            reason = "Explicit array quantifier requires a nonempty list"
        else:
            predicate = {k: v for k, v in expression.items() if k != "values"}
            predicate["field"] = "/element"
            elements = [evaluate(predicate, {"element": item}, {}) for item in actual]
            results = [item["result"] for item in elements]

            if expression["values"] == "any":
                result = True if True in results else None if None in results else False
            else:
                result = False if False in results else None if None in results else True

            return {
                "field": path,
                "op": operation,
                "expected": expected,
                "actual": actual,
                "present": present,
                "values": expression["values"],
                "elements": elements,
                "result": result,
                "unknown_checks": sum(item["unknown_checks"] for item in elements),
                "reason": "Explicit array quantifier; no implicit flattening",
            }
    elif operation == "exists":
        result, reason = (
            present == expected,
            "Explicit field-presence test; present null is present",
        )
    elif not present:
        reason = "Field is absent at the mapped path"
    elif operation in NUMERIC or operation == "cidr":
        checked = advanced(actual, expected, operation)

        return {
            "field": path,
            "op": operation,
            "expected": expected,
            "actual": actual,
            "present": present,
            **checked,
            "unknown_checks": int(checked["result"] is None),
        }
    elif not scalar(actual):
        reason = "Arrays and objects are not scalar values; no implicit flattening"
    elif operation in {"contains", "starts_with", "ends_with"} and (not isinstance(actual, str)):
        reason = "Text predicate requires a string; value is not coerced"
    else:
        sensitive = expression.get("case_sensitive", True)

        def compare(value):
            if type(actual) is not type(value):
                return False

            if isinstance(actual, str) and isinstance(value, str) and (not sensitive):
                return actual.casefold() == value.casefold()

            return actual == value

        if operation == "equals":
            result = compare(expected)
        elif operation == "in":
            result = any((compare(item) for item in expected))
        else:
            if not isinstance(actual, str) or not isinstance(expected, str):
                raise ValueError("Text comparison requires string operands")

            left, right = (
                (actual, expected) if sensitive else (actual.casefold(), expected.casefold())
            )
            result = (
                right in left
                if operation == "contains"
                else left.startswith(right) if operation == "starts_with" else left.endswith(right)
            )

    return {
        "field": path,
        "op": operation,
        "expected": expected,
        "actual": actual,
        "present": present,
        "case_sensitive": expression.get("case_sensitive", True),
        "result": result,
        "unknown_checks": int(result is None),
        "reason": reason,
    }
