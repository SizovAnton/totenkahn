import re
import ipaddress
from handlers.value_operations import NUMERIC, number, network, advanced

from rule_condition.collect_references import collect_references
from rule_condition.condition_operand_parsers import parse_condition, explain_condition
from rule_condition.prepare import prepare_condition, evaluate_condition


def sigma_pattern_to_regex(value: str) -> str:
    chunks = []
    index = 0

    while index < len(value):
        char = value[index]

        if char == "\\":
            if index + 1 < len(value) and value[index + 1] in ("*", "?", "\\"):
                chunks.append(re.escape(value[index + 1]))
                index += 1
            else:
                chunks.append(re.escape(char))
        elif char == "*":
            chunks.append(".*")
        elif char == "?":
            chunks.append(".")
        else:
            chunks.append(re.escape(char))

        index += 1

    return "".join(chunks)


def match_equals(actual: str | None, expected: str | int) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(str(expected))

    return re.fullmatch(pattern, actual, flags=re.IGNORECASE | re.DOTALL) is not None


def match_endswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.search(pattern + "\\Z", actual, flags=re.IGNORECASE | re.DOTALL) is not None


def match_contains(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.search(pattern, actual, flags=re.IGNORECASE | re.DOTALL) is not None


def check_logsource(source: dict, requirements: dict):
    checks = {}

    for key, expected in source["logsource"].items():
        if key == "definition":
            continue

        actual = requirements["source"].get(key)
        checks[key] = {"Actual": actual, "Expected": expected, "Matched": actual == expected}

    stat = all((check["Matched"] for check in checks.values()))

    return [{"Status": stat, "Checks": checks}]


def scalar_check(actual, expected, modifier, cased=False):
    if modifier in NUMERIC or modifier == "cidr":
        return advanced(actual, expected, modifier)

    if expected is None:
        return {
            "result": actual is None,
            "reason": "Explicit null comparison; empty string is not null",
        }

    if type(actual) not in (str, int):
        return {
            "result": None,
            "reason": "Text matching requires string/integer values; no implicit container/boolean/null conversion",
        }

    text = str(actual)
    pattern = sigma_pattern_to_regex(str(expected))
    flags = re.DOTALL | (0 if cased else re.IGNORECASE)

    if modifier == "contains":
        matched = re.search(pattern, text, flags=flags) is not None
    elif modifier == "startswith":
        matched = re.match(pattern, text, flags=flags) is not None
    elif modifier == "endswith":
        matched = re.search(pattern + r"\Z", text, flags=flags) is not None
    else:
        matched = re.fullmatch(pattern, text, flags=flags) is not None

    return {
        "result": matched,
        "actual_normalized": text,
        "reason": (
            "Sigma wildcard comparison; case-sensitive"
            if cased
            else "Sigma wildcard comparison; case-insensitive"
        ),
    }


def value_supported(actual, expected, modifiers, present):
    modifier, _ = parse_modifiers(modifiers)

    if modifier == "exists":
        return True

    if not present:
        return False

    if expected is None:
        return True

    values = actual if isinstance(actual, list) else [actual]

    try:
        for value in values:
            if modifier in NUMERIC:
                number(value)
            elif modifier == "cidr":
                if not isinstance(value, str) or "%" in value:
                    return False

                ipaddress.ip_address(value)
            elif type(value) not in (str, int):
                return False

        return True
    except ValueError:
        return False


def field_check(actual, expected, modifiers, present=True):
    modifier, require_all = parse_modifiers(modifiers)

    if modifier == "exists":
        return {
            "result": present == expected,
            "checks": [],
            "unknown": False,
            "reason": "Explicit presence check; present null is present",
        }

    if not present:
        return {
            "result": False,
            "checks": [],
            "unknown": False,
            "reason": "Required field is missing from the event.",
        }

    if expected is None:
        return {
            "result": actual is None,
            "checks": [{"Expected": None, "Matched": actual is None}],
            "unknown": False,
            "reason": "Explicit null comparison of the field itself; empty/multivalue is not null",
        }

    expected_values = expected if isinstance(expected, list) else [expected]
    actual_values = actual if isinstance(actual, list) else [actual]
    checks = []

    for value in expected_values:
        elements = [
            {
                "index": index,
                "actual": item,
                **scalar_check(item, value, modifier, "cased" in modifiers),
            }
            for index, item in enumerate(actual_values)
        ]
        unknown = any(item["result"] is None for item in elements)
        matched = any(item["result"] is True for item in elements)
        checks.append(
            {"Expected": value, "Matched": matched, "Unknown": unknown, "Elements": elements}
        )

    unknown = any(item["Unknown"] for item in checks)
    matched = (
        all(item["Matched"] for item in checks)
        if require_all
        else any(item["Matched"] for item in checks)
    )

    return {
        "result": matched,
        "unknown": unknown,
        "checks": checks,
        "reason": (
            "All expected values require a matching element"
            if require_all
            else "Any expected value may match any element"
        ),
    }


def evaluate_blocks(block_definition, item):
    field_checks = {}

    for rule_key, expected in block_definition.items():
        field, *modifiers = rule_key.split("|")
        actual = item.get("event_id") if field == "EventID" else item["data_fields"].get(field)
        present = "event_id" in item if field == "EventID" else field in item["data_fields"]
        checked = field_check(actual, expected, modifiers, present)
        field_checks[rule_key] = {
            "Field": field,
            "Actual": actual,
            "Expected": expected,
            "Modifiers": modifiers,
            "Field Present": present,
            "Matched": checked["result"],
            "Unknown": checked["unknown"],
            "Value Checks": checked["checks"],
            "Reason": checked["reason"],
        }

    return field_checks, all(check["Matched"] for check in field_checks.values())


def report_handler(items, sigma_rule):
    results = []
    detection = sigma_rule["detection"]
    tree = prepare_condition(detection, parse_condition, collect_references)
    references = collect_references(tree)

    for item in items:
        source_result = check_logsource(sigma_rule, item)
        source_check = source_result[0]
        selection = None
        condition_explanation = None
        block_checks = {}
        block_results = {}

        if source_check["Status"] == True:
            for block_name in sorted(references):
                field_checks, block_matched = evaluate_blocks(detection[block_name], item)
                block_checks[block_name] = field_checks
                block_results[block_name] = block_matched

            selection = evaluate_condition(tree, block_results)
            condition_explanation = explain_condition(tree, block_results)

            if any(
                check.get("Unknown")
                for fields in block_checks.values()
                for check in fields.values()
            ):
                selection = None

        if selection is None:
            selection_reason = (
                "Unsupported actual values prevent a confirmed rule decision."
                if source_check["Status"]
                else "Condition was not evaluated because the logsource does not match the rule requirements."
            )
        elif selection:
            selection_reason = "The rule condition evaluated to True."
        else:
            selection_reason = "The rule condition evaluated to False."

        values = {}

        for field_checks in block_checks.values():
            for check in field_checks.values():
                values[check["Field"]] = check["Actual"]

        res = {
            "Log Record ID": item["record_id"],
            "Run Reference": item.get("run_reference"),
            "Logsource": source_check,
            "Event Context": {
                "Computer": item["computer"],
                "Channel": item["channel"],
                "Provider": item["provider"],
            },
            "Time Created": item["system_time"],
            "Values": values,
            "Condition": detection["condition"],
            "Condition Explanation": condition_explanation,
            "Block Results": block_results,
            "Checks": block_checks,
            "Selection Reason": selection_reason,
            "Selection": selection,
        }
        results.append(res)

    return results


def validate_rule(sigma_rule):
    logsource = sigma_rule.get("logsource")
    detection = sigma_rule.get("detection")

    if not isinstance(logsource, dict) or not logsource:
        raise ValueError("Document logsource must be a non-empty dictionary")

    source_keys = ("product", "service", "category")

    if not any((key in logsource for key in source_keys)):
        raise ValueError("Rule logsource must contain product, service, or category")

    if not isinstance(detection, dict) or not detection:
        raise ValueError("Document detection must be a non-empty dictionary")

    condition = detection.get("condition")

    if not isinstance(condition, str) or not condition.split():
        raise ValueError("Document detection condition must be a non-empty string")

    tree = prepare_condition(detection, parse_condition, collect_references)
    references = collect_references(tree)

    for block_name in sorted(references):
        block = detection[block_name]

        if not isinstance(block, dict) or not block:
            raise ValueError(f"Detection block {block_name!r} must be a non-empty dictionary")

        for rule_key, expected in block.items():
            if not isinstance(rule_key, str) or not rule_key.split():
                raise ValueError(
                    f"Detection block {block_name!r} contains an invalid rule key: {rule_key!r}"
                )

            parts = rule_key.split("|")
            field = parts[0]
            modifiers = parts[1:]

            if not field.strip():
                raise ValueError(
                    f"Detection block {block_name!r} contains an invalid rule key: {rule_key!r}"
                )

            try:
                match_modifier, require_all = parse_modifiers(modifiers)
            except ValueError as e:
                raise ValueError(f"Block {block_name!r}, field {rule_key!r}: {e}") from e

            if match_modifier == "exists":
                if type(expected) is not bool:
                    raise ValueError(
                        f"The 'exists' modifier requires a boolean value: block {block_name!r}, field {rule_key!r}",
                    )

                continue

            if require_all and (not isinstance(expected, list)):
                raise ValueError(
                    f"The 'all' modifier requires a list: block {block_name!r}, field {rule_key!r}",
                )

            expected_values = expected if isinstance(expected, list) else [expected]

            if not expected_values:
                raise ValueError(
                    f"Expected values must not be empty: block {block_name!r}, field {rule_key!r}",
                )

            if expected is None:
                if modifiers:
                    raise ValueError("Null comparison does not accept modifiers")

                continue

            for value in expected_values:
                if match_modifier in NUMERIC:
                    number(value)
                elif match_modifier == "cidr":
                    network(value)
                elif match_modifier is not None or "cased" in modifiers:
                    if not isinstance(value, str):
                        raise ValueError("Text modifier requires string values")
                elif type(value) not in (str, int):
                    raise ValueError(
                        f"Unsupported value in block {block_name!r}, field {rule_key!r}: {value!r}"
                    )


def match_startswith(actual: str | None, expected: str) -> bool:
    if actual is None:
        return False

    pattern = sigma_pattern_to_regex(expected)

    return re.match(pattern, actual, flags=re.IGNORECASE | re.DOTALL) is not None


def parse_modifiers(modifiers):
    if modifiers == ["exists"]:
        return "exists", False

    require_all = modifiers[-1:] == ["all"]
    remaining = modifiers[:-1] if require_all else list(modifiers)

    if len(set(remaining)) != len(remaining):
        raise ValueError("Duplicate modifiers")

    cased = "cased" in remaining
    remaining = [item for item in remaining if item != "cased"]
    allowed = {None, "contains", "startswith", "endswith", "cidr", *NUMERIC}
    modifier = remaining[0] if remaining else None

    if len(remaining) > 1 or modifier not in allowed or (cased and modifier in NUMERIC | {"cidr"}):
        raise ValueError(f"Unsupported modifiers: {modifiers!r}")

    return modifier, require_all


def match_exists(field_present: bool, expected: bool) -> bool:
    return field_present == expected


def validate_live_logsource(sigma_rule, configuration):
    logsource = sigma_rule.get("logsource", {})
    channels = configuration["events"]["channels"]

    if not isinstance(channels, list) or not channels:
        raise ValueError("Live collection requires a non-empty list of channels")

    active_channels = set()

    for index, channel in enumerate(channels, start=1):
        if not isinstance(channel, str) or not channel.strip():
            raise ValueError(f"Event channel #{index} must be a non-empty string")

        channel_key = channel.strip().casefold()

        if channel_key in active_channels:
            raise ValueError(f"Duplicate event channel: {channel!r}")

        active_channels.add(channel_key)

    for source in configuration["sources"]:
        source_channel = source.get("channel")

        if not isinstance(source_channel, str):
            continue

        if source_channel.strip().casefold() not in active_channels:
            continue

        if "product" in logsource and logsource["product"] != source.get("product"):
            continue

        if "service" in logsource and logsource["service"] != source.get("service"):
            continue

        if "category" in logsource:
            categories = source.get("event_categories", {})

            if logsource["category"] not in categories.values():
                continue

        return

    raise ValueError(
        f"Rule logsource {logsource!r} is not supported by the configured collection channels {channels!r}",
    )
