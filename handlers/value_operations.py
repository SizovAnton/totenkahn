from decimal import Decimal, InvalidOperation
import ipaddress
import re

NUMERIC = {"gt", "gte", "lt", "lte"}


def number(value):
    if type(value) not in (str, int, float):
        raise ValueError("Expected a decimal number, not boolean/null/container")

    text = str(value)

    if (len(text) > 256) or (
        not re.fullmatch("[+-]?(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)(?:[eE][+-]?[0-9]{1,5})?", text)
    ):
        raise ValueError("Expected finite decimal syntax (no units, hex or surrounding whitespace)")

    try:
        result = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError("Invalid decimal number") from exc

    if not result.is_finite():
        raise ValueError("Nonfinite number")

    return result


def network(value):
    if not isinstance(value, str) or "/" not in value or "%" in value:
        raise ValueError("CIDR requires an IPv4/IPv6 network with prefix length")

    return ipaddress.ip_network(value, strict=True)


def advanced(actual, expected, operation):
    try:
        if operation in NUMERIC:
            left, right = (number(actual), number(expected))
            result = {
                "gt": left > right,
                "gte": left >= right,
                "lt": left < right,
                "lte": left <= right,
            }[operation]

            return {
                "result": result,
                "actual_normalized": str(left),
                "expected_normalized": str(right),
                "reason": "Explicit finite decimal comparison",
            }

        if operation == "cidr":
            if not isinstance(actual, str) or "%" in actual:
                raise ValueError("CIDR actual value must be an unscoped IP address string")

            address, subnet = (ipaddress.ip_address(actual), network(expected))

            return {
                "result": address in subnet,
                "actual_normalized": str(address),
                "expected_normalized": str(subnet),
                "reason": "IP membership in network; different IP versions do not match",
            }

        raise ValueError("Unsupported advanced operation")
    except ValueError as exc:
        return {"result": None, "reason": str(exc)}
