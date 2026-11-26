import xml.etree.ElementTree as ET
from handlers.dump_readers import DECODER, MAX_RECORD, xml_record

SECURITY = ("Security", "Microsoft-Windows-Security-Auditing")
SYSMON = ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon")
POWERSHELL = ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell")


def field_state(present, value):
    if not present:
        return "missing"

    if value is None:
        return "null"

    if value == "":
        return "empty"

    if isinstance(value, list):
        return "multivalue"

    if isinstance(value, float):
        return "number"

    if isinstance(value, dict) or isinstance(value, bool):
        return "unsupported_type"

    return "value"


def lookup(record, path):
    value = record

    for key in path:
        if not isinstance(value, dict) or key not in value:
            return (False, None)

        value = value[key]

    return (True, value)


def mapped(record, path, prefix=None):
    present, value = lookup(record, path)

    return (
        value,
        {
            "path": (prefix or []) + path,
            "present": present,
            "original_value": value,
            "state": field_state(present, value),
            "conversion": "none",
        },
    )


def windows_fields(record, result, mapping, warnings, prefix=None):
    prefix = prefix or []
    identity = (record.get("channel"), record.get("provider"))
    event_id = str(record.get("event_id"))
    paths = {"system_user_sid": ["user"]}
    profile = "windows-generic"

    if identity == SECURITY:
        profile = "windows-security"
        paths.update(
            actor_user=["fields", "SubjectUserName"],
            actor_domain=["fields", "SubjectDomainName"],
            actor_sid=["fields", "SubjectUserSid"],
            target_user=["fields", "TargetUserName"],
            target_domain=["fields", "TargetDomainName"],
            target_sid=["fields", "TargetUserSid"],
        )

        if event_id == "4688":
            paths.update(
                process_id=["fields", "NewProcessId"],
                parent_process_id=["fields", "ProcessId"],
            )
        elif event_id == "4689":
            paths.update(process_id=["fields", "ProcessId"])
    elif identity == SYSMON:
        profile = "windows-sysmon"
        paths["actor_user"] = ["fields", "User"]
    elif identity == POWERSHELL:
        profile = "windows-powershell"
        paths["script_block"] = ["fields", "ScriptBlockText"]

    result["source_profile"] = profile

    for field, path in paths.items():
        value, trace = mapped(record, path, prefix)

        if field in {"process_id", "parent_process_id"} and trace["present"]:
            try:
                if type(value) is int:
                    number = value
                elif isinstance(value, str) and value.strip():
                    number = int(value, 16 if value.lower().startswith("0x") else 10)
                else:
                    raise ValueError("Invalid PID")

                if number < 0 or number > 4294967295:
                    raise ValueError("PID outside uint32")

                value = number
                trace["conversion"] = "pid_to_decimal_integer"
            except (ValueError, TypeError):
                trace["state"] = "conversion_error"
                warnings.append("invalid_" + field)
                value = None

        result[field], mapping[field] = (value, trace)

    for field in ("process_id", "parent_process_id"):
        if identity == SYSMON and mapping.get(field, {}).get("present"):
            value = result[field]

            try:
                if isinstance(value, bool) or not isinstance(value, (str, int)):
                    raise ValueError("Invalid PID")

                number = int(value)

                if not 0 <= number <= 4294967295:
                    raise ValueError("Invalid PID")

                result[field] = number
                mapping[field]["conversion"] = "pid_to_decimal_integer"
            except (TypeError, ValueError):
                mapping[field]["state"] = "conversion_error"
                warnings.append("invalid_" + field)
                result[field] = None

    actor = mapping.get("actor_user", {})

    if actor.get("present"):
        result["user"] = result["actor_user"]
        mapping["user"] = {**actor, "role": "actor_user_not_target"}
    else:
        mapping.setdefault("user", {})["role"] = "system_security_sid_not_target"


def decode_raw(record, raw_format):
    raw = record.get("_raw")

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("Selected raw profile requires a nonempty _raw string")

    if len(raw) > MAX_RECORD:
        raise ValueError("_raw exceeds record limit")

    if raw_format == "windows_xml":
        if "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
            raise ValueError("DTD and entities are not supported in _raw")

        try:
            element = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ValueError("Invalid Windows XML in _raw") from exc

        if element.tag.rsplit("}", 1)[-1] != "Event":
            raise ValueError("_raw must contain one Windows Event")

        return xml_record(element)

    value = DECODER.decode(raw)

    if not isinstance(value, dict):
        raise ValueError("JSON _raw must be an object in generic-v1 schema")

    return value
