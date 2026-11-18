import csv
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
import json
import math
from handlers.detection_context import validate_context_profile
from hashlib import sha256

def load_session_metadata(session_dir: Path):
    metadata_path = session_dir / "session.json"

    try:
        with metadata_path.open("r", encoding="utf-8") as file:
            metadata = json.load(file)
    except FileNotFoundError:
        return None

    if not isinstance(metadata, dict):
        raise ValueError("Session metadata must be a JSON object")

    schema_version = metadata.get("schema_version")

    if type(schema_version) is not int or schema_version != 1:
        raise ValueError(
            f"Unsupported session schema_version: {schema_version!r}"
        )

    session_id = metadata.get("session_id")

    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Session metadata must include a non-empty session_id")

    mode = metadata.get("mode")

    if mode not in ("manual", "auto"):
        raise ValueError(f"Unsupported session mode: {mode!r}")

    collection = metadata.get("collection")

    if not isinstance(collection, dict):
        raise ValueError("Session collection must be a JSON object")

    status = collection.get("status")

    if status not in ("in_progress", "completed", "incomplete"):
        raise ValueError(f"Unsupported collection status: {status!r}")

    if status != "completed":
        raise ValueError(
            f"Session collection is {status!r}; replay requires 'completed'"
        )

    producer = metadata.get("producer")

    if not isinstance(producer, dict):
        raise ValueError("Session producer must be a JSON object")

    normalizer_version = producer.get("normalizer_version")
    if type(normalizer_version) is not int or normalizer_version !=1:
        raise ValueError(f"Unsupported normalizer_version: {normalizer_version!r}")

    profiles_snapshot = metadata.get("profiles_snapshot")

    if not isinstance(profiles_snapshot, dict):
        raise ValueError("Session profiles_snapshot must be a JSON object")

    defaults = profiles_snapshot.get("defaults")

    if not isinstance(defaults, dict):
        raise ValueError("Session profiles_snapshot.defaults must be a JSON object")

    windows_defaults = defaults.get("windows_event_log")

    if not isinstance(windows_defaults, dict) or not windows_defaults:
        raise ValueError("Session defaults.windows_event_log must be "
            "a non-empty JSON object")

    sources = profiles_snapshot.get("sources")

    if not isinstance(sources, list):
        raise ValueError("Session profiles_snapshot.sources must be a JSON array")

    for number, source_profile in enumerate(sources, start=1):
        if not isinstance(source_profile, dict):
            raise ValueError (f"Session source profile #{number} must be a JSON object")

        for field in ("channel", "provider"):
            value = source_profile.get(field)

            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Session source profile #{number}: "
                    f"{field} must be a non-empty string")

        categories = source_profile.get("event_categories", {})

        if not isinstance(categories, dict):
            raise ValueError(f"Session source profile #{number}: "
                f"event_categories must be a JSON object")
            
    for profile in [windows_defaults, *sources]:
        validate_context_profile(profile)
    
    return metadata

def load_manual_test_context(path:Path):
    with path.open('r', encoding="utf-8") as file:
        context = json.load(file)

    if not isinstance(context, dict):
        raise ValueError("Manual test context must be a JSON object")

    allowe_fields = {
        "description",
        "notes",
        "expected_rule_match"
    }
    unknown_fields = set(context) - allowe_fields

    if unknown_fields:
        raise ValueError(f"Unknown manual test context fields: "
            f"{', '.join(sorted(unknown_fields))}")

    description = context.get("description")

    if not isinstance(description, str) or not description.strip():
        raise ValueError("Manual test description must be a non-empty string")

    notes = context.get("notes", "")

    if not isinstance(notes, str):
        raise ValueError("Manual test notes must be a string")

    expected_rule_match = context.get("expected_rule_match")

    if(expected_rule_match is not None
       and type(expected_rule_match) is not bool):
        raise ValueError("expected_rule_match must be true, false, or null")

    return{
        "schema_version": 1,
        "source": "engineer",
        "description": description.strip(),
        "notes": notes,
        "expectation":{
            "scope": "all_session_events",
            "expected_rule_match": expected_rule_match
        }
    }

def load_csv_file(path: str | Path):

    with open(path, encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        res = list(reader)

    return res

def load_xml_file(path: str):
    tree = ET.parse(path)
    root = tree.getroot()

    return root

def load_sigma_rule(yaml_file, *, with_snapshot=False):
    rule_bytes = Path(yaml_file).read_bytes()

    rule_text = rule_bytes.decode("utf-8")
    settings = yaml.safe_load(rule_text)

    if not isinstance(settings, dict):
        raise ValueError("Sigma rule must be a YAML object")

    if not with_snapshot:
        return settings

    snapshpt = {
        "format": "yaml",
        "encoding": "utf-8",
        "text": rule_text,
        "sha256": sha256(rule_bytes).hexdigest()
    }

    return settings, snapshpt

def load_sources_confsg(path):
    with open(path, encoding="utf-8") as file:
        return json.load(file)

def merge_config(base, overrides):
    copy = base.copy()

    for key, value in overrides.items():
        if isinstance(copy.get(key), dict) and isinstance(value, dict):
            copy[key] = merge_config(copy[key], value)
        else:
            copy[key] = value

    return copy

def load_configuration(default_path, override_path):
    default = load_sources_confsg(default_path)

    if not isinstance(default, dict):
        raise ValueError(f"Configuration must be a JSON object: {default_path}")

    try:
        override = load_sources_confsg(override_path)
    except FileNotFoundError:
        override = {}
    
    if not isinstance(override, dict):
        raise ValueError(f"Configuration must be a JSON object: {override_path}")

    merged = merge_config(default, override)
    for profile in [merged['defaults']['windows_event_log'], *merged['sources']]:
        validate_context_profile(profile)
    return merged

def load_test_case(path: Path):
    with path.open("r", encoding="utf-8") as file:
        test_case = json.load(file)

    return validate_test_case(test_case)

def validate_test_case(test_case):

    def require_fields(value, expected, label):
        if not isinstance(value, dict):
            raise ValueError(f"{label} must be an object")

        missing = expected - set(value)
        unknown = set(value) - expected

        if missing:
            raise ValueError(
                f"{label}: missing fields: {', '.join(sorted(missing))}"
            )

        if unknown:
            raise ValueError(
                f"{label}: unknown fields: {', '.join(sorted(unknown))}"
            )

    if not isinstance(test_case, dict):
        raise ValueError("Test case must be an object")

    version = test_case.get("schema_version")
    if type(version) is not int or version not in (1, 2):
        raise ValueError("Unsupported test case schema_version")

    require_fields(
        test_case,
        {
            "schema_version",
            "case_id",
            "session_id",
            "description",
            "evidence",
            "expectation",
        } | ({"telemetry"} if version == 2 else set()),
        "Test case",
    )

    for field in ("case_id", "session_id", "description"):
        value = test_case[field]

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Test case {field} must be a non-empty string")

    evidence = test_case["evidence"]

    require_fields(
        evidence,
        {"method", "reason", "record_ids"},
        "Test case evidence",
    )

    if evidence["method"] != "manual_record_ids":
        raise ValueError("Unsupported evidence selection method")

    reason = evidence["reason"]

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Evidence reason must be a non-empty string")

    record_ids = evidence["record_ids"]

    if not isinstance(record_ids, list):
        raise ValueError("Evidence record_ids must be a list")

    seen = set()

    for record_id in record_ids:
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("Evidence record ID must be a non-empty string")

        if record_id in seen:
            raise ValueError(f"Duplicate evidence record ID: {record_id}")

        seen.add(record_id)

    expectation = test_case["expectation"]

    require_fields(
        expectation,
        {"scope", "expected_rule_match"},
        "Test case expectation",
    )

    if expectation["scope"] != "selected_events":
        raise ValueError("Unsupported test case expectation scope")

    if type(expectation["expected_rule_match"]) is not bool:
        raise ValueError("expected_rule_match must be true or false")

    if version == 2:
        telemetry = test_case["telemetry"]
        require_fields(telemetry, {"scope", "requirements"}, "Telemetry")
        if telemetry["scope"] != "selected_events":
            raise ValueError("Unsupported telemetry scope")
        requirements = telemetry["requirements"]
        if not isinstance(requirements, list) or not requirements:
            raise ValueError("Telemetry requirements must be a non-empty list")

        def validate_path(path):
            if (not isinstance(path, list) or not path
                    or any(not isinstance(key, str) or not key.strip() for key in path)):
                raise ValueError("Field path must be a non-empty list of non-empty strings")

        requirement_ids = set()
        
        for requirement in requirements:
            require_fields(requirement, {"id", "selector", "min_count", "required_fields"},
                           "Telemetry requirement")
            requirement_id = requirement["id"]
            if not isinstance(requirement_id, str) or not requirement_id.strip():
                raise ValueError("Telemetry requirement id must be a non-empty string")
            if requirement_id in requirement_ids:
                raise ValueError(f"Duplicate telemetry requirement id: {requirement_id}")
            requirement_ids.add(requirement_id)
            if type(requirement["min_count"]) is not int or requirement["min_count"] < 1:
                raise ValueError("Telemetry min_count must be a positive integer")

            selector = requirement["selector"]
            if not isinstance(selector, list):
                raise ValueError("Telemetry selector must be a list")
            paths = set()
            
            for predicate in selector:
                require_fields(predicate, {"path", "equals"}, "Telemetry selector predicate")
                validate_path(predicate["path"])
                path_key = tuple(predicate["path"])
                if path_key in paths:
                    raise ValueError("Duplicate selector field path")
                paths.add(path_key)
                value = predicate["equals"]
                if (value is not None and type(value) not in (str, int, float, bool)
                        or type(value) is float and not math.isfinite(value)):
                    raise ValueError("Selector equals must be a finite JSON scalar")

            fields = requirement["required_fields"]
            if not isinstance(fields, list):
                raise ValueError("Telemetry required_fields must be a list")
            paths = set()
            for path in fields:
                validate_path(path)
                if tuple(path) in paths:
                    raise ValueError("Duplicate required field path")
                paths.add(tuple(path))

    return test_case


def load_regression_suite(path: Path):
    path = path.resolve()
    
    with path.open(encoding="utf-8") as file:
        suite = json.load(file)
    
    if not isinstance(suite, dict) or set(suite) != {"schema_version", "suite_id", "description", "cases"}:
        raise ValueError("Regression suite must contain schema_version, suite_id, description and cases")
    
    if type(suite["schema_version"]) is not int or suite["schema_version"] != 1:
        raise ValueError("Unsupported regression suite schema_version")
    
    for key in ("suite_id", "description"):
        if not isinstance(suite[key], str) or not suite[key].strip():
            raise ValueError(f"Suite {key} must be a non-empty string")
    
    if not isinstance(suite["cases"], list) or not suite["cases"]:
        raise ValueError("Regression suite cases must be a non-empty list")
    
    entries = []
    seen = set()
    
    for entry in suite["cases"]:
        if not isinstance(entry, dict) or set(entry) != {"test_case", "session"}:
            raise ValueError("Suite entries must contain test_case and session only")
        
        for key in ("test_case", "session"):
            if not isinstance(entry[key], str) or not entry[key].strip():
                raise ValueError(f"Suite entry {key} must be a non-empty path")
        
        case_path = (path.parent / entry["test_case"]).resolve()
        session_dir = (path.parent / entry["session"]).resolve()
        identity = (case_path, session_dir)
        
        if identity in seen:
            raise ValueError("Duplicate regression suite entry")
        
        seen.add(identity)
        entries.append({"case_path": case_path, "session_dir": session_dir})
    
    return suite, entries

def load_regression_session(session_dir: Path):

    from handlers.events import config_handler

    metadata = load_session_metadata(session_dir)
    
    if metadata is None:
        raise ValueError("Regression requires a saved session passport")
    
    with (session_dir / "events.json").open(encoding="utf-8") as file:
        events = json.load(file)
    if not isinstance(events, list):
        raise ValueError("Session events must be a list")
    
    seen = set()
    
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Session event must be an object")
        
        for key in ("record_id", "channel", "provider", "event_id", "computer", "system_time"):
            if not isinstance(event.get(key), str) or not event[key].strip():
                raise ValueError(f"Session event {key} must be a non-empty string")
        
        if event["record_id"] in seen:
            raise ValueError(f"Duplicate event record_id: {event['record_id']}")
        
        seen.add(event["record_id"])
        
        if not isinstance(event.get("data_fields"), dict):
            raise ValueError("Session event data_fields must be an object")
        
        expected_source = config_handler(event["channel"], event["provider"],
                                         metadata["profiles_snapshot"], event["event_id"])
        
        if event.get("source") != expected_source:
            raise ValueError("Saved event source does not match session profiles_snapshot")
    
    return metadata, events
