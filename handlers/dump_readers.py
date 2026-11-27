import json
from pathlib import Path
import xml.etree.ElementTree as ET
from handlers.component_inventory import reject_duplicate_keys, reject_json_constant

MAX_RECORD = 16 * 1024 * 1024
DECODER = json.JSONDecoder(
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_json_constant,
)


class JsonStream:

    def __init__(self, stream):
        self.stream = stream
        self.buffer = ""
        self.offset = 0
        self.eof = False

    def more(self):
        chunk = self.stream.read(65536)
        self.buffer += chunk
        self.eof = not chunk

        if len(self.buffer) > MAX_RECORD + 65536:
            raise ValueError("JSON record exceeds 16 MiB character limit")

    def take(self, count):
        self.offset += count
        self.buffer = self.buffer[count:]

    def peek(self):
        while True:
            count = len(self.buffer) - len(self.buffer.lstrip())
            self.take(count)

            if self.buffer or self.eof:
                return self.buffer[:1]

            self.more()

    def require(self, text):
        if self.peek() != text:
            raise ValueError(f"Expected {text!r} at character {self.offset}")

        self.take(1)

    def value(self):
        self.peek()
        start = self.offset

        while True:
            try:
                value, end = DECODER.raw_decode(self.buffer)

                if end == len(self.buffer) and (not self.eof):
                    self.more()
                    continue

                raw = self.buffer[:end]

                if len(raw) > MAX_RECORD:
                    raise ValueError("JSON record exceeds 16 MiB character limit")

                self.take(end)

                return (value, raw, start)
            except json.JSONDecodeError:
                if self.eof:
                    raise ValueError(f"Invalid JSON at character {start}")

                self.more()

    def array(self):
        self.require("[")

        if self.peek() == "]":
            self.take(1)

            return

        while True:
            yield self.value()
            token = self.peek()
            self.take(1)

            if token == "]":
                return

            if token != ",":
                raise ValueError(f"Invalid array separator at character {self.offset}")

    def document(self, splunk):
        if self.peek() == "[":
            yield from self.array()

            return

        if self.peek() != "{" or not splunk:
            yield self.value()

            return

        start = self.offset
        self.require("{")
        values = {}
        found_results = False
        metadata_size = 0

        if self.peek() == "}":
            self.take(1)
            yield ({}, "{}", start)

            return

        while True:
            key, _, _ = self.value()

            if not isinstance(key, str) or key in values:
                raise ValueError("Invalid or duplicate Splunk envelope key")

            self.require(":")

            if key == "results":
                found_results = True
                values[key] = None
                yield from self.array()
            else:
                values[key], encoded, _ = self.value()
                metadata_size += len(encoded) + len(key)

                if metadata_size > MAX_RECORD:
                    raise ValueError("Splunk object metadata/record exceeds limit")

            token = self.peek()
            self.take(1)

            if token == "}":
                break

            if token != ",":
                raise ValueError("Invalid Splunk envelope separator")

        if not found_results:
            yield (values, json.dumps(values, ensure_ascii=False), start)


def json_records(path, *, lines=False, splunk=False):
    with Path(path).open(encoding="utf-8-sig") as stream:
        if lines:
            number = 0

            while True:
                raw = stream.readline(MAX_RECORD + 1)

                if not raw:
                    break

                number += 1

                if len(raw) > MAX_RECORD:
                    raise ValueError(f"JSONL line {number} exceeds limit")

                if not raw.strip():
                    continue

                try:
                    value = DECODER.decode(raw)
                    yield {"record": value, "raw": raw, "locator": {"line": number}}
                except (ValueError, TypeError) as exc:
                    yield {"error": str(exc), "locator": {"line": number}}

            return

        reader = JsonStream(stream)
        number = 0

        while reader.peek():
            for value, raw, offset in reader.document(splunk):
                number += 1
                yield {
                    "record": value,
                    "raw": raw,
                    "locator": {"record": number, "character": offset},
                }


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def xml_record(event):
    system = next((child for child in event if local_name(child.tag) == "System"), None)

    if system is None:
        raise ValueError("Windows Event has no System element")

    values = {local_name(child.tag): child for child in system}

    def text(name):
        element = values.get(name)

        return element.text if element is not None else None

    fields = {}

    for child in event:
        if local_name(child.tag) == "EventData":
            for index, field in enumerate(child):
                name = field.get("Name", f"unnamed_{index}")
                value = field.text or ""

                if name in fields:
                    previous = fields[name]
                    fields[name] = (
                        [*previous, value] if isinstance(previous, list) else [previous, value]
                    )
                else:
                    fields[name] = value

    user_data = []

    for child in event:
        if local_name(child.tag) == "UserData":

            def preserve(element):
                return {
                    "tag": element.tag,
                    "attributes": dict(element.attrib),
                    "text": element.text,
                    "children": [preserve(item) for item in element],
                }

            user_data.append(preserve(child))

    provider = values.get("Provider")
    created = values.get("TimeCreated")
    security = values.get("Security")

    return {
        "timestamp": created.get("SystemTime") if created is not None else None,
        "host": text("Computer"),
        "event_id": text("EventID"),
        "native_record_id": text("EventRecordID"),
        "channel": text("Channel"),
        "provider": provider.get("Name") if provider is not None else None,
        "user": security.get("UserID") if security is not None else None,
        "fields": fields,
        "user_data": user_data,
    }


def reject_xml_declarations(path):
    tail = b""

    with Path(path).open("rb") as stream:
        while chunk := stream.read(65536):
            text = (tail + chunk).replace(b"\x00", b"").upper()

            if b"<!DOCTYPE" in text or b"<!ENTITY" in text:
                raise ValueError("DTD and entity declarations are not supported")

            tail = chunk[-64:]


def xml_records(path):
    reject_xml_declarations(path)

    with Path(path).open("rb") as original:
        yield from bounded_xml_records(original)


def bounded_xml_records(original):
    stack = []
    number = 0

    class Reader:

        def __init__(self):
            self.pending = 0

        def read(self, size=-1):
            chunk = original.read(min(size, 65536) if size > 0 else 65536)
            self.pending += len(chunk)

            if self.pending > MAX_RECORD:
                raise ValueError("XML bytes between completed events exceed limit")

            return chunk

    reader = Reader()

    for action, element in ET.iterparse(reader, events=("start", "end")):
        if action == "start":
            stack.append(element)
            continue

        if local_name(element.tag) == "Event":
            number += 1
            reader.pending = 0
            raw = ET.tostring(element, encoding="unicode")

            try:
                if len(raw) > MAX_RECORD:
                    raise ValueError("XML event exceeds 16 MiB character limit")

                yield {"record": xml_record(element), "raw": raw, "locator": {"event": number}}
            except ValueError as exc:
                yield {"error": str(exc), "locator": {"event": number}}

            if len(stack) > 1:
                stack[-2].remove(element)

            element.clear()

        stack.pop()

    if number == 0:
        raise ValueError("No Windows Event elements found")
