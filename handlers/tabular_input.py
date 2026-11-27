import csv
import gzip
from pathlib import Path
from hashlib import sha256
from handlers.dump_readers import MAX_RECORD

ENCODINGS = ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp1252")


def options(encoding="utf-8-sig", delimiter=None, null_value=None, max_expanded_mib=1024):
    if encoding not in ENCODINGS:
        raise ValueError("Unsupported tabular encoding")

    if delimiter is not None and (len(delimiter) != 1 or delimiter in """\x0d
"\x00"""):
        raise ValueError("Delimiter must be one character, not a newline, NUL or quote")

    if type(max_expanded_mib) is not int or not 1 <= max_expanded_mib <= 65536:
        raise ValueError("max-expanded-mib must be 1..65536")

    return {
        "encoding": encoding,
        "delimiter": delimiter,
        "null_value": null_value,
        "max_expanded_mib": max_expanded_mib,
    }


def unpack_gzip(source, target, max_bytes, progress=None):
    size = 0
    checksum = sha256()

    with gzip.GzipFile(filename=source, mode="rb") as incoming, Path(target).open("xb") as outgoing:
        while chunk := incoming.read(min(1024 * 1024, max_bytes - size + 1)):
            size += len(chunk)

            if size > max_bytes:
                raise ValueError(
                    "Expanded gzip exceeds configured limit; retained partial file is not indexed",
                )

            outgoing.write(chunk)
            checksum.update(chunk)

            if progress and size % (16 * 1024 * 1024) == 0:
                progress(f"Expanded gzip: {size} bytes")

    return {"size": size, "sha256": checksum.hexdigest()}


class RecordLines:

    def __init__(self, stream):
        self.stream = stream
        self.lines = []
        self.size = 0

    def __iter__(self):
        return self

    def __next__(self):
        line = self.stream.readline(MAX_RECORD + 1)

        if not line:
            raise StopIteration

        self.size += len(line)

        if self.size > MAX_RECORD:
            raise ValueError("Tabular record exceeds 16 MiB character limit")

        self.lines.append(line)

        return line

    def take(self):
        text = "".join(self.lines)
        self.lines = []
        self.size = 0

        return text


def tabular_records(path, kind, reader_options):
    delimiter = reader_options["delimiter"] or ("\t" if kind == "tsv" else ",")
    previous_limit = csv.field_size_limit(MAX_RECORD)

    try:
        with Path(path).open(encoding=reader_options["encoding"], newline="") as stream:
            lines = RecordLines(stream)
            reader = csv.reader(lines, delimiter=delimiter, strict=True)
            header = next(reader, None)

            if (
                (not header)
                or any((not key.strip() or "\x00" in key for key in header))
                or (len(set(header)) != len(header))
            ):
                raise ValueError("Tabular header must contain unique nonempty column names")

            lines.take()
            number = 0

            while True:
                start = reader.line_num + 1
                values = next(reader, None)

                if values is None:
                    break

                raw = lines.take()

                if not values:
                    continue

                number += 1
                locator = {"record": number, "line_start": start, "line_end": reader.line_num}

                if len(values) != len(header):
                    yield {
                        "error": f"Expected {len(header)} columns; found {len(values)}",
                        "locator": locator,
                    }
                    continue

                null_value = reader_options["null_value"]
                value = dict(
                    zip(
                        header,
                        [
                            None if null_value is not None and cell == null_value else cell
                            for cell in values
                        ],
                    ),
                )
                yield {
                    "record": value,
                    "raw": raw,
                    "locator": locator,
                    "original_cells": dict(zip(header, values)),
                }
    except csv.Error as exc:
        raise ValueError("Malformed tabular input: " + str(exc)) from exc
    finally:
        csv.field_size_limit(previous_limit)
