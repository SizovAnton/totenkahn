import re
from handlers.evidence import canonical, digest


def seal_finding(finding):
    finding["sha256"] = digest(canonical({k: v for k, v in finding.items() if k != "sha256"}))

    return finding


def validate_findings(findings):
    if not isinstance(findings, list):
        raise ValueError("Findings must be a list")

    names = set()

    for finding in findings:
        if (not isinstance(finding, dict)) or (
            set(finding)
            != {
                "name",
                "title",
                "author",
                "reason",
                "created_at",
                "expected_match",
                "evidence",
                "origin",
                "sha256",
            }
        ):
            raise ValueError("Invalid finding fields")

        name = finding["name"]

        if (
            (not isinstance(name, str))
            or (not re.fullmatch("[A-Za-z0-9_-]{1,80}", name))
            or (name in names)
        ):
            raise ValueError("Finding name must be valid and unique")

        names.add(name)

        for key in ("title", "author", "reason", "created_at"):
            if not isinstance(finding[key], str) or not finding[key].strip():
                raise ValueError("Finding metadata must be nonempty text")

        if type(finding["expected_match"]) is not bool:
            raise ValueError("Finding expectation must be an explicit boolean")

        refs = finding["evidence"]

        if not isinstance(refs, list) or not 1 <= len(refs) <= 500:
            raise ValueError("Finding requires 1..500 evidence references")

        seen = set()

        for ref in refs:
            if set(ref) != {
                "attachment",
                "row_id",
                "event_id",
                "file_id",
                "ordinal",
                "source_sha256",
                "normalized_sha256",
            }:
                raise ValueError("Invalid finding evidence reference")

            if type(ref["row_id"]) is not int or ref["row_id"] <= 0:
                raise ValueError("Invalid finding row ID")

            key = (ref["attachment"], ref["row_id"])

            if key in seen:
                raise ValueError("Duplicate finding evidence reference")

            seen.add(key)

        expected = digest(canonical({k: v for k, v in finding.items() if k != "sha256"}))

        if expected != finding["sha256"]:
            raise ValueError("Finding checksum changed")
