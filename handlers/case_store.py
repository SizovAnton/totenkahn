from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import shutil
from uuid import uuid4
from zipfile import ZipFile, ZIP_DEFLATED
from handlers.component_inventory import utc_now
from handlers.hunt_definition import validate_saved
from handlers.finding_contract import validate_findings
from handlers.dump_readers import DECODER
from handlers.evidence import canonical, digest, file_hash, verify_dataset, read_index
from handlers.evidence_selection import create_selection, load_selection, selected_rows


def safe_file(root, relative):
    path = root / relative

    if (
        Path(relative).is_absolute()
        or (".." in Path(relative).parts)
        or path.is_symlink()
        or (not path.resolve().is_relative_to(root.resolve()))
    ):
        raise ValueError("Unsafe evidence path")

    return path


def load_case(root):
    root = Path(root).resolve()
    value = DECODER.decode((root / "case.json").read_text(encoding="utf-8"))

    if value.get("schema_version") != 1:
        raise ValueError("Unsupported case schema")

    expected = digest(canonical({k: v for k, v in value.items() if k != "sha256"}))

    if value.get("sha256") != expected:
        raise ValueError("Case manifest changed")

    previous = None

    for index, entry in enumerate(value["history"], 1):
        if entry["revision"] != index or entry["previous"] != previous:
            raise ValueError("Case history chain is invalid")

        actual = digest(canonical({k: v for k, v in entry.items() if k != "sha256"}))

        if actual != entry["sha256"]:
            raise ValueError("Case history entry changed")

        previous = actual

    validate_saved(value.get("hunts", []))
    validate_findings(value.get("findings", []))

    return value


def save_case(root, value, action, details):
    entry = {
        "revision": len(value["history"]) + 1,
        "at": utc_now(),
        "action": action,
        "details": details,
        "previous": value["history"][-1]["sha256"] if value["history"] else None,
    }
    entry["sha256"] = digest(canonical(entry))
    value["history"].append(entry)
    value["updated_at"] = entry["at"]
    value.pop("sha256", None)
    value["sha256"] = digest(canonical(value))
    temporary = root / ("manifest-" + uuid4().hex + ".tmp")

    try:
        with temporary.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2))
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, root / "case.json")
    finally:
        temporary.unlink(missing_ok=True)

    return value


@contextmanager
def case_lock(root):
    root = Path(root).resolve()
    lock = root / ".case.lock"

    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 384)
    except FileExistsError:
        raise ValueError(
            "Case is busy or a previous operation was interrupted. Confirm no writer is running before removing .case.lock",
        ) from None

    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(str(os.getpid()))

        yield root
    finally:
        lock.unlink(missing_ok=True)


def create_case(root, title, description=""):
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Case title is required")

    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    value = {
        "schema_version": 1,
        "case_id": str(uuid4()),
        "title": title,
        "description": description,
        "created_at": utc_now(),
        "state": "open",
        "attachments": [],
        "notes": [],
        "history": [],
    }

    return save_case(root, value, "created", {"title": title})


def copy_checked(source, target, expected):
    if source.is_symlink() or not source.is_file() or file_hash(source) != expected:
        raise ValueError("Source file missing or changed: " + str(source))

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

    if file_hash(target) != expected or file_hash(source) != expected:
        raise ValueError("Source changed while copying: " + str(source))


def attachment_paths(root, attachment):
    folder = safe_file(root, attachment["directory"])

    if not folder.is_dir():
        raise ValueError("Missing attachment directory")

    return (folder / "dataset", folder / "selection")


def verify_case(root):
    root = Path(root).resolve()
    value = load_case(root)
    counts = 0
    limitations = []

    for attachment in value["attachments"]:
        dataset, selection = attachment_paths(root, attachment)

        if file_hash(selection / "selection.json") != attachment["selection_sha256"]:
            raise ValueError("Attachment selection changed")

        saved = load_selection(dataset, selection)
        result = verify_dataset(dataset)

        if result["status"] != "passed":
            raise ValueError("Attachment integrity failed: " + canonical(result))

        connection, _ = read_index(dataset)

        try:
            count = sum((1 for _ in selected_rows(connection, selection, saved)))
        finally:
            connection.close()

        if count != attachment["count"] or saved["dataset_id"] != attachment["dataset_id"]:
            raise ValueError("Attachment identity or count changed")

        counts += count

        if saved["dataset_status"] not in {"passed", "passed_with_warnings"}:
            limitations.append(
                {"attachment": attachment["id"], "dataset_status": saved["dataset_status"]},
            )

    registered = {a["directory"] for a in value["attachments"]}
    orphans = [p.name for p in root.glob(".pending-*")]
    orphans.extend(
        (
            p.name
            for p in (root / "evidence").glob("*")
            if p.relative_to(root).as_posix() not in registered
        ),
    )

    if orphans:
        limitations.append(
            {
                "unregistered_directories": orphans,
                "reason": "Interrupted operation remnants; not included in evidence or export",
            },
        )

    known = {a["id"]: a for a in value["attachments"]}

    for note in value["notes"]:
        if note["attachment"] is not None and note["attachment"] not in known:
            raise ValueError("Note points to unknown attachment")

    if value.get("findings"):
        from handlers.finding_store import verify_finding_refs

        verify_finding_refs(root, value, value["findings"])

    return {
        "status": "passed",
        "case_id": value["case_id"],
        "revision": len(value["history"]),
        "attachments": len(value["attachments"]),
        "events": counts,
        "limitations": limitations,
        "scope": "Local snapshot integrity, not authenticated chain of custody or evidence completeness",
    }


def add_dataset(root, dataset, selection=None, label=None):
    dataset = Path(dataset).resolve()

    with case_lock(root) as root:
        value = load_case(root)

        if value["state"] != "open":
            raise ValueError("Case is closed; reopen it before editing")

        if root == dataset or root.is_relative_to(dataset) or dataset.is_relative_to(root):
            raise ValueError("Case and incoming dataset must be separate directories")

        chosen_label = label or dataset.name

        if not isinstance(chosen_label, str) or not chosen_label.strip():
            raise ValueError("Attachment label must be nonempty")

        if any((a["label"] == chosen_label for a in value["attachments"])):
            raise ValueError("Attachment label already attached; choose --label")

        result = verify_dataset(dataset)

        if result["status"] != "passed":
            raise ValueError("Incoming dataset failed integrity verification")

        manifest_path = dataset / "manifest.json"
        manifest_hash = file_hash(manifest_path)
        manifest = DECODER.decode(manifest_path.read_text(encoding="utf-8"))
        identifier = "evidence-" + uuid4().hex[:12]
        directory = "evidence/" + identifier
        pending = root / (".pending-" + uuid4().hex)
        pending.mkdir()
        destination = None
        committed = False

        try:
            target = pending / "dataset"
            copy_checked(manifest_path, target / "manifest.json", manifest_hash)
            copy_checked(
                dataset / "index.sqlite",
                target / "index.sqlite",
                manifest["index_sha256"],
            )

            for source in manifest["files"]:
                relative = source["stored"]
                copy_checked(
                    safe_file(dataset, relative),
                    safe_file(target, relative),
                    source["sha256"],
                )

                if "expanded" in source:
                    expanded = source["expanded"]
                    copy_checked(
                        safe_file(dataset, expanded["stored"]),
                        safe_file(target, expanded["stored"]),
                        expanded["sha256"],
                    )

            if verify_dataset(target)["status"] != "passed":
                raise ValueError("Copied dataset failed integrity verification")

            if selection is None:
                saved = create_selection(target, pending / "selection", {})
            else:
                selection = Path(selection).resolve()
                load_selection(dataset, selection)
                (pending / "selection").mkdir()

                for name in ("selection.json", "members.jsonl"):
                    copy_checked(
                        selection / name,
                        pending / "selection" / name,
                        file_hash(selection / name),
                    )

                saved = load_selection(target, pending / "selection")

            if file_hash(manifest_path) != manifest_hash:
                raise ValueError("Dataset changed during attachment")

            if any(
                (
                    (
                        (a["dataset_id"] == saved["dataset_id"])
                        and (a["members_sha256"] == saved["members_sha256"])
                    )
                    for a in value["attachments"]
                ),
            ):
                raise ValueError("This dataset selection is already attached")

            entry = {
                "id": identifier,
                "label": chosen_label,
                "directory": directory,
                "dataset_id": saved["dataset_id"],
                "count": saved["count"],
                "dataset_status": saved["dataset_status"],
                "members_sha256": saved["members_sha256"],
                "selection_sha256": file_hash(pending / "selection/selection.json"),
                "added_at": utc_now(),
            }
            destination = safe_file(root, directory)
            destination.parent.mkdir(exist_ok=True)
            os.rename(pending, destination)
            value["attachments"].append(entry)
            save_case(root, value, "attached", entry)
            committed = True

            return entry
        finally:
            if pending.exists():
                shutil.rmtree(pending)

            if destination is not None and destination.exists() and (not committed):
                persisted = load_case(root)

                if not any((a["directory"] == directory for a in persisted["attachments"])):
                    shutil.rmtree(destination)


def add_note(root, text, author, attachment=None, row=None, tags=None):
    if not text.strip() or not author.strip():
        raise ValueError("Nonempty note text and author are required")

    if row is not None and (attachment is None or type(row) is not int or row <= 0):
        raise ValueError("A positive row reference requires an attachment")

    with case_lock(root) as root:
        value = load_case(root)

        if value["state"] != "open":
            raise ValueError("Case is closed; reopen it before editing")

        event_id = None

        if attachment is not None:
            matches = [
                a for a in value["attachments"] if a["id"] == attachment or a["label"] == attachment
            ]

            if len(matches) != 1:
                raise ValueError("Unknown or ambiguous attachment ID/label")

            attachment = matches[0]["id"]
            dataset, selection = attachment_paths(root, matches[0])
            saved = load_selection(dataset, selection)

            if row is not None:
                connection, _ = read_index(dataset)

                try:
                    for item in selected_rows(connection, selection, saved):
                        if item[0] == row:
                            event_id = item[1]

                    if event_id is None:
                        raise ValueError("Row is outside the attached selection")
                finally:
                    connection.close()

        tags = sorted(set(tags or []))

        if any((not isinstance(tag, str) or not tag.strip() for tag in tags)):
            raise ValueError("Tags must be nonempty strings")

        note = {
            "id": str(uuid4()),
            "at": utc_now(),
            "author": author,
            "text": text,
            "tags": tags,
            "attachment": attachment,
            "row": row,
            "event_id": event_id,
            "kind": "analyst_annotation_not_observed_event",
        }
        value["notes"].append(note)
        save_case(
            root,
            value,
            "noted",
            {"note_id": note["id"], "note_sha256": digest(canonical(note))},
        )

        return note


def export_case(root, archive):
    root, archive = (Path(root).resolve(), Path(archive).resolve())

    if archive.is_relative_to(root):
        raise ValueError("Export must be outside the case")

    with case_lock(root):
        verification = verify_case(root)
        value = load_case(root)
        paths = [root / "case.json"]

        for attachment in value["attachments"]:
            dataset, selection = attachment_paths(root, attachment)
            manifest = DECODER.decode((dataset / "manifest.json").read_text(encoding="utf-8"))
            paths.extend(
                [
                    dataset / "manifest.json",
                    dataset / "index.sqlite",
                    selection / "selection.json",
                    selection / "members.jsonl",
                ],
            )
            paths.extend((safe_file(dataset, s["stored"]) for s in manifest["files"]))
            paths.extend(
                safe_file(dataset, s["expanded"]["stored"])
                for s in manifest["files"]
                if "expanded" in s
            )

        archive.parent.mkdir(parents=True, exist_ok=True)

        with archive.open("xb") as stream:
            with ZipFile(stream, "w", ZIP_DEFLATED) as output:
                for path in sorted(set(paths)):
                    output.write(path, path.relative_to(root).as_posix())

        with ZipFile(archive) as check:
            for path in sorted(set(paths)):
                with check.open(path.relative_to(root).as_posix()) as stream:
                    checksum = hashlib.sha256()

                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        checksum.update(block)

                    actual = checksum.hexdigest()

                if actual != file_hash(path):
                    raise ValueError("Export changed during packaging")

        verify_case(root)

        return {
            "status": "passed",
            "archive": str(archive),
            "sha256": file_hash(archive),
            "verification": verification,
        }


def set_state(root, state, author, reason):
    if state not in {"open", "closed"} or not author.strip() or (not reason.strip()):
        raise ValueError("State requires open/closed, author and reason")

    with case_lock(root) as root:
        value = load_case(root)

        if value["state"] == state:
            raise ValueError("Case already has this state")

        if state == "closed":
            verify_case(root)

        previous = value["state"]
        value["state"] = state
        save_case(
            root,
            value,
            "state_changed",
            {"previous": previous, "state": state, "author": author, "reason": reason},
        )

        return {"status": "passed", "state": state, "case_id": value["case_id"]}
