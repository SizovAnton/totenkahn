import json
from pathlib import Path, PurePosixPath
import tempfile

from handlers.dump_readers import DECODER
from handlers.evidence import (
    PROFILES,
    canonical,
    digest,
    file_hash,
    import_dump,
    snapshot_file,
)


def recovery_inputs(dataset):
    dataset = Path(dataset).resolve()
    manifest_path = dataset / "manifest.json"

    if manifest_path.is_symlink():
        raise ValueError("Recovery manifest must not be a symlink")

    manifest = DECODER.decode(manifest_path.read_text(encoding="utf-8-sig"))

    if manifest.get("schema_version") != 1 or not manifest.get("files"):
        raise ValueError("Recovery requires a manifest with retained originals")

    originals = []
    profiles = {}
    options = {}
    names = set()

    for entry in manifest["files"]:
        name = entry.get("name", "")
        path = PurePosixPath(name)

        if (
            not name
            or path.is_absolute()
            or ".." in path.parts
            or "\\" in name
            or ":" in name
            or name.casefold() in names
        ):
            raise ValueError("Unsafe or duplicate recovery source name")

        names.add(name.casefold())
        stored = dataset / entry.get("stored", "")

        if not stored.resolve().is_relative_to(dataset / "originals") or any(
            p.is_symlink() for p in [stored, *stored.parents] if p.is_relative_to(dataset)
        ):
            raise ValueError(
                "Recovery original is outside the retained originals directory or is linked"
            )

        if not stored.is_file() or not entry.get("sha256") or file_hash(stored) != entry["sha256"]:
            raise ValueError("Recovery original is missing, incomplete or changed: " + name)

        if stored.stat().st_size != entry.get("size"):
            raise ValueError("Recovery original size changed: " + name)

        profile = entry.get("profile")

        if not isinstance(profile, dict) or digest(canonical(profile)) != entry.get(
            "profile_sha256"
        ):
            raise ValueError("Recovery source has no saved profile: " + name)

        if entry.get("format") not in {"xml", "evtx"}:
            profiles[canonical(profile)] = profile

        reader_options = entry.get("reader_options", {})
        options[canonical(reader_options)] = reader_options
        originals.append((entry, stored))

    if len(profiles) > 1 or len(options) > 1:
        raise ValueError(
            "Recovery currently requires one generic profile and one reader-options configuration; reimport mixed sources separately"
        )

    return (
        dataset,
        manifest,
        originals,
        next(iter(profiles.values()), None),
        next(iter(options.values()), {}),
    )


def recover_dump(project, dataset, output, *, timeout=600, progress=None):
    dataset, manifest, originals, profile, options = recovery_inputs(dataset)
    output = Path(output).absolute()

    if output.exists() or output.is_symlink():
        raise FileExistsError("Recovery requires a new output directory")

    if output.resolve().is_relative_to(dataset):
        raise ValueError("Recovery output must be outside the old dataset")

    manifest_hash = file_hash(dataset / "manifest.json")

    with tempfile.TemporaryDirectory(prefix="totenkahn-recovery-") as temporary:
        work = Path(temporary)
        sources = work / "sources"
        sources.mkdir()

        for entry, stored in originals:
            target = sources / entry["name"]
            target.parent.mkdir(parents=True, exist_ok=True)
            checksum, size = snapshot_file(stored, target, progress)

            if checksum != entry["sha256"] or size != entry["size"]:
                raise ValueError("Recovery source changed while copying")

        profile_argument = None

        if profile is not None:
            if PROFILES.get(profile.get("id")) == profile:
                profile_argument = profile["id"]
            else:
                profile_file = work / "profile.json"
                profile_file.write_text(json.dumps(profile), encoding="utf-8")
                profile_argument = str(profile_file)

        if file_hash(dataset / "manifest.json") != manifest_hash:
            raise ValueError("Recovery manifest changed during preparation")

        lineage = {
            "method": "restart_from_verified_retained_originals",
            "previous_dataset_id": manifest.get("dataset_id"),
            "previous_manifest_sha256": manifest_hash,
            "previous_status": manifest.get("status"),
            "retained_files": len(originals),
            "originals": [
                {key: entry[key] for key in ("name", "sha256", "size")} for entry, _ in originals
            ],
            "coverage": "Only originals listed in the old manifest; unvisited input files are not recovered",
            "old_dataset_modified": False,
        }
        report = import_dump(
            project,
            sources,
            output,
            profile=profile_argument,
            reader_options=options,
            timeout=timeout,
            progress=progress,
            recovery=lineage,
        )

    return report
