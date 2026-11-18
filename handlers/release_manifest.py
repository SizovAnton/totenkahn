import argparse
import hashlib
import json
import stat

from pathlib import Path

from handlers.component_inventory import (
    reject_duplicate_keys,
    reject_json_constant,
    require_fields,
    require_sha256,
    require_text,
    require_time,
    utc_now,
)


MANIFEST_NAME = "release-manifest.json"
MANIFEST_SCHEMA_VERSION = 1

REQUIRED_FILES = {
    "dvp.exe",
    "dvp-setup.exe",
    "config/components.json",
    "config/dependencies.lock.json",
    "config/default.config",
    "config/config.json",
    "scripts/invoke_atomic.ps1",
    "scripts/watch_windows_events.ps1",
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.txt",
}

RESERVED_NAMES = (
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)

def validate_release_path(value: str) -> str:
    require_text(value, "Release file path")

    if "\\" in value:
        raise ValueError("Release paths must use forward slashes")

    parts = value.split("/")

    for part in parts:
        if not part or part in {".", ".."}:
            raise ValueError(f"Invalid release path: {value!r}")

        if part.endswith((" ", ".")):
            raise ValueError(f"Invalid Windows path segment: {part!r}")

        if any(
            ord(character) < 32 or character in '<>:"|?*'
            for character in part
        ):
            raise ValueError(f"Invalid Windows path segment: {part!r}")

        # CON.txt теж є зарезервованим Windows-іменем.
        base_name = part.split(".", 1)[0].upper()

        if base_name in RESERVED_NAMES:
            raise ValueError(f"Reserved Windows path segment: {part!r}")

    return value

def validate_commit(value: str) -> None:
    require_text(value, "source_commit")

    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("source_commit must be a full lowercase Git commit hash")

def validate_manifest(manifest: dict) -> dict:
    require_fields(
        manifest,
        {
            "schema_version",
            "product",
            "version",
            "source_commit",
            "created_at",
            "files",
        },
        "Release manifest",
    )

    schema_version = manifest["schema_version"]
    if type(schema_version) is not int or schema_version != MANIFEST_SCHEMA_VERSION:
        raise ValueError("Unsupported release manifest schema_version")

    if manifest["product"] != "DVP":
        raise ValueError("Unexpected release product")

    require_text(manifest["version"], "Release version")
    validate_commit(manifest["source_commit"])
    require_time(manifest["created_at"], "Release created_at")

    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise ValueError("Release files must be a non-empty JSON array")

    paths = set()
    folded_paths = set()

    for item in files:
        require_fields(item, {"path", "size", "sha256"}, "Release file")

        path = validate_release_path(item["path"])
        folded = path.casefold()

        if folded == MANIFEST_NAME.casefold():
            raise ValueError("The manifest cannot include itself")

        if folded in folded_paths:
            raise ValueError(f"Duplicate release path: {path}")

        if type(item["size"]) is not int or item["size"] < 0:
            raise ValueError(f"Invalid file size: {path}")

        # В обліку компонентів невідомий хеш допустимий.
        # У готовому маніфесті хеш обов'язковий.
        if item["sha256"] is None:
            raise ValueError(f"Missing SHA-256: {path}")
        require_sha256(item["sha256"], f"SHA-256 for {path}")

        paths.add(path)
        folded_paths.add(folded)

    # Один шлях не може одночасно бути файлом і батьківським каталогом.
    for path in paths:
        parts = path.casefold().split("/")
        for index in range(1, len(parts)):
            if "/".join(parts[:index]) in folded_paths:
                raise ValueError(f"File/directory path conflict: {path}")

    missing = REQUIRED_FILES - paths
    if missing:
        raise ValueError(f"Missing required release files: {sorted(missing)!r}")

    if not any(path.startswith("examples/") for path in paths):
        raise ValueError("Release must include at least one example file")

    return manifest

def checked_stat(path: Path):
    metadata = path.lstat()

    # FILE_ATTRIBUTE_REPARSE_POINT у Windows.
    reparse_point = 0x400
    attributes = getattr(metadata, "st_file_attributes", 0)

    if stat.S_ISLNK(metadata.st_mode) or attributes & reparse_point:
        raise ValueError(f"Linked paths are not supported in releases: {path}")

    return metadata

def collect_release_files(root: Path) -> dict[str, Path]:
    root = Path(root)
    root_metadata = checked_stat(root)

    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"Release root must be a directory: {root}")

    files = {}
    seen_paths = set()

    def visit(directory: Path) -> None:
        for child in sorted(directory.iterdir(), key=lambda item: item.name):
            relative = child.relative_to(root).as_posix()
            validate_release_path(relative)

            folded = relative.casefold()
            if folded in seen_paths:
                raise ValueError(f"Conflicting release path: {relative}")
            seen_paths.add(folded)

            metadata = checked_stat(child)

            if stat.S_ISDIR(metadata.st_mode):
                visit(child)

            elif stat.S_ISREG(metadata.st_mode):
                # Сам маніфест перевіряємо окремо.
                if relative != MANIFEST_NAME:
                    files[relative] = child

            else:
                raise ValueError(f"Unsupported release entry: {relative}")

    visit(root)
    return files

def describe_file(path: Path) -> dict:
    before = checked_stat(path)

    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"Expected a regular file: {path}")

    digest = hashlib.sha256()
    size = 0

    with path.open("rb") as file:
        # Не завантажуємо великий exe або DLL повністю в пам'ять.
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)

    after = checked_stat(path)

    # Виявляємо звичайну зміну файла під час читання.
    # Каталог складання все одно має бути незмінним під час перевірки.
    before_identity = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    )
    after_identity = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    )

    if before_identity != after_identity or size != after.st_size:
        raise ValueError(f"File changed while being read: {path}")

    return {
        "size": size,
        "sha256": digest.hexdigest(),
    }

def build_manifest(
    root: Path,
    *,
    version: str,
    source_commit: str,
) -> dict:
    require_text(version, "Release version")
    validate_commit(source_commit)

    actual_files = collect_release_files(root)

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "product": "DVP",
        "version": version,
        "source_commit": source_commit,
        "created_at": utc_now(),
        "files": [
            {
                "path": relative,
                **describe_file(path),
            }
            for relative, path in sorted(actual_files.items())
        ],
    }

    return validate_manifest(manifest)

def write_manifest(root: Path, manifest: dict) -> Path:
    validate_manifest(manifest)
    path = Path(root) / MANIFEST_NAME

    payload = json.dumps(
        manifest,
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    ) + "\n"

    # Режим x не дозволяє мовчки переписати вже створений маніфест.
    # Новий реліз готуємо в новому каталозі складання.
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(payload)

    return path

def load_manifest(root: Path) -> dict:
    path = Path(root) / MANIFEST_NAME
    metadata = checked_stat(path)

    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Release manifest must be a regular file")

    with path.open("r", encoding="utf-8") as file:
        manifest = json.load(
            file,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )

    return validate_manifest(manifest)

def verify_release(root: Path) -> dict:
    root = Path(root)
    manifest = load_manifest(root)

    expected = {
        item["path"]: item
        for item in manifest["files"]
    }
    actual = collect_release_files(root)

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))

    changed = []
    errors = []

    for relative in sorted(set(expected) & set(actual)):
        try:
            observed = describe_file(actual[relative])
        except (OSError, ValueError) as exc:
            errors.append({
                "path": relative,
                "reason": str(exc),
            })
            continue

        wanted = expected[relative]

        if (
            observed["size"] != wanted["size"]
            or observed["sha256"] != wanted["sha256"]
        ):
            changed.append({
                "path": relative,
                "expected": {
                    "size": wanted["size"],
                    "sha256": wanted["sha256"],
                },
                "actual": observed,
            })

    return {
        "status": (
            "passed"
            if not (missing or unexpected or changed or errors)
            else "failed"
        ),
        "version": manifest["version"],
        "source_commit": manifest["source_commit"],
        "checked_at": utc_now(),
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
        "errors": errors,
    }

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and verify DVP release manifests"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build_parser = commands.add_parser("build")
    build_parser.add_argument("--root", type=Path, required=True)
    build_parser.add_argument("--version", required=True)
    build_parser.add_argument("--commit", required=True)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--root", type=Path, required=True)

    args = parser.parse_args()

    try:
        if args.command == "build":
            manifest = build_manifest(
                args.root,
                version=args.version,
                source_commit=args.commit,
            )
            write_manifest(args.root, manifest)

        # Після створення також перевіряємо записаний комплект.
        result = verify_release(args.root)

    except (OSError, ValueError) as exc:
        print(json.dumps({
            "status": "error",
            "reason": str(exc),
        }, ensure_ascii=False, indent=2))
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2))

    # 0 — комплект відповідає маніфесту.
    # 1 — комплект перевірено, але знайдено невідповідності.
    # 2 — перевірку неможливо коректно виконати.
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
