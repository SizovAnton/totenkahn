import hashlib
import json
from pathlib import Path
from urllib.parse import quote
import zipfile

from handlers.package_cache import obtain_package, verify_package_file, validate_package
from handlers.package_extract import inspect_zip
from handlers.release_manifest import validate_release_path


def load_catalog(project, package):
    path = Path(project) / "config/atomic-files.lock.json"

    if not path.exists():
        return None

    catalog = json.loads(path.read_text(encoding="utf-8"))

    if (
        catalog.get("schema_version") != 1
        or catalog.get("archive_sha256") != package["sha256"]
        or catalog.get("revision") != package["version"]
    ):
        raise ValueError("Atomic file catalog does not match dependency lock")

    for name, metadata in catalog["files"].items():
        validate_release_path(name)

        if type(metadata.get("size")) is not int or metadata["size"] < 0:
            raise ValueError("Invalid Atomic file size")

        locked = file_package(package, name, metadata)
        validate_package(dict(locked, size=max(1, locked["size"])))

        if metadata["size"] == 0 and metadata["sha256"] != hashlib.sha256(b"").hexdigest():
            raise ValueError("Invalid empty Atomic file digest")

    return catalog["files"]


def file_package(package, name, metadata):
    return {
        "component_id": "atomic_file:" + name,
        "version": package["version"],
        "url": "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
        + quote(package["version"], safe="")
        + "/atomics/"
        + quote(name, safe="/"),
        "size": metadata["size"],
        "sha256": metadata["sha256"],
    }


class AtomicSource:

    def __init__(self, project, package, cache, *, offline=False):
        self.package = package
        self.cache = Path(cache)
        self.offline = offline
        catalog = load_catalog(project, package)
        self.files: dict = catalog if catalog is not None else {}
        self.archive = None
        self.zipped = None
        self.entries = {}

        cached_archive = self.cache / (package["sha256"] + ".package")

        if catalog is None or cached_archive.exists():
            self.archive = Path(obtain_package(package, self.cache, offline=True)["path"])
            self.zipped = zipfile.ZipFile(self.archive)
            entries = inspect_zip(self.zipped, max_entries=50000, max_unpacked_bytes=2 * 1024**3)
            prefixes = {
                name.split("/atomics/", 1)[0] + "/atomics/"
                for _, name, _ in entries
                if "/atomics/" in name
            }

            if len(prefixes) != 1:
                self.zipped.close()

                raise ValueError("Unexpected Atomic archive layout")

            prefix = prefixes.pop()
            self.entries = {
                name[len(prefix) :]: entry
                for entry, name, directory in entries
                if not directory and name.startswith(prefix)
            }

            if catalog is None:
                self.files = {
                    name: {
                        "size": entry.file_size,
                        "sha256": hashlib.sha256(self.zipped.read(entry)).hexdigest(),
                    }
                    for name, entry in self.entries.items()
                }

    def read(self, name):
        if self.zipped is not None:
            return self.zipped.read(self.entries[name])

        if self.files[name]["size"] == 0:
            return b""

        locked = file_package(self.package, name, self.files[name])
        path = Path(obtain_package(locked, self.cache, offline=self.offline)["path"])
        verify_package_file(path, locked)

        return path.read_bytes()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.zipped is not None:
            self.zipped.close()
