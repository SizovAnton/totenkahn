import hashlib
# import shutil
import stat
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path
from handlers.package_cache import verify_package_file
from handlers.release_manifest import validate_release_path

def inspect_zip(archive: zipfile.ZipFile, *, max_entries: int, max_unpacked_bytes: int) -> list:
    entries = archive.infolist()

    if not entries:
        raise ValueError('Package archive is empty')

    if len(entries) > max_entries:
        raise ValueError('Package archive contains too many entries')

    explicit_paths = set()
    known_paths = {}
    total_size = 0
    file_count = 0
    result = []

    for entry in entries:
        if entry.orig_filename != entry.filename:
            raise ValueError('Archive entry name was normalized')

        is_directory = entry.is_dir()
        relative = entry.filename[:-1] if is_directory else entry.filename
        validate_release_path(relative)
        folded = relative.casefold()

        if folded in explicit_paths:
            raise ValueError(f'Duplicate archive entry: {relative}')

        explicit_paths.add(folded)

        if entry.flag_bits & 1:
            raise ValueError(f'Encrypted archive entry is unsupported: {relative}')

        if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            raise ValueError(f'Unsupported ZIP compression: {relative}')

        unix_mode = entry.external_attr >> 16
        entry_type = stat.S_IFMT(unix_mode)
        expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG

        if entry_type not in {0, expected_type}:
            raise ValueError(f'Links and special files are unsupported: {relative}')

        if entry.external_attr & 1024:
            raise ValueError(f'Reparse entries are unsupported: {relative}')

        if is_directory and entry.file_size != 0:
            raise ValueError(f'Directory entry contains data: {relative}')

        parts = relative.split('/')

        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            key = prefix.casefold()
            kind = 'directory' if index < len(parts) or is_directory else 'file'
            previous = known_paths.get(key)

            if previous is not None and previous != (prefix, kind):
                raise ValueError(f'Conflicting archive path or casing: {prefix}')

            known_paths[key] = (prefix, kind)

        total_size += entry.file_size

        if total_size > max_unpacked_bytes:
            raise ValueError('Package exceeds the unpacked size limit')

        if not is_directory:
            file_count += 1

        result.append((entry, relative, is_directory))

    if file_count == 0:
        raise ValueError('Package archive contains no files')

    return result

def extract_files(archive: zipfile.ZipFile, entries: list, destination: Path, *, max_unpacked_bytes: int) -> list[dict]:
    files = []
    total_written = 0

    for entry, relative, is_directory in entries:
        target = destination.joinpath(*relative.split('/'))

        if is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        written = 0

        with archive.open(entry, 'r') as source, target.open('xb') as output:
            while (chunk := source.read(1024 * 1024)):
                written += len(chunk)
                total_written += len(chunk)

                if written > entry.file_size:
                    raise ValueError(f'Archive entry exceeds its declared size: {relative}')

                if total_written > max_unpacked_bytes:
                    raise ValueError('Unpacked data exceeds the size limit')

                output.write(chunk)
                digest.update(chunk)

        if written != entry.file_size:
            raise ValueError(f'Archive entry size mismatch: {relative}')

        files.append({'path': relative, 'size': written, 'sha256': digest.hexdigest()})

    return files

@contextmanager
def prepare_zip_package(package_path: Path, package: dict, *, staging_parent: Path, max_entries: int=50000, max_unpacked_bytes: int=2 * 1024 * 1024 * 1024):
    for name, value in (('max_entries', max_entries), ('max_unpacked_bytes', max_unpacked_bytes)):
        if type(value) is not int or value <= 0:
            raise ValueError(f'{name} must be a positive integer')

    package_path = Path(package_path)
    staging_parent = Path(staging_parent)
    verify_package_file(package_path, package)
    staging_parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='totenkahn-stage-', dir=staging_parent) as temporary:
        work_dir = Path(temporary)
        snapshot = work_dir / 'package.zip'
        payload_dir = work_dir / 'payload'
        payload_dir.mkdir()
        copied = 0

        with package_path.open('rb') as source, snapshot.open('xb') as output:
            while (chunk := source.read(1024 * 1024)):
                copied += len(chunk)

                if copied > package['size']:
                    raise ValueError('Package changed while being copied')

                output.write(chunk)

        verify_package_file(snapshot, package)

        with zipfile.ZipFile(snapshot, 'r') as archive:
            entries = inspect_zip(archive, max_entries=max_entries, max_unpacked_bytes=max_unpacked_bytes)
            files = extract_files(archive, entries, payload_dir, max_unpacked_bytes=max_unpacked_bytes)

        yield {
            'component_id': package['component_id'],
            'version': package['version'],
            'package_sha256': package['sha256'],
            'directory': str(payload_dir),
            'files': files,
        }
