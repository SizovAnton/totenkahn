import hashlib
from http.client import HTTPException
import json
import os
import stat
import tempfile
import sys
import time

from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from handlers.component_inventory import (
    reject_duplicate_keys,
    reject_json_constant,
    require_fields,
    require_sha256,
    require_text,
)


def validate_https_url(value: str) -> None:
    require_text(value, "Package URL")
    parsed = urlsplit(value)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(character.isspace() for character in value)
    ):
        raise ValueError("Package URL must be an HTTPS URL without credentials")


def validate_package(package: dict) -> dict:
    require_fields(
        package,
        {"component_id", "version", "url", "size", "sha256"},
        "Locked package",
    )

    require_text(package["component_id"], "Package component_id")
    require_text(package["version"], "Package version or revision")
    validate_https_url(package["url"])

    if type(package["size"]) is not int or package["size"] <= 0:
        raise ValueError("Package size must be a positive integer")

    if package["sha256"] is None:
        raise ValueError("Package SHA-256 is required")

    require_sha256(package["sha256"], "Package SHA-256")
    return package


def load_dependency_lock(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        lock = json.load(
            file,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )

    require_fields(lock, {"schema_version", "packages"}, "Dependency lock")

    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ValueError("Unsupported dependency lock schema_version")

    packages = lock["packages"]
    if not isinstance(packages, list) or not packages:
        raise ValueError("Dependency lock must contain packages")

    seen = set()

    for package in packages:
        validate_package(package)

        component_id = package["component_id"]
        if component_id in seen:
            raise ValueError(f"Duplicate locked component: {component_id}")

        seen.add(component_id)

    return lock

def verify_package_file(path: Path, package: dict) -> None:
    validate_package(package)

    metadata = path.lstat()
    
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or attributes & 0x400
    ):
        raise ValueError(f"Package cache entry must be a regular file: {path}")

    if metadata.st_size != package["size"]:
        raise ValueError(f"Package size mismatch: {path}")

    digest = hashlib.sha256()
    size = 0

    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            size += len(chunk)

            if size > package["size"]:
                raise ValueError(f"Package exceeds its locked size: {path}")

            digest.update(chunk)

    if size != package["size"]:
        raise ValueError(f"Package size mismatch: {path}")

    if digest.hexdigest() != package["sha256"]:
        raise ValueError(f"Package SHA-256 mismatch: {path}")


class HTTPSRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # HTTPS-посилання не повинне перенаправляти завантаження на HTTP.
        validate_https_url(newurl)

        return super().redirect_request(
            req, fp, code, msg, headers, newurl
        )

def obtain_package(
    package: dict,
    cache_dir: Path,
    *,
    offline: bool = False,
    timeout_seconds: int = 30,
) -> dict:
    validate_package(package)

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")

    cache_dir = Path(cache_dir)

    # Назва походить лише від перевіреного SHA-256.
    # URL або назва компонента не визначають локальний шлях.
    target = cache_dir / f"{package['sha256']}.package"

    try:
        target.lstat()
    except FileNotFoundError:
        cached = False
    else:
        cached = True

    if cached:
        # Пошкоджений кеш не використовуємо й не перезаписуємо мовчки.
        verify_package_file(target, package)
        return {
            "component_id": package["component_id"],
            "version": package["version"],
            "path": str(target),
            "sha256": package["sha256"],
            "source": "cache",
        }

    if offline:
        raise FileNotFoundError(
            f"Verified package is unavailable in offline cache: "
            f"{package['component_id']}"
        )

    cache_dir.mkdir(parents=True, exist_ok=True)

    request = Request(
        package["url"],
        headers={
            "User-Agent": "DVP-PackageFetcher/1",
            "Accept-Encoding": "identity",
        },
    )
    opener = build_opener(HTTPSRedirectHandler())
    temporary_path = None

    try:
        print(
            f"Connecting: {package['component_id']}",
            file=sys.stderr,
            flush=True,
        )
        with opener.open(request, timeout=timeout_seconds) as response:
            if response.getcode() != 200:
                raise ValueError("Package server did not return HTTP 200")

            # Перевіряємо також кінцевий URL після перенаправлень.
            validate_https_url(response.geturl())

            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=cache_dir,
                prefix=".download-",
                suffix=".part",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)
                received = 0
                started = time.monotonic()
                last_report = started

                print(
                    f"Downloading: {package['component_id']} "
                    f"({package['size']} bytes)",
                    file=sys.stderr,
                    flush=True,
                )

                while True:
                    # Це бюджет передачі між читаннями, а не жорсткий
                    # загальний таймаут DNS, з'єднання й усього встановлення.
                    if time.monotonic() - started > 300:
                        raise TimeoutError(
                            "Package download exceeded its transfer time budget"
                        )

                    # Читаємо доступну порцію, не накопичуючи блок 1 MiB.
                    chunk = response.read1(64 * 1024)
                    if not chunk:
                        break

                    received += len(chunk)
                    if received > package["size"]:
                        raise ValueError("Downloaded package exceeds locked size")

                    file.write(chunk)
                    now = time.monotonic()
                    if now - last_report >= 2 or received == package["size"]:
                        file.flush()
                        percent = received * 100 / package["size"]
                        print(
                            f"Downloading {package['component_id']}: "
                            f"{received}/{package['size']} bytes "
                            f"({percent:.1f}%)",
                            file=sys.stderr,
                            flush=True,
                        )
                        last_report = now

                file.flush()
                os.fsync(file.fileno())

        # Перевіряємо записані байти перед публікацією в кеші.
        verify_package_file(temporary_path, package)

        os.replace(temporary_path, target)
        temporary_path = None

        return {
            "component_id": package["component_id"],
            "version": package["version"],
            "path": str(target),
            "sha256": package["sha256"],
            "source": "download",
        }

    except HTTPException as exc:
        # Наприклад, IncompleteRead не є OSError; повертаємо керовану
        # помилку отримання пакета замість необробленого traceback.
        raise OSError(f"Package transfer failed: {type(exc).__name__}: {exc}") from exc
    finally:
        # Неповний або невірний пакет не залишаємо готовим до використання.
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)