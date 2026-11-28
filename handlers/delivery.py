import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

from handlers.component_inventory import utc_now, reject_duplicate_keys, reject_json_constant
from handlers.installation import plain_path, local_path, installation_lock
from handlers.release_manifest import MANIFEST_NAME, describe_file, verify_release


SCOPE = "Verified executable delivery and five-stage offline acceptance; not live readiness"


def default_root():
    base = os.environ.get("LOCALAPPDATA")

    return plain_path((Path(base) if base else Path.home() / ".local/share") / "totenkahn-delivery")


def read_json(path):
    return json.loads(
        plain_path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_json_constant,
    )


def atomic_json(path, value):
    path = plain_path(path)
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Release ID must be the 64-character lowercase manifest SHA-256")

    return value


def inspect_release(release, expected):
    release = plain_path(release)
    identity(expected)
    manifest = local_path(release, MANIFEST_NAME)

    if describe_file(manifest)["sha256"] != expected:
        raise ValueError("Release manifest differs from the reviewed SHA-256")

    integrity = verify_release(release)

    if describe_file(manifest)["sha256"] != expected:
        raise ValueError("Release manifest changed during verification")

    if integrity["status"] != "passed":
        raise ValueError("Release integrity failed: " + json.dumps(integrity))

    return {"status": "passed", "release_id": expected, "integrity": integrity, "scope": SCOPE}


def slot(root, release_id):
    return local_path(root, "releases/" + identity(release_id))


def read_state(root):
    path = local_path(root, "state.json")

    if not path.exists():
        return {"schema_version": 1, "active": None, "previous": None, "history": []}

    state = read_json(path)

    if not isinstance(state, dict) or state.get("schema_version") != 1 or not isinstance(state.get("history"), list):
        raise ValueError("Invalid delivery state")

    for key in ("active", "previous"):
        if key not in state:
            raise ValueError("Incomplete delivery state")

        if state[key] is not None:
            identity(state[key])

    return state


def stage(root, release, expected):
    root, release = plain_path(root), plain_path(release)
    inspect_release(release, expected)

    if root == release or root.is_relative_to(release) or release.is_relative_to(root):
        raise ValueError("Source release and delivery store must be separate directories")

    root.mkdir(parents=True, exist_ok=True)

    with installation_lock(root):
        destination = slot(root, expected)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if destination.exists():
            result = inspect_release(destination, expected)
            return dict(result, repeated=True, release_directory=str(destination))

        temporary = plain_path(root / ("staging-" + str(uuid4())))
        shutil.copytree(release, temporary, symlinks=True)
        inspect_release(temporary, expected)
        inspect_release(release, expected)
        os.replace(temporary, destination)

    return {"status": "passed", "release_id": expected, "release_directory": str(destination), "active_changed": False}


def validate_offline(report):
    from handlers.offline_acceptance import STAGES

    if (
        report.get("status") != "passed"
        or report.get("scope") != "five_stage_synthetic_offline_acceptance"
        or report.get("selected_stages") != [1, 2, 3, 4, 5]
        or report.get("atomic_tests_executed") != 0
        or report.get("host_configuration_changes") is not False
        or report.get("external_services_used") != []
    ):
        raise ValueError("Complete five-stage offline acceptance did not pass")

    stages = report.get("stages", [])

    if len(stages) != len(STAGES):
        raise ValueError("Acceptance is missing stages")

    for actual, (stage_id, _, checks) in zip(stages, STAGES):
        actual_checks = actual.get("checks", [])

        if (
            actual.get("id") != stage_id
            or actual.get("status") != "passed"
            or len(actual_checks) != len(checks)
            or [check.get("name") for check in actual_checks] != checks
            or any(check.get("status") != "passed" for check in actual_checks)
        ):
            raise ValueError("Acceptance failed or omitted checks: " + stage_id)


def execute(arguments, work, name, environment, timeout):
    with (work / (name + ".stdout.txt")).open("wb") as stdout, (work / (name + ".stderr.txt")).open("wb") as stderr:
        result = subprocess.run(
            arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            env=environment, cwd=work, timeout=timeout, check=False,
        )

    if result.returncode != 0:
        raise ValueError(f"{name} failed with exit {result.returncode}; see {work}")


def test_release(root, release_id, timeout=600):
    if sys.platform != "win32":
        raise ValueError("Executable delivery acceptance must run on Windows")

    root = plain_path(root)
    release = slot(root, release_id)

    with installation_lock(root):
        inspect_release(release, release_id)
        local_path(root, "tested/" + release_id + ".json").unlink(missing_ok=True)
        work = local_path(root, "tests/" + str(uuid4()))
        work.mkdir(parents=True, exist_ok=False)
        environment = dict(os.environ, TOTENKAHN_HOME=str(work / "isolated-data"), NO_COLOR="1", PYTHONUTF8="1")
        receipt = {"status": "error", "release_id": release_id, "scope": SCOPE, "started_at": utc_now(), "platform": sys.platform}

        try:
            execute([str(release / "totenkahn-setup.exe"), "--help"], work, "setup-help", environment, 30)
            execute([str(release / "totenkahn.exe"), "--help"], work, "application-help", environment, 30)
            execute(
                [str(release / "totenkahn.exe"), "self-test", "offline", "--output-dir", str(work / "offline"), "--json"],
                work, "offline", environment, timeout,
            )
            validate_offline(read_json(work / "offline/report.json"))
            inspect_release(release, release_id)
            receipt.update(status="passed", atomic_tests_executed=0)
            receipt["files"] = {
                name: describe_file(local_path(work, name))
                for name in ("offline/report.json", "setup-help.stdout.txt", "setup-help.stderr.txt", "application-help.stdout.txt", "application-help.stderr.txt", "offline.stdout.txt", "offline.stderr.txt")
            }
        except Exception as exc:
            receipt["reason"] = str(exc)
        finally:
            receipt["finished_at"] = utc_now()
            atomic_json(work / "receipt.json", receipt)

        if receipt["status"] == "passed":
            record = {"receipt": work.relative_to(root).as_posix() + "/receipt.json", "digest": describe_file(work / "receipt.json")}
            pointer = local_path(root, "tested/" + release_id + ".json")
            pointer.parent.mkdir(parents=True, exist_ok=True)
            atomic_json(pointer, record)

    return dict(receipt, report=str(work / "receipt.json"))


def acceptance_record(root, release_id, record=None):
    if record is None:
        record = read_json(local_path(root, "tested/" + identity(release_id) + ".json"))

    receipt_path = local_path(root, record["receipt"])

    if describe_file(receipt_path) != record["digest"]:
        raise ValueError("Acceptance receipt changed")

    receipt = read_json(receipt_path)

    if receipt.get("status") != "passed" or receipt.get("release_id") != release_id or receipt.get("platform") != "win32":
        raise ValueError("No successful Windows acceptance for this release")

    if "offline/report.json" not in receipt["files"]:
        raise ValueError("Missing offline report binding")

    for name, digest in receipt["files"].items():
        if describe_file(local_path(receipt_path.parent, name)) != digest:
            raise ValueError("Acceptance evidence changed: " + name)

    validate_offline(read_json(receipt_path.parent / "offline/report.json"))

    return record


def accepted_record(state, release_id):
    for entry in reversed(state["history"]):
        if entry.get("release_id") == release_id and entry.get("action") == "activate":
            return entry["acceptance"]

    raise ValueError("Previous release has no activation approval")


def promote(root, release_id=None, *, reviewer, reason, approved=False, rollback=False):
    if not approved or not reviewer.strip() or not reason.strip():
        raise ValueError("Activation/rollback requires -y, --reviewer and a non-empty --reason confirming reviewed limitations")

    root = plain_path(root)

    with installation_lock(root):
        state = read_state(root)
        target = state["previous"] if rollback else identity(release_id)

        if rollback and release_id is not None and target != identity(release_id):
            raise ValueError("Previous release differs from the reviewed rollback target")

        if target is None:
            raise ValueError("No previously accepted release is available for rollback")

        inspect_release(slot(root, target), target)
        record = acceptance_record(root, target, accepted_record(state, target) if rollback else None)

        if state["active"] == target and accepted_record(state, target) == record:
            return {"status": "passed", "active": target, "repeated": True}

        if state["active"] != target:
            state["previous"], state["active"] = state["active"], target
        state["history"].append({
            "action": "rollback" if rollback else "activate", "release_id": target,
            "previous": state["previous"], "reviewer": reviewer, "reason": reason,
            "at": utc_now(), "acceptance": record,
        })
        atomic_json(root / "state.json", state)

    return dict(state, status="passed", scope=SCOPE, user_data_changed=False)


def status(root):
    root = plain_path(root)
    state = read_state(root)

    if state["active"] is not None:
        inspect_release(slot(root, state["active"]), state["active"])
        acceptance_record(root, state["active"], accepted_record(state, state["active"]))

    return dict(state, status="passed" if state["active"] else "needs_action", scope=SCOPE)


def run_active(root, arguments):
    if sys.platform != "win32":
        raise ValueError("The delivered executable requires Windows")

    root = plain_path(root)

    with installation_lock(root):
        current = status(root)

        if current["active"] is None:
            raise ValueError("No active release; stage, test and activate first")

        executable = slot(root, current["active"]) / "totenkahn.exe"
        environment = dict(os.environ)

        if "TOTENKAHN_HOME" not in environment:
            from handlers.runtime_paths import data_root
            environment["TOTENKAHN_HOME"] = str(data_root())

        application_data = plain_path(environment["TOTENKAHN_HOME"])

        if application_data == root or application_data.is_relative_to(root):
            raise ValueError("Application data must be outside the delivery store")

        return subprocess.call([str(executable), *arguments], env=environment)
