import hashlib
import json
import math
import socket
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import UUID
import yaml
from handlers.component_inventory import utc_now
from handlers.installation import plain_path
from handlers.process_control import terminate_process


class ResourcesNotReady(ValueError):
    pass


class LifecycleError(RuntimeError):

    def __init__(self, report):
        self.report = report
        super().__init__(report.get("reason", report["status"]))


def parse_inputs(values):
    result = {}

    for value in values or []:
        key, sep, text = value.partition("=")

        if not sep or not key or key in result:
            raise ValueError("Inputs must be unique NAME=VALUE pairs")

        result[key] = text

    return result


def build_plan(
    config,
    technique,
    number,
    *,
    inputs=None,
    timeout=120,
    cleanup=False,
    prepare=False,
    definition_bytes=None,
):
    technique = str(technique).strip().upper()

    if not re.fullmatch("T\\d{4}(?:\\.\\d{3})?", technique):
        raise ValueError("Technique must be T1234 or T1234.001")

    if type(number) is not int or number < 1:
        raise ValueError("Test number must be positive")

    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Atomic timeout must be between 1 and 3600 seconds per command")

    atomic = config["atomic"]

    for key in ("module_path", "yaml_module_path"):
        if not plain_path(Path(atomic[key])).is_file():
            raise ValueError("Required module manifest is missing: " + key)

    selected = atomic.get("selected_tests", {}).get(f"{technique}:{number}")

    if atomic.get("managed_catalog") and (not selected or selected.get("status") != "passed"):
        raise ResourcesNotReady(
            "Selected test resources are not prepared; run dependencies prepare-test --technique "
            + technique
            + " --test-number "
            + str(number),
        )

    root = plain_path(Path(selected["atomics_path"] if selected else atomic["atomics_path"]))

    if selected:
        for name, expected in selected["files"].items():
            file = plain_path(root / name)

            if (not file.is_file()) or (
                hashlib.sha256(file.read_bytes()).hexdigest() != expected["sha256"]
            ):
                raise ResourcesNotReady("Prepared resource is missing or modified: " + name)

    path = plain_path(root / technique / (technique + ".yaml"))
    raw = path.read_bytes() if definition_bytes is None else definition_bytes
    definition = yaml.safe_load(raw.decode("utf-8-sig"))

    if not isinstance(definition, dict) or definition.get("attack_technique") != technique:
        raise ValueError("Definition does not match the selected technique")

    tests = definition.get("atomic_tests")

    if not isinstance(tests, list) or number > len(tests):
        raise ValueError("Selected test number is not present")

    test = tests[number - 1]

    if "windows" not in test.get("supported_platforms", []):
        raise ValueError("Selected test does not support Windows")

    executor = test["executor"]

    if executor.get("name") not in {"powershell", "command_prompt"}:
        raise ValueError(
            "Automatic execution supports Windows PowerShell and command_prompt tests only",
        )

    guid = str(test["auto_generated_guid"])
    UUID(guid)
    specs = test.get("input_arguments") or {}
    inputs = inputs or {}

    if not isinstance(specs, dict) or set(inputs) - set(specs):
        raise ValueError("Unknown Atomic input argument")

    resolved = {}

    for key, spec in specs.items():
        value = inputs.get(key, spec.get("default"))

        if value is None or isinstance(value, (dict, list)):
            raise ValueError(f"Missing or invalid input: {key}")

        value = str(value)

        if "\x00" in value:
            raise ValueError("Input contains a null character")

        if spec.get("type") == "integer":
            int(value)

        if spec.get("type") == "float" and (not math.isfinite(float(value))):
            raise ValueError(f"Input must be finite: {key}")

        resolved[key] = value

    def render(text):
        if not isinstance(text, str):
            raise ValueError("Atomic commands must be strings")

        for key, value in resolved.items():
            text = text.replace("#{" + key + "}", value)

        text = text.replace("$PathToAtomicsFolder", str(root)).replace(
            "PathToAtomicsFolder",
            str(root),
        )

        if re.search("#\\{[^}]+\\}", text):
            raise ValueError("Unresolved Atomic input placeholder")

        return text

    dependencies = []
    dep_executor = test.get("dependency_executor_name") or executor["name"]

    for index, dep in enumerate(test.get("dependencies") or [], 1):
        if dep_executor not in {"powershell", "command_prompt"}:
            raise ValueError("Unsupported prerequisite executor")

        check = render(dep["prereq_command"]).strip()

        if not check:
            raise ValueError("Empty prerequisite check")

        if dep_executor == "command_prompt":
            check = check.replace("\n", " && ")

        dependencies.append(
            {
                "number": index,
                "description": render(dep.get("description", "")),
                "executor": dep_executor,
                "check": check,
                "prepare": render(dep.get("get_prereq_command") or ""),
            },
        )

    command = render(executor["command"]).strip()

    if not command:
        raise ValueError("Empty Atomic command")

    pins = {str(path): hashlib.sha256(raw).hexdigest()}
    resource_roots = (
        [root / family for family in selected["asset_techniques"]]
        if selected
        else [root / technique]
    )
    trees = (
        *resource_roots,
        Path(atomic["module_path"]).parent,
        Path(atomic["yaml_module_path"]).parent,
    )

    for folder in trees:
        for file in folder.rglob("*"):
            plain_path(file)

            if file.is_file():
                pins[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()

    return {
        "schema_version": 1,
        "preview_only": definition_bytes is not None,
        "technique": technique,
        "test_number": number,
        "test_guid": guid,
        "name": test.get("name", ""),
        "definition": str(path),
        "definition_sha256": pins[str(path)],
        "executor": executor["name"],
        "elevation_required": bool(executor.get("elevation_required", False)),
        "inputs": resolved,
        "command": command,
        "dependencies": dependencies,
        "cleanup_command": render(executor.get("cleanup_command") or ""),
        "cleanup_requested": bool(cleanup),
        "prepare_requested": bool(prepare),
        "timeout_seconds": timeout,
        "resource_roots": [str(p) for p in resource_roots],
        "module_path": str(plain_path(Path(atomic["module_path"]))),
        "yaml_module_path": str(plain_path(Path(atomic["yaml_module_path"]))),
        "pins": pins,
        "tree_roots": [str(p) for p in trees],
        "limitations": "Prerequisite checks execute definition code. Preparation may change the host. Cleanup is the definition command, not a verified rollback; external resources are not automatically owned or removed.",
    }


def public_plan(plan):
    return {key: value for key, value in plan.items() if key not in {"pins", "tree_roots"}}


def verify_plan(plan):
    if plan.get("preview_only"):
        raise ValueError("Preview plan cannot execute; prepare selected resources first")

    observed = set()

    for root in plan["tree_roots"]:
        for path in plain_path(Path(root)).rglob("*"):
            plain_path(path)

            if path.is_file():
                observed.add(str(path))

    if observed != set(plan["pins"]):
        raise ValueError("Atomic component file inventory changed after approval")

    for name, digest in plan["pins"].items():
        if hashlib.sha256(plain_path(Path(name)).read_bytes()).hexdigest() != digest:
            raise ValueError("Atomic definition or component changed after approval: " + name)

    module = Path(plan["module_path"])

    if (module.parent.parent / "privateConfig.ps1").exists():
        raise ValueError("Unexpected ART privateConfig.ps1")


def record_prepared_additions(plan):
    for name, digest in plan["pins"].items():
        if hashlib.sha256(plain_path(Path(name)).read_bytes()).hexdigest() != digest:
            raise ValueError("Prerequisite preparation changed a previously approved file: " + name)

    additions = {}

    for folder in plan.get("resource_roots", []):
        for file in plain_path(Path(folder)).rglob("*"):
            plain_path(file)

            if file.is_file() and str(file) not in plan["pins"]:
                additions[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()

    plan["pins"].update(additions)
    verify_plan(plan)

    return additions


def run_command(project, plan, command, executor, directory, cancel=None):
    verify_plan(plan)
    request = {
        "command": command,
        "executor": executor,
        "timeout_seconds": plan["timeout_seconds"],
        "module_path": plan["module_path"],
        "yaml_module_path": plan["yaml_module_path"],
        "elevation_required": plan["elevation_required"],
    }
    request_path = directory / "request.json"
    request_path.write_text(json.dumps(request, ensure_ascii=False), encoding="utf-8")
    response_path = directory / "response.json"

    if response_path.exists():
        raise ValueError("Atomic response file already exists")

    started = time.monotonic()

    with (
        (directory / "stdout.txt").open("wb") as stdout,
        (directory / "stderr.txt").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(project / "scripts/atomic_step.ps1"),
                "-RequestPath",
                str(request_path),
                "-ResponsePath",
                str(response_path),
            ],
            cwd=directory,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )

        try:
            while process.poll() is None:
                if cancel is not None and cancel.is_set():
                    terminate_process(process)

                    return {
                        "status": "interrupted",
                        "reason": "Collection stopped or run cancelled",
                        "exit_code": None,
                        "remaining_processes": "not_verified",
                    }

                if time.monotonic() - started > plan["timeout_seconds"] + 30:
                    terminate_process(process)

                    return {
                        "status": "timeout",
                        "reason": "Atomic command exceeded its deadline",
                        "exit_code": None,
                        "remaining_processes": "not_verified",
                    }

                time.sleep(0.1)
        finally:
            terminate_process(process)
            process.wait(timeout=15)

    try:
        result = json.loads(response_path.read_text(encoding="utf-8-sig"))

        if (not isinstance(result, dict)) or (
            result.get("status") not in {"passed", "failed", "blocked", "timeout"}
        ):
            raise ValueError("Invalid step status")

        if result["status"] in {"passed", "failed"} and type(result.get("exit_code")) is not int:
            raise ValueError("Missing command exit code")

        if result["status"] == "passed" and (result["exit_code"] != 0 or process.returncode != 0):
            raise ValueError("Step success disagrees with process exit code")

        return result
    except (ValueError, UnicodeError, OSError) as exc:
        return {
            "status": "error",
            "reason": "Invalid PowerShell step response: " + str(exc),
            "process_exit_code": process.returncode,
            "exit_code": None,
        }


class AtomicLifecycle:

    def __init__(self, project, plan, directory, *, runner=None):
        self.project, self.plan, self.directory = (Path(project), plan, Path(directory))
        self.runner = runner or run_command
        self.directory.mkdir(parents=True, exist_ok=False)
        self.report = {
            "schema_version": 1,
            "status": "planned",
            "plan": public_plan(plan),
            "started_at": utc_now(),
            "steps": [],
            "execution": {"status": "not_started"},
            "cleanup": {"status": "not_requested"},
            "prerequisites": [],
            "residuals": [],
            "detection": {"status": "not_evaluated"},
        }
        self.execution_started = False
        self.save()

    def save(self):
        save_lifecycle_report(self.directory, self.report)

    def save_failure(self):
        try:
            self.save()
        except Exception as exc:
            self.report.setdefault("persistence_errors", []).append(str(exc))
            print("Could not persist Atomic failure: " + str(exc), file=sys.stderr, flush=True)

    def step(self, label, command, executor, cancel=None):
        directory = self.directory / f"{len(self.report['steps']) + 1:03d}-{label}"
        directory.mkdir()
        record = {
            "stage": label,
            "started_at": utc_now(),
            "status": "in_progress",
            "artifacts": str(directory),
        }
        self.report["steps"].append(record)
        self.save()

        try:
            result = self.runner(self.project, self.plan, command, executor, directory, cancel)
        except (Exception, KeyboardInterrupt) as exc:
            result = {
                "status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "error",
                "reason": str(exc) or type(exc).__name__,
                "exit_code": None,
            }
            record.update(result, finished_at=utc_now())
            self.save_failure()

            if isinstance(exc, KeyboardInterrupt):
                raise

        record.update(result, finished_at=utc_now())

        if result["status"] == "passed":
            self.save()
        else:
            self.save_failure()

        return result

    def block(self, reason, status="blocked"):
        self.report.update(status=status, reason=reason)
        self.save_failure()

        raise LifecycleError(self.report)

    def prepare(self):
        verify_plan(self.plan)

        for dep in self.plan["dependencies"]:
            entry = {
                "number": dep["number"],
                "description": dep["description"],
                "origin": "unknown",
            }
            self.report["prerequisites"].append(entry)
            before = self.step("check-prerequisite", dep["check"], dep["executor"])
            entry["before"] = before

            if before["status"] == "passed":
                entry["origin"] = "preexisting"
                self.save()
                continue

            if before["status"] != "failed":
                self.block("Prerequisite check could not complete", before["status"])

            if not self.plan["prepare_requested"]:
                self.block("Missing prerequisites; use --prepare-prereqs to approve preparation")

            if not dep["prepare"].strip():
                self.block("No preparation command is defined")

            entry["origin"] = "preparation_attempted_not_exclusive_ownership"
            self.report["residuals"].append(
                {
                    "prerequisite": dep["number"],
                    "status": "manual_review",
                    "reason": "Arbitrary prerequisite changes cannot be inferred or safely rolled back automatically",
                },
            )
            obtained = self.step("prepare-prerequisite", dep["prepare"], dep["executor"])
            entry["preparation"] = obtained

            if obtained["status"] != "passed":
                self.block("Prerequisite preparation failed", obtained["status"])

            additions = record_prepared_additions(self.plan)
            entry["created_resource_files"] = additions
            entry["resource_ownership"] = "not_claimed; preserve for manual review"
            self.save()
            after = self.step("recheck-prerequisite", dep["check"], dep["executor"])
            entry["after"] = after

            if after["status"] != "passed":
                self.block("Prerequisite was not satisfied after preparation", after["status"])

        self.report["status"] = "ready"
        self.save()

    def execute(self, cancel=None):
        self.execution_started = True
        self.report["status"] = "running"
        self.save()

        try:
            result = self.step("execute", self.plan["command"], self.plan["executor"], cancel)
        except KeyboardInterrupt:
            self.report["execution"] = {
                "status": "interrupted",
                "reason": "Interrupted during test execution",
            }
            self.report["status"] = "interrupted"
            self.save_failure()

            raise

        if (result["status"] == "passed") and (
            type(result.get("process_id")) is not int or result["process_id"] < 1
        ):
            result = {
                "status": "error",
                "reason": "Execution returned no usable process ID",
                "exit_code": result.get("exit_code"),
            }

        self.report["execution"] = result
        self.report["status"] = result["status"]

        if result["status"] != "passed":
            self.block("Atomic execution did not succeed", result["status"])

        self.save()
        import csv

        record = self.report["steps"][-1]
        path = self.directory / "execution.csv"

        with path.open("w", encoding="utf-8", newline="") as stream:
            row = {
                "Execution Time (UTC)": result.get("started_at", record["started_at"]),
                "Hostname": socket.gethostname(),
                "Technique": self.plan["technique"],
                "Test Number": self.plan["test_number"],
                "Test Name": self.plan["name"],
                "GUID": self.plan["test_guid"],
                "ProcessId": result.get("process_id"),
                "ExitCode": result["exit_code"],
            }
            writer = csv.DictWriter(stream, fieldnames=list(row))
            writer.writeheader()
            writer.writerow(row)

        return {
            "status": "succeeded",
            "run_id": self.directory.parent.name,
            "technique": self.plan["technique"],
            "test_number": self.plan["test_number"],
            "test_guid": self.plan["test_guid"],
            "exit_code": 0,
            "execution_log": str(path),
            "lifecycle": str(self.directory / "lifecycle.json"),
        }

    def cleanup(self):
        if not self.execution_started:
            self.report["cleanup"] = {
                "status": "not_started",
                "reason": "Test execution was not attempted",
            }
        elif not self.plan["cleanup_requested"]:
            self.report["cleanup"] = {"status": "not_requested"}
            self.report["residuals"].append(
                {"status": "manual_review", "reason": "Test cleanup was not requested"},
            )
        elif not self.plan["cleanup_command"].strip():
            self.report["cleanup"] = {"status": "not_defined"}
            self.report["residuals"].append(
                {"status": "manual_review", "reason": "No cleanup command defined"},
            )
        else:
            self.report["cleanup"] = self.step(
                "cleanup", self.plan["cleanup_command"], self.plan["executor"]
            )
            self.report["cleanup"]["scope"] = "definition_command_only_not_full_rollback"

            if self.report["status"] == "passed" and self.report["cleanup"]["status"] != "passed":
                self.report.update(
                    status="needs_verification",
                    reason="Test succeeded but cleanup did not succeed",
                )

            self.report["residuals"].append(
                {"status": "not_verified", "reason": "Complete host restoration is not verified"},
            )

        self.report["finished_at"] = utc_now()
        self.save()


def detection_outcome(correlation, results, collection_status):
    ids = {event["record_id"] for event in correlation.get("process_candidates", [])}
    selected = {
        item["Log Record ID"]: item["Selection"] for item in results if item["Log Record ID"] in ids
    }
    result = {
        "status": "insufficient_data",
        "scope": "correlated_candidate_events",
        "candidate_event_ids": sorted(ids),
        "matches": sum((v is True for v in selected.values())),
        "limitations": "Correlation identifies candidates, not proven causality. Telemetry completeness is not certified.",
    }

    if collection_status != "completed":
        result["reason"] = "Collection did not complete"
    elif correlation.get("correlation_status") != "candidates_collected" or not ids:
        result["reason"] = "No unambiguous process candidate chain was collected"
    elif ids - set(selected) or any((value is None for value in selected.values())):
        result["reason"] = "Some candidate events lack a rule evaluation"
    else:
        result["status"] = "match" if result["matches"] else "no_match"
        result["reason"] = (
            "Rule matched recorded candidate events"
            if result["matches"]
            else "Rule did not match recorded candidate events"
        )

    return result


def save_lifecycle_report(directory, report):
    directory = Path(directory)
    path = directory / "lifecycle.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)
    from reporting.atomic_view import render_lifecycle

    (directory / "lifecycle.html").write_text(
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Atomic lifecycle</title><h1>Atomic lifecycle</h1>'
        + render_lifecycle(report),
        encoding="utf-8",
    )
