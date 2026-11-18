import subprocess
import os
from queue import Queue, Empty
from threading import Thread
import time
import json
import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from datetime import datetime, timezone
from copy import deepcopy
from shutil import copyfile

from handlers.atomic_lifecycle import AtomicLifecycle, LifecycleError
from handlers.process_control import terminate_process
from handlers.runtime_paths import runtime_config
from handlers.telemetry import inspect as inspect_telemetry, TelemetryNotReady
from handlers.events import process_events
from scripts.check_atomic import run_scenario
from handlers.file_handlers import load_configuration, load_csv_file
from handlers.correlation import correlate_processes

def run_scenario_and_stop(scenario_command, stop_file):
    try:
        return run_scenario(scenario_command)
    finally:
        stop_file.touch()

def run_managed_and_stop(lifecycle, stop_file, cancel_event):
    try:
        return lifecycle.execute(cancel_event)
    finally:
        stop_file.touch()


def collector_lines(collector, is_ready, *, timeout, manual=False):
    """Readiness і автоматичний збір обмежені часом навіть без stdout."""
    messages = Queue()
    def read():
        try:
            for line in collector.stdout:
                messages.put(line)
        except Exception as exc:
            messages.put(exc)
        finally:
            messages.put(None)
    Thread(target=read, daemon=True).start()
    started = time.monotonic()
    ready_at = None
    while True:
        now = time.monotonic()
        if is_ready() and ready_at is None: ready_at = now
        if ready_at is None and now-started > 60:
            raise TimeoutError('Collector readiness timed out')
        if ready_at is not None and not manual and now-ready_at > timeout:
            raise TimeoutError('Collection exceeded the Atomic run deadline')
        try: line = messages.get(timeout=0.2)
        except Empty: continue
        if line is None: return
        if isinstance(line, Exception): raise line
        yield line


def wait_for_manual_stop(stop_file: Path, cancel_event: Event) -> bool:
    if sys.platform != "win32":
        raise RuntimeError("Manual live collection requires Windows")

    if sys.stdin is None or not sys.stdin.isatty():
        raise RuntimeError("Manual mode requires an interactive console")

    import msvcrt

    skip_special_key = False

    while not cancel_event.is_set():
        if msvcrt.kbhit():
            key = msvcrt.getwch()

            if skip_special_key:
                skip_special_key = False
            elif key in ("\x00", "\xe0"):
                skip_special_key = True
            elif key == "\r":
                if cancel_event.is_set():
                    return False

                stop_file.touch()
                return True

        cancel_event.wait(0.1)

    return False

def run_manual_and_stop(stop_file, cancel_event):
    try:
        return wait_for_manual_stop(stop_file, cancel_event)
    finally:
        stop_file.touch()

def build_atomic_command(project_dir, config, technique, test_number):
    invoke_atomic_path = project_dir / "scripts" / "invoke_atomic.ps1"

    if not invoke_atomic_path.is_file():
        raise FileNotFoundError( f"PowerShell script not found: {invoke_atomic_path}")

    atomic = config.get("atomic")

    if not isinstance(atomic, dict) or not atomic:
        raise ValueError("Atomic configuration must be a non-empty dictionary")

    for field in ("module_path", "atomics_path"):
        value = atomic.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"atomic.{field} must be a non-empty string")

    if not isinstance(technique, str) or not technique.strip():
        raise ValueError("Technique must be a non-empty string")

    technique = technique.strip().upper()

    if type(test_number) is not int or not 1 <= test_number <= 2147483647:
        raise ValueError("Test number must be a positive 32-bit integer")

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(invoke_atomic_path),
        "-ModulePath",
        atomic["module_path"],
        "-AtomicPath",
        atomic["atomics_path"],
        "-Technique",
        technique,
        "-TestNumber",
        str(test_number)
    ]
    yaml_module_path = atomic.get("yaml_module_path")
    if yaml_module_path is not None:
        if not isinstance(yaml_module_path, str) or not yaml_module_path.strip():
            raise ValueError("atomic.yaml_module_path must be a non-empty string")
        command.extend(["-YamlModulePath", yaml_module_path])
    return command


def build_session_metadata(session_id, config, channels, *, manual):
    profile_snapshot = deepcopy({
        "defaults": config["defaults"],
        "sources": config["sources"]
    })

    started_at = datetime.now(timezone.utc).isoformat()

    return {
        "schema_version": 1,
        "session_id": session_id,
        "mode": "manual" if manual else "auto",
        "producer": {
            "build_id": None,
            "normalizer_version": 1,
        },
        "collection": {
            "status": "in_progress",
            "requested_channels": list(channels),
            "ready_channels": [],
            "started_at": started_at,
            "ready_received_at": None,
            "finished_at": None,
            "stop_reason": None,
            "errors": [],
        },
        "profiles_snapshot": profile_snapshot,
        "artifacts": {
            "events": "events.json",
            "scenario": "scenario.json",
            "execution_log": None
        }
    }

def write_session_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def save_session_metadata(session_dir, session_metadata):
    write_session_json(session_dir / 'session.json', session_metadata)


def copy_execution_log(session_dir, execution_results):
    raw_path = execution_results.get("execution_log")

    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Scenario result must include a non-empty execution_log path")

    source_path = Path(raw_path)

    if not source_path.is_file():
        raise FileNotFoundError(f"Execution log not found: {source_path}")

    output_path = session_dir / "execution.csv"
    temporary_path = session_dir / "execution.csv.tmp"

    if source_path.resolve() == output_path.resolve():
        return output_path.name

    copyfile(source_path, temporary_path)
    temporary_path.replace(output_path)

    return output_path.name

def save_session_files(session_dir, events, scenario):
    failures = []
    # Помилка одного артефакту не заважає спробі зберегти інший.
    for name, value in [('events.json', events), ('scenario.json', scenario)]:
        try:
            write_session_json(session_dir / name, value)
        except Exception as exc:
            failures.append(f'{name}: {exc}')
    if failures:
        raise OSError('; '.join(failures))


def run_live_session(technique=None, test_number=None, *, manual=False, test_context=None, atomic_plan=None, approved=False, host_requirements=None):
    if test_context is not None and not manual:
        raise ValueError("test_context requires manual mode")

    if test_context is not None and not isinstance(test_context, dict):
        raise ValueError("test_context must be a dictionary or None")

    test_context = deepcopy(test_context)
    
    if manual:
        if technique is not None or test_number is not None:
            raise ValueError("Manual mode does not accept Atomic parameters")

        if sys.platform != "win32":
            raise RuntimeError("Manual live collection requires Windows")

        if sys.stdin is None or not sys.stdin.isatty():
            raise RuntimeError("Manual mode requires an interactive console")
        
    if getattr(sys, 'frozen', False):
        project_dir = Path(sys.executable).resolve().parent
    else:
        project_dir = Path(__file__).resolve().parents[1]

    default_config = project_dir / "config" / "default.config"
    config_json = project_dir / "config" / "config.json"

    config = runtime_config(project_dir)

    if not manual:
        if sys.platform != 'win32': raise RuntimeError('Automatic collection requires Windows')
        if not approved or atomic_plan is None:
            raise ValueError('Automatic execution requires an explicitly approved Atomic plan')
        if atomic_plan['technique'] != technique or atomic_plan['test_number'] != test_number:
            raise ValueError('Atomic selection does not match the approved plan')

    if host_requirements is None:
        raise ValueError('Live collection requires rule-specific telemetry requirements')
    try:
        host_report=inspect_telemetry(project_dir,host_requirements)
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
        raise TelemetryNotReady({'status':'blocked','reason':str(exc)}) from exc
    if host_report['status']!='passed':
        raise TelemetryNotReady(host_report)
    config['events']['channels']=host_requirements['channels']

    session_id = str(uuid4())
    session_dir = Path(config.get("paths", {}).get("runs_dir", str(project_dir / "runs"))) / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    stop_file = session_dir / "collector.stop"

    collector_path = project_dir / "scripts" / "watch_windows_events.ps1"

    if not collector_path.is_file():
        raise FileNotFoundError(f"Collector script not found: {collector_path}")

    channels = config["events"]["channels"]

    if not isinstance(channels, list) or not channels:
        raise ValueError("events.channels must be a non-empty list")

    normalized_channels = []
    seen_channels = set()

    for index, channel in enumerate(channels, start=1):
        if not isinstance(channel, str) or not channel.strip():
            raise ValueError(f"Event channel #{index} must be a non-empty string")

        channel = channel.strip()
        channel_key = channel.casefold()

        if channel_key in seen_channels:
            raise ValueError(f"Duplicate event channel: {channel!r}")

        seen_channels.add(channel_key)
        normalized_channels.append(channel)

    channels = normalized_channels
    session_metadata = build_session_metadata(
        session_id,
        config,
        channels,
        manual=manual
    )

    session_metadata["telemetry_readiness"] = host_report
    collection = session_metadata["collection"]
    channels_json = json.dumps(channels, ensure_ascii=False)

    collector_command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(collector_path),
        "-LogNamesJson",
        channels_json,
        "-StopFile",
        str(stop_file)
    ]

    collected_events = []
    collector_ready = False
    scenario_future = None
    cancel_event = Event()
    ready_received_at = None
    interrupted = False

    collector_log_path = session_dir / "collector.log"
    save_session_metadata(session_dir, session_metadata)

    lifecycle = AtomicLifecycle(project_dir, atomic_plan, session_dir/'atomic') if not manual else None
    if lifecycle:
        session_metadata['artifacts']['atomic_lifecycle'] = 'atomic/lifecycle.json'
        save_session_metadata(session_dir, session_metadata)

    try:
        if lifecycle:
            # Наявність lifecycle не звужує тип окремої змінної atomic_plan.
            if atomic_plan is None:
                raise ValueError('Automatic lifecycle requires an Atomic plan')
            if atomic_plan['elevation_required']:
                import ctypes
                if not getattr(ctypes, 'windll').shell32.IsUserAnAdmin():
                    lifecycle.block('Selected test requires an elevated console')
            lifecycle.prepare()
        with collector_log_path.open("w", encoding="utf-8") as collector_log:
            with ThreadPoolExecutor(max_workers=1) as executor:
                with subprocess.Popen(collector_command,
                                    stdout = subprocess.PIPE,
                                    stderr=collector_log,
                                    text=True,
                                    encoding="utf-8") as collector:
                    try:
                        if collector.stdout is None:
                            raise RuntimeError("Collector stdout is unavailable")

                        for line in collector_lines(collector, lambda: collector_ready,
                                timeout=(atomic_plan['timeout_seconds']+60) if atomic_plan else 3600, manual=manual):
                            message = json.loads(line)

                            if not isinstance(message, dict):
                                raise ValueError("Collector message must be a JSON object")

                            if message.get("type") == "ready":
                                if collector_ready:
                                    raise RuntimeError("Collector sent readiness more than once")

                                ready_channels = message.get("channels")

                                if not isinstance(ready_channels, list):
                                    raise ValueError("Collector readiness message must include a channels list")

                                if ready_channels != channels:
                                    raise RuntimeError("Collector confirmed unexpected channels: "
                                        f"{ready_channels!r}; expected {channels!r}")

                                collector_ready = True

                                ready_received_at = datetime.now(timezone.utc).isoformat()

                                collection["ready_channels"] = list(ready_channels)
                                collection["ready_received_at"] = ready_received_at
                                save_session_metadata(
                                    session_dir,
                                    session_metadata
                                )

                                if manual:
                                    scenario_future = executor.submit(
                                        run_manual_and_stop,
                                        stop_file,
                                        cancel_event,
                                    )

                                    print(
                                        "Collector ready; perform the test from "
                                        "Kali/Parrot, then press Enter here to stop.",
                                        flush=True,
                                    )
                                else:
                                    scenario_future = executor.submit(
                                        run_managed_and_stop,
                                        lifecycle,
                                        stop_file,
                                        cancel_event,
                                    )

                                    print(
                                        "Collector ready; scenario started",
                                        flush=True,
                                    )

                                continue

                            if message.get("type") != "event":
                                raise ValueError (f"Unknown collector message type: "
                                    f"{message.get('type')!r}")

                            if not collector_ready:
                                raise RuntimeError("Collector sent an event before readiness")

                            raw_xml = message.get("xml")

                            if not isinstance(raw_xml, str) or not raw_xml.strip():
                                raise ValueError("Collector event must include non-empty XML")

                            root = ET.fromstring(raw_xml)
                            prepared_events = process_events([root], config)

                            for prepared_event in prepared_events:
                                prepared_event["raw_xml"] = raw_xml

                            collected_events.extend(prepared_events)

                        collector_returncode = collector.wait()
                        collection["finished_at"] = datetime.now(timezone.utc).isoformat()

                        if collector_returncode != 0:
                            raise RuntimeError(f"Collector exited with code {collector_returncode}; "
                                f"diagnostics: {collector_log_path}")

                        if not collector_ready or scenario_future is None:
                            raise RuntimeError("Collector finished without starting the scenario")

                        if not stop_file.is_file():
                            raise RuntimeError("Collector finished before the stop signal")

                    finally:
                        cancel_event.set()

                        if collector.poll() is None:
                            try:
                                stop_file.touch()
                            finally:
                                try:
                                    collector.wait(timeout=15)
                                except subprocess.TimeoutExpired:
                                    terminate_process(collector)

                session_result = scenario_future.result()

                if manual:
                    if session_result is not True:
                        raise RuntimeError("Manual session ended without Enter confirmation")

                    execution_results = {
                        "mode": "manual",
                        "session_id": session_id,
                        "test_context": test_context,
                        "status": "succeeded",
                        "channels": channels,
                        "stop_reason": "enter",
                        "ready_received_at": ready_received_at,
                        "finished_at": datetime.now(timezone.utc).isoformat()
                    }
                else:
                    if not isinstance(session_result, dict):
                        raise RuntimeError("Automatic scenario result must be a dictionary")

                    execution_results = session_result
    
    except(Exception, KeyboardInterrupt) as e:
        interrupted = isinstance(e, KeyboardInterrupt)

        collection["status"] = "incomplete"
        collection["finished_at"] = datetime.now(timezone.utc).isoformat()
        collection["stop_reason"] = "interrupt" if interrupted else "error"
        collection["errors"].append({
            "type": type(e).__name__,
            "message": str(e) or type(e).__name__
        })

        partial_scenario = {
            'mode': 'manual' if manual else 'auto', 'session_id': session_id,
            'status': 'incomplete', 'channels': channels, 'collector_ready': collector_ready,
            'stop_reason': collection['stop_reason'], 'error_type': type(e).__name__,
            'error': str(e) or type(e).__name__, 'ready_received_at': ready_received_at,
            'finished_at': collection['finished_at'],
        }
        if manual:
            partial_scenario['test_context'] = test_context
        else:
            partial_scenario.update(technique=technique, test_number=test_number, lifecycle='atomic/lifecycle.json')
        try:
            save_session_files(session_dir, collected_events, partial_scenario)
        except Exception as save_error:
            collection['errors'].append({'stage':'saving_partial_evidence','message':str(save_error)})
            print(f'Could not save all partial evidence: {save_error}',file=sys.stderr,flush=True)
        if lifecycle:
            lifecycle.report['collection'] = deepcopy(collection)
            if lifecycle.report['status'] in {'planned','ready','running','passed'}:
                lifecycle.report.update(status='interrupted' if interrupted else 'error',reason=str(e))
            lifecycle.save_failure()
        print(f'Incomplete session artifacts: {session_dir}',file=sys.stderr,flush=True)
        try:
            save_session_metadata(session_dir, session_metadata)
        except Exception as metadata_error:
            print(
                f"Could not save incomplete session metadata: {metadata_error}",
                file=sys.stderr,
                flush=True,
            )

        if lifecycle and not interrupted:
            raise LifecycleError(lifecycle.report) from e
        raise
    finally:
        if lifecycle:
            try:
                lifecycle.cleanup()
            except (Exception, KeyboardInterrupt) as cleanup_error:
                lifecycle.report['cleanup'] = {'status':'error','reason':str(cleanup_error)}
                if lifecycle.report['status']=='passed':
                    lifecycle.report.update(status='needs_verification',reason='Cleanup could not complete')
                lifecycle.save_failure()
                if isinstance(cleanup_error, KeyboardInterrupt) and not interrupted:
                    raise

    try:
        if manual:
            collection["finished_at"] = execution_results["finished_at"]
            collection["stop_reason"] = execution_results["stop_reason"]
        else:
            collection["finished_at"] = collection["finished_at"] or datetime.now(timezone.utc).isoformat()
            collection["stop_reason"] = "scenario_finished"

            execution_log_name = copy_execution_log(
                session_dir,
                execution_results
            )

            execution_results = {
                **execution_results,
                "execution_log": execution_log_name,
                "execution_log_base": "session"
            }

            session_metadata["artifacts"]["execution_log"] = execution_log_name

        save_session_files(
            session_dir,
            collected_events,
            execution_results
        )

        collection["status"] = "completed"
        if lifecycle:
            lifecycle.report['collection'] = deepcopy(collection)
            lifecycle.save()
            execution_results['atomic_lifecycle'] = deepcopy(lifecycle.report)
            save_session_files(session_dir, collected_events, execution_results)
        save_session_metadata(session_dir, session_metadata)

    except (Exception, KeyboardInterrupt) as save_error:
        collection["status"] = "incomplete"

        if collection["finished_at"] is None:
            collection["finished_at"] = datetime.now(timezone.utc).isoformat()

        collection["stop_reason"] = (
            "interrupt"
            if isinstance(save_error, KeyboardInterrupt)
            else "error"
        )

        collection["errors"].append({
            "stage": "saving",
            "type": type(save_error).__name__,
            "message": str(save_error) or type(save_error).__name__,
        })

        try:
            save_session_metadata(session_dir, session_metadata)
        except Exception as metadata_error:
            print(
                f"Could not save incomplete session metadata: {metadata_error}",
                file=sys.stderr,
                flush=True,
            )

        raise

    if manual:
        return {
            "session_dir": session_dir,
            "session_metadata": session_metadata,
            "events": collected_events,
            "scenario": execution_results,
            "atomic_run": None,
            "correlation": None,
        }

    execution_log_path = session_dir / execution_results["execution_log"]

    if not execution_log_path.is_file():
        raise FileNotFoundError(f"Execution log not found: {execution_log_path}")

    execution_rows = load_csv_file(execution_log_path)
    matching_runs = []

    for row in execution_rows:
        if row.get("GUID") == execution_results["test_guid"] and row.get("Technique") == execution_results["technique"]:
            matching_runs.append(row)

    if len(matching_runs) != 1:
        raise RuntimeError(f"Expected one matching execution record; found {len(matching_runs)}")

    at_run = matching_runs[0]

    correlation = correlate_processes(at_run, collected_events)

    correlation_status = correlation["correlation_status"]
    root_candidates = correlation["root_candidates"]
    root_evidence = correlation["root_evidence"]
    process_candidates = correlation["process_candidates"]
    process_evidence = correlation["process_evidence"]

    correlation_result = {
        "session_id" : session_id,
        "run_id" : execution_results["run_id"],
        "status" : correlation_status,
        "root_candidates" : root_candidates,
        "process_candidates" : process_candidates,
        "root_evidence": root_evidence,
        "process_evidence": process_evidence,
    }

    output_correlation = session_dir / "process_correlation.json"
    with output_correlation.open("w", encoding="utf-8") as output_correlation_file:
        json.dump(correlation_result, output_correlation_file, ensure_ascii=False, indent=2)

    return {
        "session_dir": session_dir,
        "session_metadata": session_metadata,
        "events": collected_events,
        "scenario": execution_results,
        "atomic_run": at_run,
        "correlation": correlation,
    }

