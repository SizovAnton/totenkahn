import base64
import json
import shutil
import subprocess
import sys
import os
from pathlib import Path
from handlers.component_inventory import (
    reject_duplicate_keys,
    reject_json_constant,
    require_choice,
    require_text,
    utc_now,
)

SUPPORTED_MODES = {'replay', 'regression', 'manual', 'auto'}

def make_check(check_id: str, status: str, reason: str, *, details=None) -> dict:
    require_text(check_id, 'Check ID')
    require_choice(status, {'passed', 'failed', 'unknown'}, 'Check status')
    require_text(reason, 'Check reason')

    return {'id': check_id, 'status': status, 'reason': reason, 'details': details}

def make_report(mode: str, checks: list[dict]) -> dict:
    statuses = {item['status'] for item in checks}

    if 'failed' in statuses:
        status = 'blocked'
    elif 'unknown' in statuses:
        status = 'needs_verification'
    else:
        status = 'passed'

    return {
        'schema_version': 1,
        'mode': mode,
        'checked_at': utc_now(),
        'scope': 'environment_preflight',
        'status': status,
        'checks': checks,
    }

def check_file(check_id: str, path: Path) -> dict:
    try:
        with path.open('rb') as file:
            file.read(1)
    except FileNotFoundError as exc:
        return make_check(
            check_id,
            'failed',
            'Required file was not found',
            details={'path': str(path), 'presence': 'absent', 'error': str(exc)},
        )
    except OSError as exc:
        return make_check(
            check_id,
            'unknown',
            'Required file could not be inspected',
            details={'path': str(path), 'presence': 'unknown', 'error': str(exc)},
        )

    return make_check(
        check_id,
        'passed',
        'Required file is readable',
        details={'path': str(path), 'presence': 'present'},
    )

def read_channels(config: dict) -> list[str]:
    events = config.get('events')

    if not isinstance(events, dict):
        raise ValueError('events must be a JSON object')

    channels = events.get('channels')

    if not isinstance(channels, list) or not channels:
        raise ValueError('events.channels must be a non-empty JSON array')

    result = []
    seen = set()

    for channel in channels:
        require_text(channel, 'Event channel')
        channel = channel.strip()
        key = channel.casefold()

        if key in seen:
            raise ValueError(f'Duplicate event channel: {channel}')

        seen.add(key)
        result.append(channel)

    return result
WINDOWS_PROBE = '''
$ErrorActionPreference = \'Stop\'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$requestJson = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($requestBase64)
)
$request = ConvertFrom-Json -InputObject $requestJson

$channelResults = @(
    foreach ($name in $request.channels) {
        try {

            $pattern = [System.Management.Automation.WildcardPattern]::Escape(
                [string]$name
            )

            $logs = @(
                Get-WinEvent -ListLog $pattern -Force -ErrorAction Stop
            )

            $exact = @(
                $logs | Where-Object { $_.LogName -ieq $name }
            )

            if ($exact.Count -ne 1) {
                throw \'Expected exactly one matching event channel\'
            }

            $enabled = [bool]$exact[0].IsEnabled

            [pscustomobject]@{
                name = [string]$name
                status = $(if ($enabled) { \'passed\' } else { \'failed\' })
                reason = $(
                    if ($enabled) {
                        \'Event channel configuration is accessible and enabled\'
                    } else {
                        \'Event channel is disabled\'
                    }
                )
            }
        }
        catch {
            [pscustomobject]@{
                name = [string]$name
                status = \'unknown\'
                reason = [string]$_.Exception.Message
            }
        }
    }
)

$result = [pscustomobject]@{
    execution_policy = [string](Get-ExecutionPolicy)
    powershell_version = [string]$PSVersionTable.PSVersion
    channels = @($channelResults)
}

$result | ConvertTo-Json -Depth 6 -Compress
'''

def run_windows_probe(powershell: str, channels: list[str], *, timeout_seconds: int=30) -> dict:
    request = json.dumps({'channels': channels}, ensure_ascii=False)
    payload = base64.b64encode(request.encode('utf-8')).decode('ascii')
    script = "$requestBase64 = '" + payload + "'\n" + WINDOWS_PROBE
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    completed = subprocess.run(
        [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )

    if completed.returncode != 0:
        error = completed.stderr.decode('utf-8', errors='replace').strip()
        raise ValueError(f'PowerShell probe failed with exit code {completed.returncode}: {error}')

    result = json.loads(
        completed.stdout.decode('utf-8-sig'),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_json_constant,
    )

    if not isinstance(result, dict):
        raise ValueError('PowerShell probe must return a JSON object')

    require_text(result.get('powershell_version'), 'PowerShell version')
    require_text(result.get('execution_policy'), 'PowerShell execution policy')
    rows = result.get('channels')

    if not isinstance(rows, list) or len(rows) != len(channels):
        raise ValueError('PowerShell probe returned an invalid channel list')

    returned = set()
    expected = set(channels)

    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Channel result must be a JSON object')

        name = row.get('name')
        require_text(name, 'Channel result name')

        if name not in expected or name in returned:
            raise ValueError('Unexpected or duplicate channel result')

        require_choice(
            row.get('status'),
            {'passed', 'failed', 'unknown'},
            'Channel result status',
        )
        require_text(row.get('reason'), 'Channel result reason')
        returned.add(name)

    return result

def check_atomic_paths(config: dict) -> list[dict]:
    atomic = config.get('atomic')

    if not isinstance(atomic, dict):
        return [
            make_check(
                'atomic.configuration',
                'failed',
                'Atomic configuration is missing or invalid',
            ),
        ]

    checks = []

    for field, expected_kind in (('module_path', 'file'), ('yaml_module_path', 'file'), ('atomics_path', 'directory')):
        value = atomic.get(field)
        check_id = 'atomic.yaml_module' if field == 'yaml_module_path' else f'atomic.{field}'

        if not isinstance(value, str) or not value.strip():
            checks.append(
                make_check(check_id, 'failed', f'atomic.{field} must be a non-empty path'),
            )
            continue

        path = Path(value)

        if not path.is_absolute():
            checks.append(
                make_check(check_id, 'failed', 'Atomic paths must be absolute', details={'path': value}),
            )
            continue

        if expected_kind == 'file':
            checks.append(check_file(check_id, path))
            continue

        try:
            path.stat()

            if not path.is_dir():
                raise ValueError('Atomics path is not a directory')

            with os.scandir(path) as entries:
                if next(entries, None) is None:
                    raise ValueError('Atomics directory is empty')
        except FileNotFoundError as exc:
            checks.append(
                make_check(
                    check_id,
                    'failed',
                    'Atomics directory was not found',
                    details={'path': str(path), 'presence': 'absent', 'error': str(exc)},
                ),
            )
        except (OSError, ValueError) as exc:
            checks.append(
                make_check(
                    check_id,
                    'unknown',
                    'Atomics directory could not be verified',
                    details={'path': str(path), 'presence': 'unknown', 'error': str(exc)},
                ),
            )
        else:
            checks.append(
                make_check(
                    check_id,
                    'passed',
                    'Atomics directory is accessible and non-empty',
                    details={'path': str(path)},
                ),
            )

    checks.append(
        make_check(
            'atomic.runtime_and_prerequisites',
            'unknown',
            'Module compatibility and selected test prerequisites are not checked yet',
        ),
    )

    return checks

def check_environment(project_dir: Path, config: dict, *, mode: str) -> dict:
    require_choice(mode, SUPPORTED_MODES, 'Execution mode')

    if not isinstance(config, dict):
        raise ValueError('Configuration must be a JSON object')

    project_dir = Path(project_dir)
    checks = []

    if mode in {'replay', 'regression'}:
        checks.append(
            make_check(
                'live_dependencies',
                'passed',
                'This mode does not require live collection or Atomic components',
            ),
        )

        return make_report(mode, checks)

    if sys.platform != 'win32':
        checks.append(
            make_check(
                'platform',
                'failed',
                'Live collection requires Windows',
                details={'platform': sys.platform},
            ),
        )

        return make_report(mode, checks)

    checks.append(make_check('platform', 'passed', 'Windows platform detected'))
    checks.append(
        check_file('collector.script', project_dir / 'scripts' / 'watch_windows_events.ps1'),
    )

    try:
        channels = read_channels(config)
    except ValueError as exc:
        checks.append(make_check('channels.configuration', 'failed', str(exc)))
        channels = None

    powershell = shutil.which('powershell.exe')

    if powershell is None:
        checks.append(make_check('powershell', 'failed', 'powershell.exe was not found'))
    elif channels is not None:
        try:
            result = run_windows_probe(powershell, channels)
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
            checks.append(
                make_check(
                    'powershell.probe',
                    'unknown',
                    'Windows environment probe did not complete successfully',
                    details={'error': str(exc)},
                ),
            )
        else:
            checks.append(
                make_check(
                    'powershell',
                    'passed',
                    'PowerShell executed the environment probe',
                    details={'path': powershell, 'version': result['powershell_version']},
                ),
            )
            policy = result['execution_policy']
            checks.append(
                make_check(
                    'powershell.execution_policy',
                    'failed' if policy == 'Restricted' else 'unknown' if policy == 'AllSigned' else 'passed',
                    'Execution policy inspected; script signatures and organizational controls may require additional verification',
                    details={'effective_policy': policy},
                ),
            )

            for row in result['channels']:
                checks.append(make_check(f"channel:{row['name']}", row['status'], row['reason']))

    if mode == 'auto':
        checks.append(
            check_file('atomic.runner_script', project_dir / 'scripts' / 'invoke_atomic.ps1'),
        )
        checks.extend(check_atomic_paths(config))

    checks.append(
        make_check(
            'collector.subscription',
            'unknown',
            'Collector subscription readiness has not been checked',
        ),
    )

    return make_report(mode, checks)
