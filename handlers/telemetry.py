import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from uuid import uuid4
import zipfile
from urllib.request import Request, build_opener
from handlers.component_inventory import utc_now, reject_duplicate_keys
from handlers.installation import plain_path, installation_lock
from handlers.package_cache import HTTPSRedirectHandler
from handlers.package_extract import inspect_zip, extract_files
from handlers.runtime_paths import data_root

SYSMON = 'Microsoft-Windows-Sysmon/Operational'
CHANNELS = {SYSMON, 'Security'}
URL = 'https://download.sysinternals.com/files/Sysmon.zip'
CATEGORIES = {
    'process_creation': 'ProcessCreate',
    'network_connection': 'NetworkConnect',
    'image_load': 'ImageLoad',
    'file_event': 'FileCreate',
    'registry_event': 'RegistryEvent',
    'dns_query': 'DnsQuery',
}
PROFILE = '<Sysmon schemaversion="4.90"><HashAlgorithms>sha256</HashAlgorithms><EventFiltering>' + ''.join(('<' + tag + ' onmatch="exclude" />' for tag in CATEGORIES.values())) + '</EventFiltering></Sysmon>'

class TelemetryNotReady(ValueError):

    def __init__(self, report):
        self.report = report
        super().__init__(
            'Host telemetry is not ready; use telemetry plan/prepare --rule RULE. ' + json.dumps(report),
        )

def requirements(rule, config):
    source = rule.get('logsource', {})

    if source.get('product') != 'windows':
        raise ValueError('Host preparation requires a Windows rule')

    category = source.get('category')
    service = source.get('service')

    if category not in CATEGORIES:
        raise ValueError('Supported telemetry categories: ' + ', '.join(CATEGORIES))

    supported = []

    for item in config['sources']:
        channel = item.get('channel')

        if channel not in CHANNELS or channel not in config['events']['channels']:
            continue

        if service and item.get('service') != service:
            continue

        if category not in item.get('event_categories', {}).values():
            continue

        if channel == 'Security' and category != 'process_creation':
            continue

        supported.append(channel)

    if not supported:
        raise ValueError('No supported configured channel for the selected rule')

    return {
        'channels': sorted(set(supported)),
        'category': category,
        'audit_process_creation': 'Security' in supported,
        'command_line': 'Security' in supported,
        'sysmon': SYSMON in supported,
        'scope': 'configuration_only_not_event_delivery',
        'limitations': 'Collector subscription and actual required events must still be verified during the experiment',
    }

def root_path():
    return plain_path(data_root() / 'telemetry')

def read_ledger(root):
    path = plain_path(root / 'ledger.json')

    if not path.exists():
        return {'schema_version': 1, 'operations': []}

    data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=reject_duplicate_keys)

    if data.get('schema_version') != 1 or not isinstance(data.get('operations'), list):
        raise ValueError('Invalid telemetry ledger')

    for op in data['operations']:
        if op.get('key') not in {'sysmon', 'audit', 'command_line', *[f'channel:{n}' for n in CHANNELS]}:
            raise ValueError('Unexpected telemetry resource')

        if op.get('state') not in {'planned', 'committed', 'restoring', 'restored', 'interrupted'}:
            raise ValueError('Unexpected telemetry operation state')

    return data

def save_ledger(root, ledger):
    path = plain_path(root / 'ledger.json')
    temporary = plain_path(root / 'ledger.tmp')

    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(ledger, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())

    os.replace(temporary, path)

def save_ledger_after_error(root, ledger):
    try:
        save_ledger(root, ledger)
    except Exception as exc:
        print('Could not persist telemetry failure: ' + str(exc), file=sys.stderr, flush=True)

        return str(exc)

    return None

def backend(project, request):
    if sys.platform != 'win32':
        raise ValueError('Host telemetry preparation requires Windows')

    with tempfile.TemporaryDirectory(prefix='totenkahn-telemetry-probe-') as temporary:
        path = Path(temporary) / 'request.json'
        path.write_text(json.dumps(request), encoding='utf-8')
        result = subprocess.run(
            [
                'powershell.exe',
                '-NoLogo',
                '-NoProfile',
                '-NonInteractive',
                '-File',
                str(project / 'scripts/host_telemetry.ps1'),
                '-RequestPath',
                str(path),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=180 if request['action'] == 'set' else 60,
        )

    try:
        data = json.loads(result.stdout.decode('utf-8-sig'))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(
            'Invalid telemetry response: ' + result.stderr.decode('utf-8', errors='replace'),
        ) from exc

    if result.returncode or data.get('status') != 'passed':
        raise ValueError(data.get('reason', 'Host operation failed'))

    return data['result']

def resource(observed, key):
    if key.startswith('channel:'):
        return observed['channels'].get(key[8:], {}).get('enabled')

    return observed.get(key)

def trusted_sysmon(observed, ledger):
    current = observed.get('sysmon')

    return (
        (current is not None)
        and any(
            ((
                (op['key'] == 'sysmon')
                and (op['state'] == 'committed')
                and (op.get('after') == current)
                and (op.get('profile_sha256') == hashlib.sha256(PROFILE.encode()).hexdigest())
            ) for op in ledger['operations']),
        )
    )

def make_plan(req, observed, ledger):
    actions = []
    blocked = []

    if not isinstance(observed.get('host_id'), str) or not observed['host_id']:
        blocked.append('Host identity could not be verified')

    if ledger['operations'] and ledger.get('host_id') != observed.get('host_id'):
        blocked.append('Telemetry ledger belongs to a different host')

    if observed.get('errors', {}).get('sysmon') and req['sysmon']:
        blocked.append('Sysmon inspection failed: ' + observed['errors']['sysmon'])

    if req['sysmon']:
        if observed.get('sysmon') is None:
            if observed.get('native_sysmon') not in {'Disabled', 'Absent'}:
                blocked.append(
                    'Built-in Sysmon is enabled or its state is unknown; standalone installation is not allowed',
                )
            else:
                actions.append(
                    {
                        'key': 'sysmon',
                        'before': None,
                        'desired': 'install_owned_profile',
                        'source': URL,
                        'profile': PROFILE,
                        'license': 'https://learn.microsoft.com/sysinternals/license-terms',
                    },
                )
        elif not trusted_sysmon(observed, ledger):
            blocked.append(
                'Existing Sysmon is preserved; its active configuration is not a verified TOTENKAHN profile',
            )
        elif observed['sysmon'].get('state') != 'Running':
            blocked.append('Sysmon is not running')

    for key, needed, desired in [
        ('audit', req['audit_process_creation'], None),
        ('command_line', req['command_line'], {'exists': True, 'kind': 'DWord', 'value': 1}),
    ]:
        if not needed:
            continue

        before = observed.get(key)

        if key == 'audit':
            if type(before) is not int or before not in range(4):
                blocked.append('Process Creation audit policy is unreadable')
                continue

            desired = before | 1
        elif not isinstance(before, dict) or (before.get('exists') and before.get('kind') != 'DWord'):
            blocked.append(
                'Command-line audit registry value is unreadable or has an unsupported type',
            )
            continue

        if before != desired:
            actions.append({'key': key, 'before': before, 'desired': desired})

    installing = any((a['key'] == 'sysmon' for a in actions))

    for name in req['channels']:
        item = observed['channels'].get(name, {})

        if installing and name == SYSMON:
            continue

        if type(item.get('enabled')) is not bool:
            blocked.append('Channel configuration is inaccessible: ' + name)
        elif not item['enabled']:
            actions.append({'key': 'channel:' + name, 'before': False, 'desired': True})
        elif item.get('readable') is not True:
            blocked.append('Channel cannot be read: ' + name)

    if actions and observed.get('elevated') is not True:
        blocked.append('Preparation requires an elevated console')

    return {
        'status': 'blocked' if blocked else 'needs_action' if actions else 'passed',
        'requirements': req,
        'actions': actions,
        'blockers': blocked,
        'observation': observed,
        'scope': 'configuration_only_not_event_delivery',
        'impact': 'May install a system service/driver and enable host-wide auditing. Command lines may contain sensitive data. No existing Sysmon configuration, Defender or Execution Policy is overwritten.',
    }

def inspect(project, req, *, probe=None, root=None):
    root = root_path() if root is None else plain_path(root)
    observed = (probe or backend)(project, {'action': 'observe', 'channels': req['channels']})

    return make_plan(req, observed, read_ledger(root))

def acquire_sysmon(root, *, archive=None):
    destination = plain_path(root / 'packages' / str(uuid4()))
    destination.mkdir(parents=True)
    path = destination / 'Sysmon.zip'

    if archive:
        import shutil

        source = plain_path(Path(archive))

        if source.stat().st_size > 50 * 1024 ** 2:
            raise ValueError('Sysmon archive exceeds its size limit')

        shutil.copyfile(source, path)
    else:
        started = time.monotonic()
        opener = build_opener(HTTPSRedirectHandler())

        with opener.open(Request(URL, headers={'User-Agent': 'TOTENKAHN'}), timeout=20) as response, path.open('xb') as stream:
            size = 0

            while (chunk := response.read(65536)):
                size += len(chunk)

                if size > 50 * 1024 ** 2 or time.monotonic() - started > 120:
                    raise ValueError('Sysmon download exceeded its limit')

                stream.write(chunk)

    with zipfile.ZipFile(path) as zipped:
        entries = inspect_zip(zipped, max_entries=50, max_unpacked_bytes=100 * 1024 ** 2)
        extract_files(
            zipped,
            entries,
            destination / 'files',
            max_unpacked_bytes=100 * 1024 ** 2,
        )

    return {
        'directory': str(destination / 'files'),
        'archive_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'source': URL,
    }

def prepare(project, proposal, *, approved=False, accept_eula=False, archive=None, probe=None, root=None, acquire=None):
    if not approved:
        return {'status': 'blocked', 'reason': 'Host changes require explicit consent'}

    root = root_path() if root is None else plain_path(root)
    run = probe or backend

    if proposal['status'] == 'blocked':
        return proposal

    if any((a['key'] == 'sysmon' for a in proposal['actions'])) and (not accept_eula):
        return {
            'status': 'blocked',
            'reason': 'Sysmon installation requires explicit --accept-sysmon-eula',
        }

    root.mkdir(parents=True, exist_ok=True)

    with installation_lock(root / 'operation'):
        ledger = read_ledger(root)
        fresh = run(project, {'action': 'observe', 'channels': proposal['requirements']['channels']})
        current = make_plan(proposal['requirements'], fresh, ledger)

        if current['actions'] != proposal['actions'] or current['blockers'] != proposal['blockers']:
            return {'status': 'blocked', 'reason': 'Host state changed after the plan; inspect a new plan'}

        ledger['host_id'] = fresh['host_id']

        for action in proposal['actions']:
            op = {**action, 'id': str(uuid4()), 'state': 'planned', 'started_at': utc_now()}
            ledger['operations'].append(op)
            save_ledger(root, ledger)

            try:
                arguments = {**action}

                if action['key'] == 'sysmon':
                    package = (acquire or acquire_sysmon)(root, archive=archive)
                    checked = run(project, {'action': 'verify_package', **package})
                    profile = plain_path(root / ('sysmon-' + op['id'] + '.xml'))
                    profile.write_text(PROFILE, encoding='utf-8')
                    op.update(
                        package=checked,
                        profile_sha256=hashlib.sha256(PROFILE.encode()).hexdigest(),
                        profile_path=str(profile),
                    )
                    save_ledger(root, ledger)
                    arguments.update(
                        executable=checked['executable'],
                        executable_sha256=checked['sha256'],
                        profile=str(profile),
                        profile_sha256=op['profile_sha256'],
                    )

                after = run(
                    project,
                    {'action': 'set', **arguments, 'channels': proposal['requirements']['channels']},
                )
                value = resource(after, action['key'])

                if action['key'] == 'sysmon':
                    if (
                        (not value)
                        or (value.get('state') != 'Running')
                        or (not value.get('config_sha256'))
                        or (value.get('binary_sha256') != op['package']['sha256'])
                    ):
                        raise ValueError('Sysmon post-install verification failed')
                elif value != action['desired']:
                    raise ValueError('Host change did not pass its postcondition')

                op.update(state='committed', after=value, finished_at=utc_now())
                save_ledger(root, ledger)
            except (Exception, KeyboardInterrupt) as exc:
                op.update(state='interrupted', reason=str(exc), finished_at=utc_now())
                persistence_error = save_ledger_after_error(root, ledger)

                if isinstance(exc, KeyboardInterrupt):
                    raise

                return {
                    'status': 'error',
                    'reason': str(exc),
                    'ledger': str(root / 'ledger.json'),
                    'persistence_error': persistence_error,
                    'recovery': 'Partial or unconfirmed changes are retained for review; no ownership is inferred',
                }

        result = inspect(project, proposal['requirements'], probe=run, root=root)
        result['ledger'] = str(root / 'ledger.json')

        return result

def restore(project, *, approved=False, dry_run=False, probe=None, root=None):
    root = root_path() if root is None else plain_path(root)
    run = probe or backend

    if not root.exists():
        return {'status': 'passed', 'operations': []}

    if not approved and (not dry_run):
        return {'status': 'blocked', 'reason': 'Restore requires explicit consent'}

    with installation_lock(root / 'operation'):
        ledger = read_ledger(root)
        results = []

        for op in reversed(ledger['operations']):
            if op['state'] == 'restored':
                continue

            if op['state'] != 'committed':
                results.append(
                    {
                        'id': op['id'],
                        'status': 'retained',
                        'reason': 'Ownership/change completion is unconfirmed',
                    },
                )
                continue

            current = run(project, {'action': 'observe', 'channels': sorted(CHANNELS)})

            if current.get('host_id') != ledger.get('host_id'):
                results.append(
                    {
                        'id': op['id'],
                        'status': 'retained',
                        'reason': 'Telemetry ledger belongs to another host',
                    },
                )
                continue

            if resource(current, op['key']) != op['after']:
                results.append(
                    {
                        'id': op['id'],
                        'status': 'retained',
                        'reason': 'Resource changed since TOTENKAHN modified it',
                    },
                )
                continue

            if dry_run:
                results.append({'id': op['id'], 'status': 'would_restore', 'key': op['key']})
                continue

            op['state'] = 'restoring'
            save_ledger(root, ledger)

            try:
                change = {
                    'action': 'set',
                    'key': op['key'],
                    'before': op['after'],
                    'desired': op['before'],
                    'channels': sorted(CHANNELS),
                }

                if op['key'] == 'sysmon':
                    change.update(
                        executable=op['package']['executable'],
                        executable_sha256=op['package']['sha256'],
                    )

                after = run(project, change)

                if after.get('errors', {}).get(op['key']) or resource(after, op['key']) != op['before']:
                    raise ValueError('Restore postcondition failed or could not be observed')

                op.update(state='restored', restored_at=utc_now())
                results.append({'id': op['id'], 'status': 'restored'})
            except (Exception, KeyboardInterrupt) as exc:
                op.update(state='interrupted', reason=str(exc))
                persistence_error = save_ledger_after_error(root, ledger)

                if isinstance(exc, KeyboardInterrupt):
                    raise

                results.append(
                    {
                        'id': op['id'],
                        'status': 'retained',
                        'reason': str(exc),
                        'persistence_error': persistence_error,
                    },
                )

                if persistence_error:
                    return {
                        'status': 'needs_verification',
                        'operations': results,
                        'reason': 'Restore stopped because its journal could not be saved',
                    }

            save_ledger(root, ledger)

        return {
            'status': 'needs_verification' if any((r['status'] == 'retained' for r in results)) else 'passed',
            'dry_run': dry_run,
            'operations': results,
            'preserved': [
                'event logs',
                'reports',
                'sessions',
                'packages',
                'journals',
                'unconfirmed or externally changed resources',
            ],
        }
