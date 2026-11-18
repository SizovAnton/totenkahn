"""Керований життєвий цикл приватного каталогу DVP, без запуску тестів ART."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager, ExitStack
from pathlib import Path
from uuid import uuid4

from handlers.component_inventory import (
    create_inventory, create_component_record, validate_inventory,
    begin_operation, finish_operation, utc_now, reject_duplicate_keys,
    reject_json_constant, require_sha256,
)
from handlers.release_manifest import (
    verify_release, load_manifest, describe_file, validate_release_path,
)
from handlers.package_cache import load_dependency_lock, obtain_package
from handlers.package_extract import prepare_zip_package
from handlers.atomic_bundle_check import check_module_paths

STATE_DIR = '.dvp-state'
MODULES = {
    'powershell_yaml': ('powershell-yaml', 'powershell-yaml.psd1'),
    'invoke_atomic_red_team': ('Invoke-AtomicRedTeam', 'Invoke-AtomicRedTeam.psd1'),
}
PRESERVED = {'runs', 'reports', 'logs', 'evidence', '.dvp-package-cache'}


def progress(message):
    print(message, file=sys.stderr, flush=True)


def plain_path(path):
    """Відхиляємо посилання та reparse points у всьому наявному шляху."""
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError(f'Linked paths are not supported: {part}')
    return path


def local_path(root, relative):
    validate_release_path(relative)
    return plain_path(root.joinpath(*relative.split('/')))


@contextmanager
def installation_lock(target):
    target = plain_path(target)
    if not target.parent.is_dir():
        raise ValueError('Target parent directory must already exist')
    # Файл блокування не видаляємо: інакше два процеси можуть блокувати різні inode.
    lock_path = plain_path(target.parent / f'.{target.name}.dvp.lock')
    with lock_path.open('a+b') as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError('Another setup operation is using this target') from exc
        try:
            yield target
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def state_path(target):
    return local_path(target, STATE_DIR + '/installation.json')


def save_state(target, state):
    validate_state(target, state)
    destination = state_path(target)
    destination.parent.mkdir(exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(state, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_state_after_error(target, state):

    try:
        save_state(target, state)
    except Exception as exc:
        print('Could not persist installation failure: '+str(exc),file=sys.stderr,flush=True)
        return str(exc)
    
    return None

def validate_state(target, state):
    
    if not isinstance(state, dict) or type(state.get('schema_version')) is not int or state['schema_version'] != 1:
        raise ValueError('Unsupported installation state')
    
    if not isinstance(state.get('target'), str) or os.path.normcase(state['target']) != os.path.normcase(str(target)):
        raise ValueError('Installation state belongs to a different target')
    
    if state.get('status') not in {'installing', 'installed', 'verification_failed', 'interrupted', 'removing', 'removed', 'partial'}:
        raise ValueError('Unknown installation status')
    
    validate_inventory(state['inventory'])
    
    if not isinstance(state.get('files'), dict) or not isinstance(state.get('directories'), list):
        raise ValueError('Invalid installation resource ledger')
    
    ops = {op['operation_id']: op for op in state['inventory']['operations']}
    
    owned_resources = {c['component_id']: {(r['kind'], r['identifier'], r['created_by_operation_id'])
        for r in c['resources']} for c in state['inventory']['components']}
    
    seen = set()
    
    for relative, record in state['files'].items():
        validate_release_path(relative)
        folded = relative.casefold()
        
        if folded in seen or relative.split('/')[0].casefold() == STATE_DIR:
            raise ValueError('Invalid or duplicate managed path')
        
        seen.add(folded)
        
        if record.get('state') not in {'planned', 'created', 'deleted', 'abandoned'}:
            raise ValueError('Invalid file ownership state')
        if type(record.get('size')) is not int or record['size'] < 0 or record.get('sha256') is None:
            raise ValueError('Invalid managed file fingerprint')
        
        require_sha256(record['sha256'], 'Managed file hash')
        
        if type(record.get('shared')) is not bool:
            raise ValueError('Managed file shared flag must be boolean')
        
        op = ops.get(record.get('operation_id'))
        
        if op is None or op['action'] != 'install' or op['before_presence'] != 'absent':
            raise ValueError('Managed file lacks an installation operation')
        if op['component_id'] != record.get('component_id'):
            raise ValueError('Managed file component does not match its operation')
        if record['state'] in {'created', 'deleted'}:
            if ('file', relative, record['operation_id']) not in owned_resources.get(record['component_id'], set()):
                raise ValueError('Managed file lacks a matching inventory resource')
    
    for relative in state['directories']:
        validate_release_path(relative)
        
        if relative.split('/')[0].casefold() == STATE_DIR:
            raise ValueError('State directory cannot be a removable resource')
    
    return state

def load_state(target):
    with state_path(target).open(encoding='utf-8') as stream:
        state = json.load(stream, object_pairs_hook=reject_duplicate_keys,
                          parse_constant=reject_json_constant)
    
    return validate_state(target, state)

def component(state, key):
    matches = [c for c in state['inventory']['components'] if c['component_key'] == key]
    
    if len(matches) != 1:
        raise ValueError(f'Expected one component record: {key}')
    
    return matches[0]

def fingerprint_matches(path, record):
    observed = describe_file(path)
    
    return observed['size'] == record['size'] and observed['sha256'] == record['sha256']

def ensure_parents(target, path, state):
    for parent in reversed(path.relative_to(target).parents):
        if str(parent) == '.':
            continue
        
        destination = local_path(target, parent.as_posix())
        
        if destination.exists():
            if not destination.is_dir():
                raise ValueError(f'Expected directory: {destination}')
        
        else:
            destination.mkdir()
            state['directories'].append(parent.as_posix())
            save_state(target, state)

def copy_exclusive(source, destination):
  
    with source.open('rb') as src, destination.open('xb') as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())

def place_file(target, state, comp, operation_id, relative, source, expected=None):
    destination = local_path(target, relative)
    wanted = describe_file(source)
    
    if expected is not None and wanted != {k: expected[k] for k in ('size', 'sha256')}:
        raise ValueError(f'Release file changed after verification: {relative}')
    
    previous = state['files'].get(relative)
    
    if previous is not None:
        if previous['state'] == 'created' and destination.is_file() and fingerprint_matches(destination, previous):
            if wanted != {k: previous[k] for k in ('size', 'sha256')}:
                raise ValueError(f'Upgrade is not supported: {relative}')
            
            return
        
        if destination.exists():
            raise ValueError(f'Existing or modified file is preserved: {relative}')
    
    elif destination.exists():
        raise ValueError(f'Untracked file is preserved: {relative}')
    
    ensure_parents(target, destination, state)
    
    state['files'][relative] = {
        **wanted, 'state': 'planned', 'shared': False,
        'component_id': comp['component_id'], 'operation_id': operation_id,
    }

    save_state(target, state)
    copy_exclusive(source, destination)
    
    if not fingerprint_matches(destination, wanted):
        raise ValueError(f'Copied file verification failed: {relative}')
    
    state['files'][relative]['state'] = 'created'
    resource = {'kind': 'file', 'identifier': relative,
                'created_by_operation_id': operation_id, 'shared': False}
    
    comp['resources'] = [r for r in comp['resources'] if r['identifier'] != relative] + [resource]
    
    save_state(target, state)

def inspect_installation(target, state=None):
    target = plain_path(target)
    state = load_state(target) if state is None else validate_state(target, state)
    issues = []
    
    for relative, record in state['files'].items():
        if record['state'] in {'deleted', 'abandoned'}:
            continue
        
        try:
            path = local_path(target, relative)
            
            if record['state'] != 'created':
                reason = 'Ownership is unconfirmed after an interrupted write'
            elif not path.is_file():
                reason = 'Managed file is missing'
            elif not fingerprint_matches(path, record):
                reason = 'Managed file was modified'
            else:
                continue
        
        except (OSError, ValueError) as exc:
            reason = str(exc)
        
        issues.append({'path': relative, 'reason': reason})
    
    return {'status': 'passed' if not issues else 'blocked', 'issues': issues,
            'installation_status': state['status'], 'verification': state['verification']}

def verify_installed(target, state, timeout=180):
    integrity = inspect_installation(target, state)
    
    if integrity['status'] != 'passed':
        return integrity
    
    if sys.platform != 'win32':
        raise ValueError('Installed Windows executable verification requires Windows')

    completed = subprocess.run([str(target / 'dvp.exe'), '--help'],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=min(timeout, 30), check=False)
    application = {'status': 'passed' if completed.returncode == 0 else 'failed',
                   'exit_code': completed.returncode}
    if completed.returncode != 0:
        application['stderr'] = completed.stderr.decode('utf-8', errors='replace')[:4000]
        
        return {'status': 'failed', 'scope': 'installed_application_and_modules', 'application': application}
    
    paths = state['module_paths']
    modules = check_module_paths(Path(paths['powershell_yaml']), Path(paths['invoke_atomic_red_team']),
                                state['packages'], timeout_seconds=timeout)
    
    return {'status': modules['status'], 'scope': 'installed_application_and_modules',
            'application': application, 'modules': modules}


def install_release(release_dir, target, cache_dir, *, offline=False,
                    external_yaml=None, external_art=None, timeout=180, _verifier=None):
    release_dir = plain_path(release_dir)
    target = plain_path(target)
    cache_dir = plain_path(cache_dir)
    
    for other in (release_dir, target):
        if cache_dir == other or cache_dir in other.parents or other in cache_dir.parents:
            raise ValueError('Cache, release and installation directories must be separate and non-nested')
    
    if target == release_dir or target in release_dir.parents or release_dir in target.parents:
        raise ValueError('Release and installation directories must be separate')
    if bool(external_yaml) != bool(external_art):
        raise ValueError('Provide both external module manifests or neither')
    
    progress('Verifying release files')
    
    release_check = verify_release(release_dir)
    
    if release_check['status'] != 'passed':
        raise ValueError(f'Release integrity failed: {json.dumps(release_check)}')
    
    manifest = load_manifest(release_dir)
    
    for item in manifest['files']:
        if item['path'].split('/')[0].casefold() in PRESERVED | {STATE_DIR, 'managed'}:
            raise ValueError(f'Release uses a reserved installation path: {item["path"]}')
    
    lock = load_dependency_lock(release_dir / 'config/dependencies.lock.json')
    packages = {p['component_id']: p for p in lock['packages'] if p['component_id'] in MODULES}
    
    if set(packages) != set(MODULES):
        raise ValueError('Both locked module packages are required')
    
    release_hash = describe_file(release_dir / 'release-manifest.json')['sha256']
    external = None if external_yaml is None else {
        'powershell_yaml': str(plain_path(external_yaml)),
        'invoke_atomic_red_team': str(plain_path(external_art)),
    }
    
    if external:
        for value in external.values():
            if target == Path(value) or target in Path(value).parents:
                raise ValueError('External modules must be outside the installation target')
    
    verifier = _verifier or verify_installed
    
    with installation_lock(target):
        if state_path(target).exists():
            state = load_state(target)
            if state['release_sha256'] != release_hash or state['external_modules'] != external:
                raise ValueError('Changing release or external modules requires a new target')
            if state['status'] in {'removed', 'partial', 'removing'}:
                raise ValueError('Use a new target after removal; retained evidence is preserved')

            for relative, record in state['files'].items():
                path = local_path(target, relative)
                if path.exists() and (record['state'] != 'created' or not fingerprint_matches(path, record)):
                    raise ValueError(f'Existing or modified file is preserved: {relative}')
            
            for op in list(state['inventory']['operations']):
                if op['status'] == 'pending':
                    state['inventory'] = finish_operation(state['inventory'], op['operation_id'],
                        status='interrupted', verification='unknown', details='Recovered unfinished operation; resources will be rechecked')
            
            save_state(target, state)
            
            if state['status'] in {'installed', 'verification_failed'} and inspect_installation(target, state)['status'] == 'passed':
                state['status'] = 'verification_failed'
                state['verification'] = {'status': 'unknown', 'reason': 'Reverification in progress'}
                save_state(target, state)
                
                try:
                    report = verifier(target, state, timeout)
                except BaseException as exc:
                    state['verification'] = {'status': 'error', 'reason': str(exc), 'error_type': type(exc).__name__}
                    save_state_after_error(target, state)
                    raise
                
                state['verification'] = report
                state['status'] = 'installed' if report['status'] == 'passed' else 'verification_failed'
                
                if external and state['status'] == 'installed':
                    for key in MODULES:
                        component(state, key).update(presence='present', version=packages[key]['version'], last_checked_at=utc_now())
                
                save_state(target, state)
                
                return install_report(target, state, repeated=True)
        
        else:
            if target.exists() and any(target.iterdir()):
                raise ValueError('A new installation requires an empty target directory')
            
            target.mkdir(exist_ok=True)
            state = {
                'schema_version': 1, 'target': str(target), 'status': 'installing',
                'release_sha256': release_hash, 'release_version': manifest['version'],
                'inventory': create_inventory(), 'files': {}, 'directories': [],
                'packages': packages, 'external_modules': external, 'module_paths': {},
                'verification': None,
            }
            
            for key in ['dvp', *MODULES]:
                c = create_component_record(key)
                c['presence'] = 'absent'
                c['shared'] = False
                state['inventory']['components'].append(c)
            save_state(target, state)
        
        try:
            state['status'] = 'installing'
            save_state(target, state)
            
            with tempfile.TemporaryDirectory(prefix='dvp-install-') as work, ExitStack() as stack:
                work = Path(work)
                staged = {}
                if not external:
                    
                    for key, (module_name, manifest_name) in MODULES.items():
                        progress(f'Preparing private module: {key}')
                        obtained = obtain_package(packages[key], cache_dir, offline=offline)
                        prepared = stack.enter_context(prepare_zip_package(Path(obtained['path']), packages[key], staging_parent=work))
                        base = Path(prepared['directory'])
                 
                        if not (base / manifest_name).is_file():
                            raise ValueError(f'Unexpected module package layout: {key}')
                        
                        staged[key] = base
                        state['module_paths'][key] = str(target / 'managed' / 'modules' / module_name / manifest_name)
                
                else:
                    state['module_paths'] = external
                    
                    for key in MODULES:
                        c = component(state, key)
                        c.update(origin='preexisting', presence='unknown', shared=True, path=external[key])
                        c['source'].update(kind='local', location=external[key])
                
                save_state(target, state)
                expected_files = {i['path']: i for i in manifest['files']}
                
                if not fingerprint_matches(release_dir / 'config/config.json', expected_files['config/config.json']):
                    raise ValueError('Release configuration changed after verification')
                
                config = json.loads((release_dir / 'config/config.json').read_text(encoding='utf-8'))
                
                if not isinstance(config, dict):
                    raise ValueError('Release config must be an object')
                
                atomic = config.setdefault('atomic', {})
                atomic['module_path'] = state['module_paths']['invoke_atomic_red_team']
                atomic['yaml_module_path'] = state['module_paths']['powershell_yaml']

                atomic['atomics_path'] = str(target / 'managed' / 'atomics')
                generated = work / 'config.json'
                generated.write_text(json.dumps(config, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
                groups = {'dvp': [(i['path'], release_dir / i['path']) for i in manifest['files']]}
                groups['dvp'] = [(rel, generated if rel == 'config/config.json' else src) for rel, src in groups['dvp']]
                groups['dvp'].append(('release-manifest.json', release_dir / 'release-manifest.json'))
                
                for key, base in staged.items():
                    module_name = MODULES[key][0]
                    groups[key] = [(f'managed/modules/{module_name}/{p.relative_to(base).as_posix()}', p)
                                   for p in sorted(base.rglob('*')) if p.is_file()]
                
                for key, files in groups.items():
                    progress(f'Installing component: {key}')
                    
                    c = component(state, key)
                    c['presence'] = 'absent'
                    state['inventory'], op_id = begin_operation(state['inventory'], c['component_id'], 'install')
                    c = component(state, key)
                    
                    save_state(target, state)
                    
                    for relative, source in files:
                        expected = None
                        if key == 'dvp' and relative != 'config/config.json':
                            expected = expected_files.get(relative)
                            if relative == 'release-manifest.json':
                                expected = {'size': source.stat().st_size, 'sha256': release_hash}
                        
                        place_file(target, state, c, op_id, relative, source, expected)
                    
                    state['inventory'] = finish_operation(state['inventory'], op_id, status='succeeded',
                        verification='passed', details='All component files copied and verified; runtime verification is separate')
                    
                    c = component(state, key)
                    c.update(origin='installed_by_dvp', presence='present', installation_operation_id=op_id,
                             path=str(target if key == 'dvp' else Path(state['module_paths'][key]).parent),
                             version=manifest['version'] if key == 'dvp' else packages[key]['version'], last_checked_at=utc_now())
                    c['source'].update(kind='release' if key == 'dvp' else 'url',
                        location=str(release_dir) if key == 'dvp' else packages[key]['url'],
                        revision=manifest['source_commit'] if key == 'dvp' else packages[key]['version'],
                        sha256=release_hash if key == 'dvp' else packages[key]['sha256'])
                    c['removal'].update(method='owned_files', reason='Removal requires unchanged file hashes and unshared ownership')
                    
                    save_state(target, state)
            
            progress('Verifying installed module paths and synthetic YAML')
            
            state['verification'] = verifier(target, state, timeout)
            state['status'] = 'installed' if state['verification']['status'] == 'passed' else 'verification_failed'
            
            if external and state['status'] == 'installed':
                for key in MODULES:
                    component(state, key).update(presence='present', version=packages[key]['version'], last_checked_at=utc_now())
            
            save_state(target, state)
            
            return install_report(target, state)
        
        except BaseException as exc:
            state['status'] = 'interrupted'
            
            for op in list(state['inventory']['operations']):
                if op['status'] == 'pending':
                    state['inventory'] = finish_operation(state['inventory'], op['operation_id'],
                        status='interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed',
                        verification='unknown', details=f'{type(exc).__name__}: {exc}')
            
            save_state_after_error(target, state)
            
            raise

def install_report(target, state, repeated=False):
    
    return {'command': 'install', 'status': 'passed' if state['status'] == 'installed' else 'needs_verification',
            'target': str(target), 'installation_status': state['status'], 'repeated': repeated,
            'verification': state['verification'], 'installation_id': state['inventory']['installation_id'],
            'scope': 'release_files_application_start_and_module_import',
            'pending_capabilities': ['event_collection', 'selected_atomic_definitions', 'selected_test_prerequisites']}

def removal_plan(target, state=None):
    target = plain_path(target)
    state = load_state(target) if state is None else validate_state(target, state)
    items = []
    components = {c['component_id']: c for c in state['inventory']['components']}
    
    for relative, record in state['files'].items():
        action, reason = 'retain', 'Ownership or content is not confirmed'
        
        try:
            path = local_path(target, relative)
            
            if not path.exists():
                action, reason = 'absent', 'File is already absent'
            elif relative.split('/')[0].casefold() in PRESERVED:
                reason = 'Evidence and reports are preserved'
            elif record['shared'] or components[record['component_id']]['shared'] is not False or components[record['component_id']]['origin'] == 'preexisting':
                reason = 'Shared or preexisting resource'
            elif record['state'] == 'created' and fingerprint_matches(path, record):
                action, reason = 'remove', 'Owned unchanged file'
        
        except (OSError, ValueError) as exc:
            reason = str(exc)
        
        items.append({'path': relative, 'action': action, 'reason': reason})

    if target.is_dir():
        for directory, dirs, files in os.walk(target, followlinks=False):
            
            if Path(directory) == target:
                dirs[:] = [d for d in dirs if d != STATE_DIR]
            for name in list(dirs):
                relative = (Path(directory) / name).relative_to(target).as_posix()
                
                try:
                    local_path(target, relative)
                except (OSError, ValueError):
                    dirs.remove(name)
                    items.append({'path': relative, 'action': 'retain', 'reason': 'Linked or inaccessible directory'})
            
            for name in dirs:
                relative = (Path(directory) / name).relative_to(target).as_posix()
                
                if relative not in state['directories']:
                    items.append({'path': relative, 'action': 'retain', 'reason': 'Untracked directory'})
            
            for name in files:
                relative = (Path(directory) / name).relative_to(target).as_posix()
                
                if relative not in state['files']:
                    items.append({'path': relative, 'action': 'retain', 'reason': 'Untracked file'})
    
    return {'command': 'uninstall', 'status': 'passed', 'dry_run': True, 'target': str(target),
            'items': items, 'retained_state': STATE_DIR,
            'external_components': [c['path'] for c in state['inventory']['components'] if c['origin'] == 'preexisting']}

def uninstall_release(target, *, dry_run=False):
    with installation_lock(target) as target:
        state = load_state(target)
        plan = removal_plan(target, state)
        
        if dry_run:
            return plan
        
        state['status'] = 'removing'

        for op in list(state['inventory']['operations']):
            if op['status'] == 'pending':
                state['inventory'] = finish_operation(state['inventory'], op['operation_id'],
                    status='interrupted', verification='unknown', details='Recovered interrupted operation')
        
        
        save_state(target, state)
        
        errors = []
        
        for c in list(state['inventory']['components']):
            if c['origin'] == 'preexisting':
                continue
            
            state['inventory'], op_id = begin_operation(state['inventory'], c['component_id'], 'remove')
            
            save_state(target, state)
            
            for item in plan['items']:
                record = state['files'].get(item['path'])
                if record is None or record['component_id'] != c['component_id'] or item['action'] not in {'remove', 'absent'}:
                    continue
                
                try:
                    path = local_path(target, item['path'])
                    if path.exists():
                     
                        if item['action'] != 'remove' or record['state'] != 'created' or record['shared'] or not fingerprint_matches(path, record):
                            raise ValueError('Resource changed after preview; retained')
                        
                        path.unlink()
                    
                    record['state'] = 'abandoned' if record['state'] == 'planned' else 'deleted'
                    
                    save_state(target, state)
                
                except (OSError, ValueError) as exc:
                    errors.append({'path': item['path'], 'reason': str(exc)})
            
            remaining = [r for r in state['files'].values() if r['component_id'] == c['component_id'] and r['state'] not in {'deleted', 'abandoned'}]
            state['inventory'] = finish_operation(state['inventory'], op_id,
                status='failed' if remaining else 'succeeded', verification='failed' if remaining else 'passed',
                details='Retained resources remain' if remaining else 'All owned component files are absent')
            
            for current in state['inventory']['components']:
                if current['component_id'] == c['component_id']:
                    current['presence'] = 'unknown' if remaining else 'absent'
            
            save_state(target, state)
        
        for relative in sorted(set(state['directories']), key=lambda p: len(p.split('/')), reverse=True):
            try:
                local_path(target, relative).rmdir() 
            except FileNotFoundError:
                pass
            except OSError:
                pass  
            except ValueError as exc:
                errors.append({'path': relative, 'reason': str(exc)})
        
        result = removal_plan(target, state)
        retained = [i for i in result['items'] if i['path'] in state['files'] and i['action'] != 'absent']
        state['status'] = 'partial' if retained or errors else 'removed'
        
        save_state(target, state)
        
        result.update(dry_run=False, status='needs_verification' if retained or errors else 'passed',
                      installation_status=state['status'], errors=errors)
        
        return result
