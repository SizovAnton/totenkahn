import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
from uuid import uuid4
import zipfile
# import yaml
from handlers.component_inventory import (
    create_inventory,
    create_component_record,
    begin_operation,
    finish_operation,
    utc_now,
)
from handlers.installation import (
    plain_path,
    installation_lock,
    save_state,
    save_state_after_error,
    load_state,
    place_file,
    component,
    inspect_installation,
    uninstall_release,
)
from handlers.package_cache import (
    load_dependency_lock,
    obtain_package,
    verify_package_file,
)
from handlers.package_extract import inspect_zip, extract_files
from handlers.release_manifest import (
    describe_file,
    collect_release_files,
    verify_release,
)
from handlers.atomic_bundle_check import check_module_paths
from handlers.runtime_paths import (
    data_root,
    read_settings,
    write_settings,
    generation_path,
)

COMPONENTS = {
    'powershell_yaml': ('powershell-yaml', 'powershell-yaml.psd1'),
    'invoke_atomic_red_team': ('Invoke-AtomicRedTeam', 'Invoke-AtomicRedTeam.psd1'),
    'atomic_definitions': ('atomics', None),
}
BASE_COMPONENTS = {key: value for key, value in COMPONENTS.items() if key != 'atomic_definitions'}

def failure_details(exc, *, component_id, operation, path=None):
    winerror = getattr(exc, 'winerror', None)

    return {
        'status': 'blocked' if winerror in (225, 226) else 'error',
        'component_id': component_id,
        'operation': operation,
        'path': str(path) if path else getattr(exc, 'filename', None),
        'reason': str(exc) or type(exc).__name__,
        'error_type': type(exc).__name__,
        'errno': getattr(exc, 'errno', None),
        'winerror': winerror,
        'category': 'protection_block' if winerror in (225, 226) else 'operation_failed_cause_not_confirmed',
    }

def locked_packages(project):
    packages = {p['component_id']: p for p in load_dependency_lock(project / 'config/dependencies.lock.json')['packages']}

    if not set(COMPONENTS) <= set(packages):
        raise ValueError('The dependency lock must include both modules and Atomic definitions')

    return {key: packages[key] for key in COMPONENTS}

def discover(project, *, root=None, atomic_dir=None):
    root = data_root() if root is None else plain_path(root)
    found = {key: [] for key in COMPONENTS}
    hints = []

    try:
        custom = json.loads((project / 'config/config.json').read_text(encoding='utf-8'))
        atomic = custom.get('atomic', {})

        for key, field in [
            ('powershell_yaml', 'yaml_module_path'),
            ('invoke_atomic_red_team', 'module_path'),
            ('atomic_definitions', 'atomics_path'),
        ]:
            if atomic.get(field):
                found[key].append(Path(atomic[field]))
    except FileNotFoundError:
        pass

    for raw in os.environ.get('PSModulePath', '').split(';' if sys.platform == 'win32' else os.pathsep):
        if raw:
            hints.append(Path(raw))

    user = Path.home()
    hints.extend(
        [user / 'Documents/WindowsPowerShell/Modules', user / 'Documents/PowerShell/Modules'],
    )

    for env_name in ('ProgramFiles', 'ProgramW6432'):
        if os.environ.get(env_name):
            hints.append(Path(os.environ[env_name]) / 'WindowsPowerShell/Modules')

    trees = [user / 'AtomicRedTeam', Path(os.environ.get('SystemDrive', 'C:') + '/AtomicRedTeam')]

    if atomic_dir is not None:
        trees.insert(0, Path(atomic_dir))

    for base in trees:
        found['atomic_definitions'].extend([base / 'atomics', base])
        hints.extend([base, base / 'invoke-atomicredteam', base / 'Invoke-AtomicRedTeam'])

    warnings = []

    for base in hints:
        for key, (folder, filename) in COMPONENTS.items():
            if filename is None:
                continue

            for directory in (base, base / folder):
                found[key].append(directory / filename)

                try:
                    if directory.is_dir():
                        found[key].extend((child / filename for child in directory.iterdir() if child.is_dir()))
                except OSError as exc:
                    warnings.append(str(exc))

    for candidate in found['invoke_atomic_red_team'][:]:
        found['atomic_definitions'].extend(
            [candidate.parent.parent / 'atomics', candidate.parent / 'atomics'],
        )

    result = {}

    for key, values in found.items():
        valid = {}

        for value in values:
            try:
                path = plain_path(value)

                if path == root or root in path.parents:
                    continue

                exists = path.is_dir() and any(path.glob('T*/T*.yaml')) if key == 'atomic_definitions' else path.is_file()

                if exists:
                    valid[os.path.normcase(str(path))] = str(path)
            except (OSError, ValueError) as exc:
                warnings.append(str(exc))

        result[key] = list(valid.values())

    return {
        'candidates': result,
        'warnings': sorted(set(warnings)),
        'scope': 'configured_paths_psmodulepath_and_known_atomic_locations',
        'compatibility': 'Candidates will be compared with pinned package contents before reuse',
    }

def plan(project, *, root=None, atomic_dir=None):
    root = data_root() if root is None else plain_path(root)

    return {
        'status': 'needs_verification',
        'command': 'dependencies plan',
        'data_directory': str(root),
        'discovery': discover(project, root=root, atomic_dir=atomic_dir),
        'packages': [p for k, p in locked_packages(project).items() if k in BASE_COMPONENTS],
        'actions': [
            'Verify existing components against pinned packages',
            'Reuse compatible external components; never overwrite them',
            'Install missing base modules only; Atomic definitions and resources are prepared per selected test',
            'Import verified modules and parse synthetic YAML without downloading Atomic definitions',
        ],
        'system_changes': 'No services, audit policies, Execution Policy or antivirus settings are changed',
        'separate': 'Test-specific prerequisites and Atomic execution require separate explicit actions',
    }

def tree_fingerprints(root):
    root = plain_path(root)

    return {name: describe_file(path) for name, path in collect_release_files(root).items()}

def definition_path(name):
    parts = name.split('/')

    return (
        (len(parts) == 2)
        and (re.fullmatch('T\\d{4}(?:\\.\\d{3})?', parts[0]) is not None)
        and (parts[1] == parts[0] + '.yaml')
    )

def component_files(root, key):
    if key == 'atomic_definitions':
        return {p.relative_to(root).as_posix(): describe_file(plain_path(p)) for p in root.glob('T*/T*.yaml') if definition_path(p.relative_to(root).as_posix())}

    files = tree_fingerprints(root)

    def metadata(name):
        return (
            (name in {'[Content_Types].xml', '_rels/.rels', 'PSGetModuleInfo.xml'})
            or ('/' not in name and name.endswith('.nuspec'))
            or (
                name.startswith('package/services/metadata/core-properties/')
                and name.endswith('.psmdcp')
            )
        )

    return {name: value for name, value in files.items() if not metadata(name)}

def compatible(candidate, expected, key):
    base = Path(candidate) if key == 'atomic_definitions' else Path(candidate).parent
    observed = component_files(base, key)
    extras = set(observed) - set(expected)

    return (
        (extras <= {'PSGetModuleInfo.xml'})
        and all((observed.get(name) == value for name, value in expected.items()))
    )

# def check_definitions(path):
#     path = plain_path(path)
#     definitions = sorted(path.glob('T*/T*.yaml'))
#     if not definitions:
#         raise ValueError('Atomic definitions are missing')
#     tests = 0
#     for file in definitions:
#         plain_path(file)
#         data = yaml.safe_load(file.read_text(encoding='utf-8-sig'))
#         if (
#             (not isinstance(data, dict))
#             or (data.get('attack_technique') != file.stem)
#             or (not isinstance(data.get('atomic_tests'), list))
#         ):
#             raise ValueError(f'Invalid Atomic definition: {file}')
#         tests += len(data['atomic_tests'])
#     return {
#         'status': 'passed',
#         'definitions_checked': len(definitions),
#         'tests_declared': tests,
#         'tests_executed': 0,
#         'scope': 'definition_structure_only_not_test_prerequisites',
#     }

def stage_package(archive, package, work):
    verify_package_file(archive, package)
    destination = work / package['component_id']
    destination.mkdir()

    with zipfile.ZipFile(archive) as zipped:
        entries = inspect_zip(zipped, max_entries=50000, max_unpacked_bytes=2 * 1024 ** 3)

        if package['component_id'] == 'atomic_definitions':
            prefixes = {relative.split('/atomics/', 1)[0] + '/atomics/' for _, relative, _ in entries if '/atomics/' in relative}

            if len(prefixes) != 1:
                raise ValueError('Unexpected Atomic archive layout')

            prefix = prefixes.pop()
            entries = [(entry, relative[len(prefix):], directory) for entry, relative, directory in entries if (
                relative.startswith(prefix)
                and definition_path(relative[len(prefix):])
                and (not directory)
            )]

        extract_files(zipped, entries, destination, max_unpacked_bytes=2 * 1024 ** 3)

    return destination

def selected_readiness(state):
    result = {}

    for key, record in state.get('selected_tests', {}).items():
        observed = dict(record)

        if record['status'] == 'passed':
            try:
                for name, expected in record['files'].items():
                    if describe_file(plain_path(Path(record['atomics_path']) / name)) != expected:
                        raise ValueError('Prepared resource changed: ' + name)
            except (OSError, ValueError) as exc:
                observed.update(status='blocked', reason=str(exc), ready=False)

        result[key] = observed

    return result

def status(project, *, root=None, runtime=False):
    root = data_root() if root is None else plain_path(root)
    settings = read_settings(root)

    if not settings['active']:
        return {
            'status': 'needs_verification',
            'reason': 'Base modules have not been prepared',
            'data_directory': str(root),
            'last_attempt': load_state(generation_path(root, settings['generations'][-1])).get('verification') if settings['generations'] else None,
        }

    target = generation_path(root, settings['active'])
    state = load_state(target)

    if state.get('purpose') != 'totenkahn_dependencies':
        raise ValueError('Unexpected resource ledger purpose')

    if state.get('lock_sha256') != describe_file(project / 'config/dependencies.lock.json')['sha256']:
        return {
            'status': 'needs_verification',
            'reason': 'Dependency lock changed; run dependencies prepare',
        }

    base_ids = {c['component_id'] for c in state['inventory']['components'] if c['component_key'] in BASE_COMPONENTS}
    inspected = dict(
        state,
        files={name: entry for name, entry in state['files'].items() if entry['component_id'] in base_ids},
    )
    integrity = inspect_installation(target, inspected)

    if state['status'] != 'installed' or integrity['status'] != 'passed':
        return {
            'status': 'blocked',
            'reason': 'Owned dependencies are missing, modified or incomplete',
            'integrity': integrity,
        }

    for key, files in state['external_files'].items():
        if key not in BASE_COMPONENTS:
            continue

        path = Path(state['module_paths'][key])
        base = path if key == 'atomic_definitions' else path.parent

        if component_files(base, key) != files:
            return {'status': 'blocked', 'reason': f'External component changed: {key}'}

    result = {
        'status': 'passed',
        'data_directory': str(root),
        'generation': str(target),
        'components': state['inventory']['components'],
        'verification': state['verification'],
        'scope': 'base_dependencies_only_not_live_readiness_or_test_prerequisites',
        'atomic_profile': state.get('atomic_profile', 'legacy_full'),
        'selected_tests': selected_readiness(state),
    }

    if runtime:
        probe = check_module_paths(
            Path(state['module_paths']['powershell_yaml']),
            Path(state['module_paths']['invoke_atomic_red_team']),
            state['packages'],
        )
        result.update(status=probe['status'], runtime=probe)

    return result

def prepare(project, *, approved=False, offline=False, root=None, cache=None, atomic_dir=None, _probe=None):
    if not approved:
        return {'status': 'blocked', 'reason': 'Dependency preparation requires explicit consent'}

    root = data_root() if root is None else plain_path(root)
    packages = locked_packages(project)
    candidates = discover(project, root=root, atomic_dir=atomic_dir)

    if sys.platform != 'win32' and _probe is None:
        return {'status': 'blocked', 'reason': 'Preparing Windows dependencies requires Windows'}

    if _probe is None and shutil.which('powershell.exe') is None:
        return {'status': 'blocked', 'reason': 'Windows PowerShell is required'}

    if (
        (project / 'release-manifest.json').is_file()
        and (not (project / '.totenkahn-state').exists())
    ):
        if verify_release(project)['status'] != 'passed':
            raise ValueError('Release integrity failed')

    root.mkdir(parents=True, exist_ok=True)
    cache = plain_path(cache) if cache else root / 'cache'

    with installation_lock(root / 'dependency-operation'):
        existing = status(project, root=root)

        if existing['status'] == 'passed':
            if _probe is None:
                return status(project, root=root, runtime=True)

            return existing

        settings = read_settings(root)
        name = str(uuid4())
        target = generation_path(root, name)
        target.mkdir(parents=True)
        state = {
            'schema_version': 1,
            'target': str(target),
            'status': 'installing',
            'purpose': 'totenkahn_dependencies',
            'atomic_profile': 'modules_only',
            'lock_sha256': describe_file(project / 'config/dependencies.lock.json')['sha256'],
            'inventory': create_inventory(),
            'files': {},
            'directories': [],
            'verification': None,
            'module_paths': {},
            'packages': packages,
            'external_files': {},
            'discovery': candidates,
        }

        for key in BASE_COMPONENTS:
            item = create_component_record(key)
            item.update(presence='absent', shared=False)
            state['inventory']['components'].append(item)

        save_state(target, state)
        settings['generations'].append(name)
        write_settings(root, settings)

        try:
            with tempfile.TemporaryDirectory(prefix='totenkahn-dependencies-') as temporary:
                work = Path(temporary)
                failures = []

                for key, (folder, filename) in BASE_COMPONENTS.items():
                    try:
                        print(f'Preparing base dependency: {key}', flush=True)
                        obtained = obtain_package(packages[key], cache, offline=offline)
                        staged = stage_package(Path(obtained['path']), packages[key], work)
                        expected = component_files(staged, key)

                        if filename and (not (staged / filename).is_file()):
                            raise ValueError(f'Module manifest missing: {key}')

                        selected = None

                        for candidate in candidates['candidates'][key]:
                            try:
                                if compatible(candidate, expected, key):
                                    selected = candidate
                                    break
                            except (OSError, ValueError):
                                pass

                        item = component(state, key)

                        if selected:
                            path = Path(selected)
                            base = path if filename is None else path.parent
                            state['external_files'][key] = component_files(base, key)
                            item.update(
                                origin='preexisting',
                                presence='present',
                                shared=True,
                                path=str(path),
                                version=packages[key]['version'],
                                last_checked_at=utc_now(),
                            )
                            item['source'].update(
                                kind='local',
                                location=str(path),
                                revision=packages[key]['version'],
                                sha256=packages[key]['sha256'],
                            )
                            state['module_paths'][key] = str(path)
                        else:
                            state['inventory'], op = begin_operation(state['inventory'], item['component_id'], 'install')
                            item = component(state, key)

                            for index, relative in enumerate(expected, 1):
                                place_file(
                                    target,
                                    state,
                                    item,
                                    op,
                                    f'managed/{folder}/{relative}',
                                    staged / relative,
                                    expected[relative],
                                )

                                if index % 100 == 0:
                                    print(f'Installed {key}: {index}/{len(expected)} files', flush=True)

                            state['inventory'] = finish_operation(
                                state['inventory'],
                                op,
                                status='succeeded',
                                verification='passed',
                                details='Pinned files installed and verified',
                            )
                            item = component(state, key)
                            path = target / 'managed' / folder

                            if filename:
                                path = path / filename

                            state['module_paths'][key] = str(path)
                            item.update(
                                origin='installed_by_totenkahn',
                                presence='present',
                                shared=False,
                                path=str(path),
                                version=packages[key]['version'],
                                installation_operation_id=op,
                                last_checked_at=utc_now(),
                            )
                            item['source'].update(
                                kind='url',
                                location=packages[key]['url'],
                                revision=packages[key]['version'],
                                sha256=packages[key]['sha256'],
                            )

                        save_state(target, state)
                    except Exception as exc:
                        failure = failure_details(exc, component_id=key, operation='prepare_base_module')
                        failures.append(failure)
                        state.setdefault('component_failures', {})[key] = failure

                        for operation in list(state['inventory']['operations']):
                            if operation['status'] == 'pending':
                                state['inventory'] = finish_operation(
                                    state['inventory'],
                                    operation['operation_id'],
                                    status='failed',
                                    verification='unknown',
                                    details=failure['reason'],
                                )

                        save_state(target, state)

                if failures:
                    probe = {
                        'status': 'needs_verification',
                        'reason': 'Some base modules were not prepared',
                        'failures': failures,
                    }
                else:
                    probe = (_probe or check_module_paths)(
                        Path(state['module_paths']['powershell_yaml']),
                        Path(state['module_paths']['invoke_atomic_red_team']),
                        packages,
                    )

                state['verification'] = {
                    'status': probe['status'],
                    'modules': probe,
                    'definitions': {'status': 'not_requested', 'reason': 'Prepared only for a selected test'},
                }
                state['status'] = 'installed' if probe['status'] == 'passed' else 'verification_failed'
                save_state(target, state)

                if state['status'] == 'installed':
                    settings['active'] = name
                    write_settings(root, settings)

                return {
                    'status': probe['status'],
                    'generation': str(target),
                    'verification': state['verification'],
                    'failures': failures,
                    'capabilities': {
                        'replay': 'available',
                        'atomic': 'requires_selected_test_preparation' if probe['status'] == 'passed' else 'not_ready',
                    },
                    'scope': 'base_modules_only_not_live_readiness_or_test_prerequisites',
                    'atomic_profile': 'modules_only',
                    'selected_tests': selected_readiness(state),
                }
        except (Exception, KeyboardInterrupt) as exc:
            state['status'] = 'interrupted'
            state['verification'] = {'status': 'error', 'reason': str(exc), 'error_type': type(exc).__name__}

            for op in list(state['inventory']['operations']):
                if op['status'] == 'pending':
                    state['inventory'] = finish_operation(
                        state['inventory'],
                        op['operation_id'],
                        status='failed',
                        verification='unknown',
                        details=str(exc) or type(exc).__name__,
                    )

            persistence_error = save_state_after_error(target, state)

            if isinstance(exc, KeyboardInterrupt):
                raise

            return {
                'status': 'blocked' if getattr(exc, 'winerror', None) in (225, 226) else 'error',
                'reason': str(exc),
                'error_type': type(exc).__name__,
                'generation': str(target),
                'persistence_error': persistence_error,
                'recovery': 'Inspect the journal; remove confirmed owned files with dependencies remove. Protection settings are not changed.',
            }

def remove(*, root=None, approved=False, dry_run=False):
    root = data_root() if root is None else plain_path(root)

    if not approved and (not dry_run):
        return {'status': 'blocked', 'reason': 'Removal requires explicit consent'}

    if not root.exists():
        return {'status': 'passed', 'reason': 'No TOTENKAHN dependencies are recorded'}

    with installation_lock(root / 'dependency-operation'):
        settings = read_settings(root)
        results = []

        for name in settings['generations']:
            target = generation_path(root, name)
            state = load_state(target)

            if state.get('purpose') != 'totenkahn_dependencies':
                raise ValueError('Unexpected resource ledger purpose')

            results.append(uninstall_release(target, dry_run=dry_run))

        if not dry_run:
            settings['active'] = None
            write_settings(root, settings)

        return {
            'status': 'passed' if all((r['status'] == 'passed' for r in results)) else 'needs_verification',
            'dry_run': dry_run,
            'results': results,
            'retained': ['reports', 'runs', 'cache', 'journals', 'external components', 'modified files'],
        }
