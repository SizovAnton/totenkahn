"""Шляхи готового комплекту та окремі користувацькі дані DVP."""
import json
import os
import sys
from pathlib import Path
import tempfile
from handlers.installation import plain_path, load_state
from handlers.component_inventory import reject_duplicate_keys, reject_json_constant


def data_root():
    override = os.environ.get('DVP_HOME')
    base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/share')))
    return plain_path(Path(override) if override else base / 'DVP')


def read_settings(root):
    path = plain_path(root / 'settings.json')
    if not path.exists():
        return {'schema_version': 1, 'active': None, 'generations': []}
    data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=reject_duplicate_keys,
                      parse_constant=reject_json_constant)
    if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('generations'), list):
        raise ValueError('Invalid DVP settings')
    for name in data['generations']:
        generation_path(root, name)
    if data.get('active') is not None and data['active'] not in data['generations']:
        raise ValueError('Active dependencies are not in the resource ledger')
    return data


def generation_path(root, name):
    from uuid import UUID
    if not isinstance(name, str) or str(UUID(name)) != name:
        raise ValueError('Invalid dependency generation identifier')
    return plain_path(root / 'dependencies' / name)


def write_settings(root, data):
    path = plain_path(root / 'settings.json')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=root, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2, allow_nan=False)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); temporary = None
    finally:
        if temporary: temporary.unlink(missing_ok=True)


def runtime_config(project, *, root=None, use_dependencies=True):
    from handlers.file_handlers import load_configuration
    config = load_configuration(project/'config/default.config', project/'config/config.json')
    if not use_dependencies:
        if getattr(sys,'frozen',False) or os.environ.get('DVP_HOME'):
            data=data_root() if root is None else plain_path(root)
            config.setdefault('paths',{}).update(reports_dir=str(data/'reports'),runs_dir=str(data/'runs'))
        return config
    root = data_root() if root is None else plain_path(root)
    settings = read_settings(root)
    # Legacy install та developer-run без bootstrap зберігають попередню поведінку.
    if settings['generations']:
        config.setdefault('paths', {}).update(reports_dir=str(root/'reports'),runs_dir=str(root/'runs'))
    if settings['active'] is None:
        return config
    state = load_state(generation_path(root, settings['active']))
    if state.get('purpose') != 'dvp_dependencies' or state['status'] != 'installed':
        raise ValueError('Dependencies are not ready; run dependencies prepare')
    config.setdefault('atomic', {}).update(module_path=state['module_paths']['invoke_atomic_red_team'],
        yaml_module_path=state['module_paths']['powershell_yaml'], atomics_path=state['module_paths'].get('atomic_definitions',str(generation_path(root,settings['active'])/'selected-preview')))
    config['atomic']['selected_tests']=state.get('selected_tests',{})
    config['atomic']['managed_catalog']=True
    config.setdefault('paths', {}).update(reports_dir=str(root/'reports'), runs_dir=str(root/'runs'))
    return config
