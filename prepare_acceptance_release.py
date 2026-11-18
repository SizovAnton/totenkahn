import json
import shutil
import sys
from datetime import datetime
from importlib.metadata import distributions
from pathlib import Path

from handlers.release_manifest import build_manifest, write_manifest, verify_release, describe_file

root = Path.cwd()
build = root / 'build/windows-20261112-195000'
release = build / ('release-acceptance-' + datetime.now().strftime('%Y%m%d-%H%M%S'))

for name in ('dvp', 'dvp-setup'):
    if not (build / 'dist' / name / (name + '.exe')).is_file():
        raise SystemExit('Missing built executable: ' + name)

release.mkdir()
for name in ('dvp', 'dvp-setup'):
    for item in (build / 'dist' / name).iterdir():
        destination = release / item.name
        if destination.exists():
            raise RuntimeError('Build file collision: ' + str(destination))
        if item.is_dir():
            shutil.copytree(item, destination)
        else:
            shutil.copy2(item, destination)

(release / 'config').mkdir()
for name in ('default.config', 'components.json', 'dependencies.lock.json'):
    shutil.copy2(root / 'config' / name, release / 'config' / name)

(release / 'config/config.json').write_text('{}\n', encoding='utf-8')
(release / 'scripts').mkdir()

for source in (root / 'scripts').glob('*.ps1'):
    shutil.copy2(source, release / 'scripts' / source.name)

shutil.copytree(root / 'examples', release / 'examples')

for name in ('README.md', 'LICENSE'):
    shutil.copy2(root / name, release / name)

shutil.copy2(build / 'build-environment.txt', release / 'build-environment.txt')

licenses = release / 'licenses'
licenses.mkdir()

notices = ['DVP internal acceptance build. Not a production release.',
           'Package inventory includes build tools, not only bundled runtime packages.', '']

for dist in sorted(distributions(), key=lambda d: d.metadata['Name'].lower()):
    name = dist.metadata['Name']
    notices.append(name + ' ' + dist.version)
    
    for entry in dist.files or []:
        if any(token in entry.name.lower() for token in ('license', 'copying', 'notice')):
            source = Path(str(dist.locate_file(entry)))
            
            if source.is_file():
                folder = licenses / name
                folder.mkdir(exist_ok=True)
                destination = folder / (str(len(list(folder.iterdir()))) + '-' + entry.name)
                shutil.copy2(source, destination)

python_license = Path(sys.base_prefix) / 'LICENSE.txt'

if not python_license.is_file():
    raise RuntimeError('Python LICENSE.txt was not found')

shutil.copy2(python_license, licenses / 'Python-LICENSE.txt')
(release / 'THIRD_PARTY_NOTICES.txt').write_text('\n'.join(notices) + '\n', encoding='utf-8')

baseline = '1b871d023dc591da7a5aba096f4c5468da962ffc'
sources = {}

for name in ('main.py', 'dvp_setup.py', 'handlers', 'scripts', 'reporting', 'displaying', 'rule_condition'):
    path = root / name

    for source in ([path] if path.is_file() else path.rglob('*.py')):
        sources[source.relative_to(root).as_posix()] = describe_file(source)

provenance = {
    'purpose': 'internal_windows_installer_acceptance',
    'reference_commit': baseline,
    'source_state': 'Local modified build; commit is a development baseline only',
    'source_snapshot_timing': 'packaging time; not independently verified against executable inputs',
    'source_files': sources,
}

(release / 'build-provenance.json').write_text(json.dumps(provenance, indent=2), encoding='utf-8')
manifest = build_manifest(release, version='0.0.0-acceptance.20261112', source_commit=baseline)
write_manifest(release, manifest)
result = verify_release(release)

print(json.dumps(result, indent=2))

if result['status'] != 'passed':
    raise SystemExit(1)

(build / 'acceptance-release-path.txt').write_text(str(release), encoding='utf-8')
print('Release directory:', release)
