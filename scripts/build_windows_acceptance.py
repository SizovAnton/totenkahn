"""Build both Windows executables, package a test release and run acceptance."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.release_manifest import build_manifest, write_manifest, verify_release, describe_file, validate_commit
from handlers.package_cache import load_dependency_lock, obtain_package
from handlers.cli_result import STATUS_CODES, status_code, run_cli
from handlers.process_control import terminate_process

PACKAGES = ('PyInstaller==6.22.3', 'PyYAML==6.0.3', 'rich==15.0.0')


def snapshot(root):
    paths = [root / name for name in ('main.py', 'dvp_setup.py', 'validation.py', 'prepare_acceptance_release.py', 'README.md', 'LICENSE', 'pyrightconfig.json', 'requirements-quality.txt')]
    for folder in ('handlers', 'reporting', 'displaying', 'rule_condition', 'scripts'):
        paths.extend(p for p in (root / folder).rglob('*')
                     if p.is_file() and '__pycache__' not in p.parts and p.suffix in {'.py', '.ps1', '.json', '.yaml', '.yml'})
    paths.extend(p for p in (root / 'examples').rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    paths.extend(root / 'config' / name for name in ('default.config', 'components.json', 'dependencies.lock.json'))
    return {p.relative_to(root).as_posix(): describe_file(p) for p in sorted(paths)}


def run_step(command, log, cwd, timeout=900, allowed=(0,)):
    print(f'Starting: {log.stem}; log: {log}', flush=True)
    started = time.monotonic()
    env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUTF8='1')
    with log.open('wb') as output:
        process = subprocess.Popen([str(a) for a in command], cwd=cwd, env=env,
            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        next_notice = 15
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed > timeout:
                    raise TimeoutError(f'{log.stem} exceeded {timeout}s; see {log}')
                if elapsed >= next_notice:
                    print(f'Running: {log.stem} ({int(elapsed)}s)', flush=True)
                    next_notice += 15
                time.sleep(0.2)
        finally:
            if process.poll() is None:
                terminate_process(process)
    if process.returncode not in allowed:
        tail = log.read_text(encoding='utf-8', errors='replace')[-5000:]
        raise RuntimeError(f'{log.stem} exited {process.returncode}.\n{tail}')
    print(f'Finished: {log.stem} (exit {process.returncode})', flush=True)
    return process.returncode


def package_release(root, build, baseline):
    from importlib.metadata import distributions
    expected = json.loads((build / 'source-inputs.json').read_text(encoding='utf-8'))
    if snapshot(root) != expected:
        raise ValueError('Source inputs changed during the build; start a new build')
    for gate in ('quality', 'source-checks'):
        gate_report=json.loads((build/gate/'report.json').read_text(encoding='utf-8'))
        if gate_report.get('status')!='passed':
            raise ValueError('Required build gate did not pass: '+gate)
    release = build / 'release'
    release.mkdir(exist_ok=False)
    for name in ('dvp', 'dvp-setup'):
        bundle = build / 'dist' / name
        if not (bundle / (name + '.exe')).is_file():
            raise ValueError(f'Missing executable: {name}')
        for source in bundle.iterdir():
            destination = release / source.name
            if destination.exists():
                raise ValueError(f'Executable bundle collision: {destination}')
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
    (release / 'config').mkdir()
    for name in ('default.config', 'components.json', 'dependencies.lock.json'):
        shutil.copy2(root / 'config' / name, release / 'config' / name)
    (release / 'config/config.json').write_text('{}\n', encoding='utf-8')
    (release / 'scripts').mkdir()
    for source in (root / 'scripts').glob('*.ps1'):
        shutil.copy2(source, release / 'scripts' / source.name)
    shutil.copytree(root / 'examples', release / 'examples', ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('README.md', 'LICENSE'):
        shutil.copy2(root / name, release / name)
    shutil.copy2(build / 'build-environment.txt', release / 'build-environment.txt')
    for gate in ('quality','source-checks'):
        shutil.copy2(build/gate/'report.json', release/(gate+'-report.json'))
    licenses = release / 'licenses'; licenses.mkdir()
    notices = ['DVP internal acceptance build. Not a production release.',
               'Inventory includes build tools as well as runtime dependencies.', '']
    for dist in sorted(distributions(), key=lambda d: d.metadata['Name'].lower()):
        name = dist.metadata['Name']
        notices.append(name + ' ' + dist.version)
        for entry in dist.files or []:
            if any(token in entry.name.lower() for token in ('license', 'copying', 'notice')):
                source = Path(str(dist.locate_file(entry)))
                if source.is_file():
                    folder = licenses / name; folder.mkdir(exist_ok=True)
                    shutil.copy2(source, folder / (str(len(list(folder.iterdir()))) + '-' + entry.name))
    shutil.copy2(Path(sys.base_prefix) / 'LICENSE.txt', licenses / 'Python-LICENSE.txt')
    (release / 'THIRD_PARTY_NOTICES.txt').write_text('\n'.join(notices)+'\n', encoding='utf-8')
    (release / 'build-provenance.json').write_text(json.dumps({
        'purpose': 'internal_windows_report_and_installer_acceptance', 'reference_commit': baseline,
        'source_state': 'Local modified source snapshot; reference commit is not an exact release revision',
        'source_files': expected, 'inputs_unchanged_during_build': True,
        'python_version': sys.version, 'platform': sys.platform}, indent=2), encoding='utf-8')
    if snapshot(root) != expected:
        raise ValueError('Source inputs changed while packaging')
    write_manifest(release, build_manifest(release,
        version='0.0.0-acceptance.' + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S'), source_commit=baseline))
    result = verify_release(release)
    if result['status'] != 'passed':
        raise ValueError('Packaged release verification failed: '+json.dumps(result))
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=ROOT / '.dvp-package-cache')
    parser.add_argument('--source-commit', required=True, help='Reference Git commit; local changes recorded separately')
    parser.add_argument('--package-only', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    validate_commit(args.source_commit)
    if sys.platform != 'win32':
        parser.error('Windows executables must be built and accepted on Windows')
    if sys.version_info < (3, 12):
        parser.error('Python 3.12 or newer is required')
    if args.package_only:
        print(package_release(ROOT, args.package_only, args.source_commit))
        return 0
    build = ROOT / 'build' / ('windows-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid4().hex[:6])
    build.mkdir(parents=True)
    print(f'Build directory: {build}', flush=True)
    report = {'status': 'error', 'build_directory': str(build), 'build_status':'error', 'acceptance_status':'not_started', 'atomic_tests_executed': 0}
    try:
        (build / 'source-inputs.json').write_text(json.dumps(snapshot(ROOT), indent=2), encoding='utf-8')
        run_step([sys.executable, '-m', 'venv', build / 'venv'], build / '01-venv.log', ROOT)
        python = build / 'venv/Scripts/python.exe'
        run_step([python, '-m', 'pip', '--disable-pip-version-check', 'install', *PACKAGES, '-r', ROOT/'requirements-quality.txt'], build / '02-dependencies.log', ROOT)
        run_step([python, '-m', 'pip', 'check'], build / '03-pip-check.log', ROOT)
        run_step([python, '-m', 'pip', 'freeze'], build / 'build-environment.txt', ROOT)
        run_step([python, '-B', ROOT/'scripts/check_quality.py', '--output-dir', build/'quality'],
                 build/'04-quality.log', ROOT)
        run_step([python, '-B', ROOT/'scripts/check_setup_stage.py', '--source-only', '--output-dir', build/'source-checks'],
                 build/'05-source-checks.log', ROOT)
        for name, entry, libraries in [('dvp', 'main.py', '_internal-app'), ('dvp-setup', 'dvp_setup.py', '_internal-setup')]:
            run_step([python, '-m', 'PyInstaller', '--onedir', '--console', '--noupx', '--name', name,
                '--contents-directory', libraries, '--distpath', build/'dist', '--workpath', build/'work',
                '--specpath', build, ROOT/entry], build/(name+'-build.log'), ROOT)
            run_step([build/'dist'/name/(name+'.exe'), '--help'], build/(name+'-help.log'), ROOT, timeout=60)
        run_step([python, '-B', Path(__file__), '--source-commit', args.source_commit, '--package-only', build],
                 build/'package.log', ROOT)
        release = build/'release'
        report.update(build_status='passed',release_dir=str(release))
        code = run_step([python, '-u', '-B', ROOT/'scripts/check_setup_stage.py', '--cache', args.cache.resolve(),
                 '--release-dir', release, '--portable', '--output-dir', build/'acceptance'],
                 build/'acceptance.log', ROOT, timeout=3600, allowed=(0, 1, 2, 3, 130))
        acceptance = json.loads((build/'acceptance/report.json').read_text(encoding='utf-8'))
        expected_codes = STATUS_CODES
        if expected_codes.get(acceptance['status']) != code:
            raise ValueError('Acceptance status and exit code disagree')
        report.update(status=acceptance['status'], acceptance_status=acceptance['status'], limitations=acceptance.get('limitations',[]), acceptance_report=str(build/'acceptance/report.json'), release_dir=str(release))
    except KeyboardInterrupt:
        report.update(status='interrupted', reason='Build interrupted; partial artifacts and logs retained')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report.update(status='error', error_type=type(exc).__name__, reason=str(exc))
    path = build/'build-report.json'
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f'Build report: {path}')
    return status_code(report['status'])


if __name__ == '__main__':
    raise SystemExit(run_cli(main))
