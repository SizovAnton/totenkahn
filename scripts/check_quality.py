
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.cli_result import run_cli, status_code
from handlers.component_inventory import utc_now

PYRIGHT_VERSION = '1.1.414'
SOURCE_DIRS = ('handlers', 'reporting', 'displaying', 'rule_condition', 'scripts')

def python_sources(root):
    paths = list(root.glob('*.py'))

    for folder in SOURCE_DIRS:
        paths.extend((p for p in (root / folder).rglob('*.py') if '__pycache__' not in p.parts))

    return sorted(paths)

def validate_type_report(report, exit_code, expected_files):
    summary = report.get('summary', {})

    if report.get('version') != PYRIGHT_VERSION:
        raise ValueError('Unexpected Pyright version; install requirements-quality.txt')

    if (
        (type(summary.get('filesAnalyzed')) is not int)
        or (summary['filesAnalyzed'] != expected_files)
    ):
        raise ValueError('Static analysis did not cover all Python source files')

    if (
        (exit_code != 0)
        or (summary.get('errorCount') != 0)
        or (summary.get('warningCount') != 0)
        or (report.get('generalDiagnostics') != [])
    ):
        raise ValueError('Static analysis failed; inspect the saved diagnostics')
PS_PARSER = '''
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$files=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($filesBase64)))
$results=@(foreach($file in $files) {
 $tokensFound=$null; $errorsFound=$null
 $null=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokensFound,[ref]$errorsFound)
 @{file=$file;errors=@($errorsFound|ForEach-Object {@{line=$_.Extent.StartLineNumber;message=$_.Message}})}
})
[Console]::Out.WriteLine((@{files=$results}|ConvertTo-Json -Depth 6 -Compress))
'''

def validate_ps_report(report, expected_files, exit_code):
    files = report.get('files')

    if exit_code or not isinstance(files, list) or len(files) != len(expected_files):
        raise ValueError('PowerShell syntax analysis did not complete')

    if (
        ({p.get('file') for p in files} != set(expected_files))
        or any((p.get('errors') != [] for p in files))
    ):
        raise ValueError('PowerShell syntax errors or unexpected file coverage')

def check_quality(root, output, *, runner=subprocess.run):
    root = Path(root).resolve()
    output = Path(output)
    report = {
        'status': 'error',
        'checked_at': utc_now(),
        'scope': 'static_source_quality',
        'atomic_tests_executed': 0,
        'host_changes_performed': False,
        'checks': {},
        'python': sys.version,
    }
    sources = python_sources(root)

    if not sources:
        raise ValueError('No Python sources to check')

    inputs = sources + sorted((root / 'scripts').glob('*.ps1')) + [root / 'pyrightconfig.json', root / 'requirements-quality.txt']

    def fingerprints():
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    report['source_files'] = fingerprints()

    try:
        for platform in ('Linux', 'Windows'):
            completed = runner(
                [
                    sys.executable,
                    '-m',
                    'pyright',
                    '--project',
                    str(root / 'pyrightconfig.json'),
                    '--pythonpath',
                    sys.executable,
                    '--pythonplatform',
                    platform,
                    '--warnings',
                    '--outputjson',
                ],
                cwd=root,
                capture_output=True,
                timeout=180,
                check=False,
            )
            (output / f'pyright-{platform}.json').write_bytes(completed.stdout)
            (output / f'pyright-{platform}.stderr.txt').write_bytes(completed.stderr)
            data = json.loads(completed.stdout.decode('utf-8-sig'))
            validate_type_report(data, completed.returncode, len(sources))
            report['checks'][platform] = {'status': 'passed', **data['summary'], 'pyright_version': data['version']}

        powershell = shutil.which('pwsh') or shutil.which('powershell.exe')

        if powershell is None:
            raise ValueError('PowerShell is required to validate release scripts without executing them')

        files = [str(p) for p in sorted((root / 'scripts').glob('*.ps1'))]

        if not files:
            raise ValueError('No PowerShell release scripts to check')

        encoded = base64.b64encode(json.dumps(files).encode()).decode()
        script = "$filesBase64='" + encoded + "'\n" + PS_PARSER
        command = base64.b64encode(script.encode('utf-16le')).decode()
        completed = runner(
            [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', command],
            cwd=root,
            capture_output=True,
            timeout=60,
            check=False,
        )
        (output / 'powershell-syntax.json').write_bytes(completed.stdout)
        (output / 'powershell-syntax.stderr.txt').write_bytes(completed.stderr)
        data = json.loads(completed.stdout.decode('utf-8-sig'))
        validate_ps_report(data, files, completed.returncode)
        report['checks']['powershell'] = {'status': 'passed', 'files': len(files), 'scope': 'parse_only_no_script_execution'}

        if fingerprints() != report['source_files']:
            raise ValueError('Quality inputs changed during verification')

        report['status'] = 'passed'
    except KeyboardInterrupt:
        report.update(status='interrupted', reason='Static checks interrupted')
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        report.update(status='error', error_type=type(exc).__name__, reason=str(exc))

    (output / 'report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding='utf-8',
    )

    return report

def main():
    parser = argparse.ArgumentParser(description='Статичний release gate: всі Python-модулі (Linux/Windows) і синтаксис PowerShell.')
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    output = args.output_dir or Path(tempfile.mkdtemp(prefix='totenkahn-quality-'))

    if args.output_dir:
        output.mkdir(parents=True, exist_ok=False)

    report = check_quality(ROOT, output)
    print(
        json.dumps(
            {
                'status': report['status'],
                'checks': report['checks'],
                'report': str(output / 'report.json'),
                'reason': report.get('reason'),
            },
            indent=2,
        ),
    )

    return status_code(report['status'])

if __name__ == '__main__':
    raise SystemExit(run_cli(main))
