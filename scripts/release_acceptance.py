"""Перевірки звітів саме встановленої програми на синтетичних даних."""
import json
import os
from pathlib import Path
import shutil
import subprocess
from html.parser import HTMLParser

from handlers.release_manifest import describe_file


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_html(path):
    class Classes(HTMLParser):
        def __init__(self):
            super().__init__()
            self.classes = set()
        def handle_starttag(self, tag, attrs):
            for key, value in attrs:
                if key == 'class' and value:
                    self.classes.update(value.split())
    parser = Classes()
    text = path.read_text(encoding='utf-8')
    parser.feed(text)
    require({'decision-explanation', 'decision-chain', 'recorded-evaluation'} <= parser.classes,
            f'New explanation UI is missing: {path}')
    return text


def report_fingerprints(directory):
    return {p.relative_to(directory).as_posix(): describe_file(p)
            for p in sorted(directory.rglob('*')) if p.is_file()}


def verify_preserved(directory, expected):
    for name, fingerprint in expected.items():
        path = directory / name
        require(path.is_file() and describe_file(path) == fingerprint,
                f'Generated evidence was removed or changed: {path}')


def validate_ordinary(data, html):
    require(data['Analysis']['mode'] == 'replay', 'Expected a replay report')
    require(data['Events Summary'] == {'Total Events': 3, 'Match': 1, 'Unmatch': 2, 'Skipped': 0},
            'Unexpected ordinary rule decisions')
    require(data['Test Case Evaluation']['status'] == 'met', 'Selected positive test expectation was not met')
    selected = {}
    for groups in data['Event Review'].values():
        for group in groups:
            for ref in group['References']:
                selected[ref['Log Record ID']] = group['Evidence']
    require(selected['positive']['Selection'] is True and selected['negative']['Selection'] is False
            and selected['insufficient']['Selection'] is False, 'Wrong per-event decisions')
    require(selected['negative']['Block Results'] == {'filter': True, 'selection': True},
            'NOT filter case did not exercise the intended branches')
    missing = selected['insufficient']['Checks']['selection']['CommandLine|contains']
    require(missing['Field Present'] is False and missing['Matched'] is False,
            'Missing field was not recorded distinctly')
    require('CommandLine is absent' in html and 'NOT:' in html and 'AND(' in html,
            'Missing field / logical explanation text is absent')


def validate_regression(data, html):
    require({c['case_id']: c['comparison'] for c in data['cases']} == {
        'positive': 'improved', 'negative': 'regressed', 'insufficient': 'insufficient_data'},
        'Regression expectations changed unexpectedly')
    require('Baseline rule evaluation' in html and 'Candidate rule evaluation' in html,
            'Both rule explanations must be visible')


def run_application_reports(target, work, timeout, app_command=None, *, skip_dependencies=True, reports_directory=None):
    # app_command використовується лише локальним тестом вихідного коду.
    command = [*(app_command or [str(target / 'dvp.exe')]), *(['--skip-dependencies'] if skip_dependencies else [])]
    inputs = work / 'report-inputs'
    shutil.copytree(target / 'examples/regression', inputs)
    session = inputs / 'session'
    events = json.loads((session / 'events.json').read_text(encoding='utf-8'))
    for event in events:
        if event['record_id'] != 'insufficient':
            event['data_fields']['CommandLine'] = 'example.exe --acceptance'
    (session / 'events.json').write_text(json.dumps(events), encoding='utf-8')
    (session / 'scenario.json').write_text(json.dumps({
        'mode': 'manual', 'status': 'succeeded', 'session_id': 'synthetic-regression-demo',
        'test_context': None, 'origin': 'synthetic_acceptance_fixture'}), encoding='utf-8')
    rule = {'title': 'Synthetic executable acceptance', 'id': 'acceptance-explanation',
            'logsource': {'product': 'windows', 'service': 'dvp-demo'},
            'detection': {'selection': {'CommandLine|contains': '--acceptance'},
                          'filter': {'marker': 'benign'}, 'condition': 'selection and not filter'}}
    rule_path = inputs / 'acceptance-rule.json'
    rule_path.write_text(json.dumps(rule), encoding='utf-8')
    reports = Path(reports_directory) if reports_directory else target / 'reports'
    before = set(reports.glob('*.json'))
    artifact_dir = work / 'application-reports'
    artifact_dir.mkdir()

    def run(name, arguments):
        print(f'Checking installed application: {name}', flush=True)
        stdout, stderr = work / (name+'.stdout.txt'), work / (name+'.stderr.txt')
        env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUTF8='1')
        with stdout.open('wb') as out, stderr.open('wb') as err:
            completed = subprocess.run([*command, *arguments], cwd=work, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout, check=False)
        require(completed.returncode == 0, f'{name} exited {completed.returncode}; see {stderr}')
        text = ' '.join(stdout.read_text(encoding='utf-8', errors='replace').split())
        require('Event decision:' in text, f'{name}: CLI explanation is missing')
        return {'exit_code': completed.returncode, 'stdout': str(stdout), 'stderr': str(stderr)}

    ordinary = run('ordinary-replay', ['--rule', str(rule_path), '--session', str(session),
                                     '--test-case', str(inputs / 'positive.json')])
    created = set(reports.glob('*.json')) - before
    require(len(created) == 1, 'Expected exactly one ordinary JSON report')
    ordinary_json = created.pop()
    ordinary_html = ordinary_json.with_suffix('.html')
    validate_ordinary(json.loads(ordinary_json.read_text(encoding='utf-8')), validate_html(ordinary_html))
    shutil.copy2(ordinary_json, artifact_dir / 'ordinary.json')
    shutil.copy2(ordinary_html, artifact_dir / 'ordinary.html')
    regression = run('regression-replay', ['--regression-suite', str(inputs / 'suite.json'),
        '--baseline-rule', str(inputs / 'baseline.yaml'), '--candidate-rule', str(inputs / 'candidate.yaml'),
        '--output-dir', str(reports / 'acceptance-regression')])
    generated = list((reports / 'acceptance-regression').glob('regression-*/report.json'))
    require(len(generated) == 1, 'Expected exactly one regression report')
    reg_json = generated[0]
    reg_html = reg_json.with_suffix('.html')
    validate_regression(json.loads(reg_json.read_text(encoding='utf-8')), validate_html(reg_html))
    shutil.copy2(reg_json, artifact_dir / 'regression.json')
    shutil.copy2(reg_html, artifact_dir / 'regression.html')
    return {'status': 'passed', 'ordinary': ordinary, 'regression': regression,
            'artifacts': str(artifact_dir), 'report_fingerprints': report_fingerprints(reports),
            'scope': 'synthetic_replay_reports_from_installed_executable'}
