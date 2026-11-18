import argparse
from datetime import datetime, timezone
# from os import error
import sys
import subprocess
from pathlib import Path
import json
from copy import deepcopy
from rich.console import Group, RenderableType
from displaying.console import (
    configure_standard_streams,
    create_console,
    show_startup_banner,
)
from rich.table import Table
from rich.text import Text
from handlers.ci import dispatch as dispatch_ci
from handlers.dependency_cli import dispatch, ensure_ready, CODES
from handlers.cli_result import run_cli, status_code
from handlers.runtime_paths import runtime_config
from handlers.telemetry_cli import dispatch as dispatch_telemetry
from handlers.telemetry import requirements as telemetry_requirements, TelemetryNotReady
from handlers.atomic_lifecycle import (
    build_plan,
    public_plan,
    parse_inputs,
    LifecycleError,
    ResourcesNotReady,
    detection_outcome,
    save_lifecycle_report,
)
from handlers.dependency_cli import confirm
from reporting.atomic_view import lifecycle_summary
from reporting.explanation import regression_terminal_explanations
from displaying.reviw import build_event_review_view, build_atomic_runs_view
from displaying.table import build_report_metadata_view
from displaying.detection_graph import build_detection_graph
from handlers.correlation import correlate_processes, link_atomic_runs
from handlers.detection_context import build_detection_context
from handlers.events import process_events, config_handler
from handlers.file_handlers import load_csv_file, load_sigma_rule, load_xml_file, load_session_metadata, load_manual_test_context, load_test_case
# from handlers.file_handlers import load_configuration
from handlers.matching import report_handler, validate_rule, validate_live_logsource
from reporting.report import (
    build_rule_report,
    save_report_json,
    summarize_channels,
    evaluate_manual_expectation,
    evaluate_test_case,
    resolve_test_evidence,
)
from reporting.html_report import save_report_html
from scripts.check_live_run import run_live_session
from reporting.regression import run_regression, save_regression_report

def main():
    configure_standard_streams()
    show_startup_banner(sys.argv[1:])

    if getattr(sys, 'frozen', False):
        project_dir = Path(sys.executable).resolve().parent
    else:
        project_dir = Path(__file__).resolve().parent

    ci_result = dispatch_ci(sys.argv[1:])

    if ci_result is not None:
        raise SystemExit(ci_result)

    management = dispatch_telemetry(project_dir, sys.argv[1:])

    if management is None:
        management = dispatch(project_dir, sys.argv[1:])

    if management is not None:
        raise SystemExit(management)

    parser = argparse.ArgumentParser(
        description='Read Sigma rule yaml file',
        epilog='CI: ci --config CONFIG --output-dir NEW_DIR; Management: dependencies plan/status/prepare/remove; telemetry plan/check/prepare/restore --rule RULE; reports --open',
    )
    source_group = parser.add_mutually_exclusive_group()
    parser.add_argument(
        '--rule',
        type=Path,
        help='Path to Sigma YAML; required outside regression mode',
    )
    source_group.add_argument(
        '--session',
        type=Path,
        help='Path to a saved session directory',
    )
    source_group.add_argument(
        '--auto',
        action='store_true',
        help='Run auto test and evaluate collected events',
    )
    parser.add_argument(
        '--execution-log',
        type=Path,
        help='Override the execution log path for a saved session',
    )
    parser.add_argument(
        '--show-correlation',
        action='store_true',
        help='Show detailed correlation information',
    )
    parser.add_argument(
        '--atomic-test',
        nargs=2,
        metavar=('TECHNIQUE', 'TEST_NUMBER'),
        help='Specify the Atomic Red Team technique and test number to run',
    )
    source_group.add_argument(
        '--manual',
        action='store_true',
        help='Collect Windows events until Enter and evaluate the rule',
    )
    parser.add_argument(
        '--test-context',
        type=Path,
        help='Path to manual test context JSON; requires --manual',
    )
    parser.add_argument(
        '--test-case',
        type=Path,
        help='Path to a test case JSON; requires --session',
    )
    source_group.add_argument(
        '--regression-suite',
        type=Path,
        help='Compare two rules on a saved regression suite; no live collection',
    )
    parser.add_argument(
        '--baseline-rule',
        type=Path,
        help='Baseline Sigma YAML for regression',
    )
    parser.add_argument(
        '--candidate-rule',
        type=Path,
        help='Candidate Sigma YAML for regression',
    )
    parser.add_argument('--output-dir', type=Path, help='Regression report directory')
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Approve first-run base dependency preparation',
    )
    parser.add_argument(
        '--offline',
        action='store_true',
        help='Use cached packages during first-run preparation',
    )
    parser.add_argument(
        '--skip-dependencies',
        action='store_true',
        help='Explicitly bypass setup for saved-data replay/regression only',
    )
    parser.add_argument(
        '--input',
        action='append',
        default=[],
        metavar='NAME=VALUE',
        help='Selected Atomic input; repeat for multiple values',
    )
    parser.add_argument(
        '--atomic-timeout',
        type=int,
        default=120,
        help='Maximum seconds for each Atomic command',
    )
    parser.add_argument(
        '--atomic-plan',
        action='store_true',
        help='Show selected test plan without executing definition code',
    )
    parser.add_argument(
        '--prepare-prereqs',
        action='store_true',
        help='Allow preparation of missing prerequisites for the selected test',
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Run the selected definition cleanup after collection stops',
    )
    parser.add_argument(
        '--approve-atomic',
        action='store_true',
        help='Approve the displayed Atomic plan without an interactive prompt',
    )
    args = parser.parse_args()

    if (
        (
            args.input
            or args.atomic_plan
            or args.prepare_prereqs
            or args.cleanup
            or args.approve_atomic
            or (args.atomic_timeout != 120)
        )
        and (not args.auto)
    ):
        parser.error('Atomic lifecycle options require --auto')

    if args.atomic_plan:
        if not args.atomic_test:
            parser.error('--atomic-plan requires --atomic-test TECHNIQUE NUMBER')

        try:
            plan = build_plan(
                runtime_config(project_dir),
                args.atomic_test[0],
                int(args.atomic_test[1]),
                inputs=parse_inputs(args.input),
                timeout=args.atomic_timeout,
                cleanup=args.cleanup,
                prepare=args.prepare_prereqs,
            )
        except ResourcesNotReady as exc:
            print(
                json.dumps({'status': 'blocked', 'stage': 'atomic_resources', 'reason': str(exc)}),
            )
            raise SystemExit(1)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            parser.error(str(exc))

        print(json.dumps(public_plan(plan), ensure_ascii=False, indent=2))

        return

    if args.skip_dependencies and (not (args.session or args.regression_suite)):
        parser.error(
            '--skip-dependencies requires replay or regression; it is not available for live modes',
        )

    if sys.platform == 'win32' and (not args.skip_dependencies):
        try:
            readiness = ensure_ready(project_dir, yes=args.yes, offline=args.offline)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.TimeoutExpired) as exc:
            readiness = {'status': 'error', 'reason': str(exc)}

        if readiness['status'] != 'passed':
            print(json.dumps(readiness, ensure_ascii=False, indent=2))

            if args.auto or not (args.session or args.regression_suite or args.manual):
                raise SystemExit(CODES.get(readiness['status'], 2))

            print(
                'Atomic dependencies are unavailable; continuing the independent requested mode.',
                file=sys.stderr,
            )

    if len(sys.argv) == 1 or set(sys.argv[1:]) <= {'--yes', '--offline'}:
        parser.print_help()
        print(
            'Base preparation does not execute Atomic tests. Use doctor to inspect live readiness.',
        )

        return

    if args.regression_suite is not None:
        if (
            (args.rule is not None)
            or (args.test_case is not None)
            or (args.test_context is not None)
            or (args.execution_log is not None)
            or (args.atomic_test is not None)
            or args.show_correlation
        ):
            parser.error('Regression mode cannot be combined with single-run options')

        if args.baseline_rule is None or args.candidate_rule is None:
            parser.error('--regression-suite requires --baseline-rule and --candidate-rule')

        try:
            regression = run_regression(args.regression_suite, args.baseline_rule, args.candidate_rule)

            if args.output_dir is not None:
                output_dir = args.output_dir
            else:
                config = runtime_config(project_dir, use_dependencies=not args.skip_dependencies)
                output_dir = project_dir / config['paths']['reports_dir']

            json_path, html_path = save_regression_report(regression, output_dir)
        except (OSError, ValueError) as error:
            parser.error(f'Cannot run regression: {error}')

        console = create_console()
        console.print('Regression summary: ' + json.dumps(regression['summary']), markup=False)
        comparison_table = Table(title='Regression cases')

        for heading in ('Case', 'Baseline', 'Candidate', 'Comparison', 'Selected / outside changes'):
            comparison_table.add_column(heading, overflow='fold')

        for case in regression['cases']:
            selected = sum((change['selected'] for change in case['changed_events']))
            outside = len(case['changed_events']) - selected
            comparison_table.add_row(
                Text(case['case_id']),
                Text(case['baseline']['status']),
                Text(case['candidate']['status']),
                Text(case['comparison']),
                f'{selected} / {outside}',
            )

        for session_id, session in regression['sessions'].items():
            console.print(Text(f'Session: {session_id}', style='bold'))
            console.print(build_detection_graph(session.get('detection_context')))
            console.print(regression_terminal_explanations(session))

        console.print(comparison_table)
        console.print(f'JSON report saved: {json_path}', markup=False)
        console.print(f'HTML report saved: {html_path}', markup=False)

        return regression

    if any(
        (value is not None for value in (args.baseline_rule, args.candidate_rule, args.output_dir)),
    ):
        parser.error(
            '--baseline-rule, --candidate-rule and --output-dir require --regression-suite',
        )

    if args.rule is None:
        parser.error('--rule is required outside regression mode')

    manual_session = args.manual

    if args.test_case is not None and args.session is None:
        parser.error('--test-case requires --session')

    test_case = None

    if args.test_case is not None:
        try:
            test_case = load_test_case(args.test_case)
        except (OSError, ValueError) as error:
            parser.error(f'Cannot load test case: {error}')

    if args.test_context is not None and (not args.manual):
        parser.error('--test-context requires --manual')

    if args.atomic_test is not None and (not args.auto):
        parser.error('--atomic-test requires --auto')

    if args.execution_log is not None and args.session is None:
        parser.error('--execution-log requires --session')

    technique = None
    test_number = None

    if args.auto:
        if args.atomic_test is None:
            parser.error('--auto requires --atomic-test TECHNIQUE TEST_NUMBER')

        technique, raw_test_number = args.atomic_test
        technique = technique.strip().upper()

        try:
            test_number = int(raw_test_number)
        except ValueError:
            parser.error(f'Invalid test number: {raw_test_number}')

        if not 1 <= test_number <= 2147483647:
            parser.error(f'Test number must be between 1 and 2147483647: {test_number}')

    if not args.rule.is_file():
        parser.error(f'Sigma rule file not found: {args.rule}')

    session_metadata = None
    scenario = None
    correlation = None
    at_run = None
    live_session = None
    host_requirements = None
    linked_runs = []

    if args.session is not None:
        if not args.session.is_dir():
            parser.error(f'Session directory not found: {args.session}')

        try:
            session_metadata = load_session_metadata(args.session)
        except (OSError, ValueError) as metadata_error:
            parser.error(f'Cannot replay session: {metadata_error}')

        if session_metadata is None:
            print(
                'Warning: legacy session without session.json; replay uses current source profiles.',
                file=sys.stderr,
            )

        events_path = args.session / 'events.json'

        if not events_path.is_file():
            parser.error(f'Session events file not found: {events_path}')

    sigma_rule, rule_snapshot = load_sigma_rule(args.rule, with_snapshot=True)

    try:
        validate_rule(sigma_rule)
    except ValueError as e:
        parser.error(f'Unsupported or invalid Sigma rule: {e}')

    test_context = None

    if args.test_context is not None:
        try:
            test_context = load_manual_test_context(args.test_context)
        except (OSError, ValueError) as context_error:
            parser.error(f'Invalid manual test context: {context_error}')

        test_context['expectation']['rule_sha256'] = rule_snapshot['sha256']

    configuration = runtime_config(project_dir, use_dependencies=not args.skip_dependencies)

    if args.auto or args.manual:
        try:
            validate_live_logsource(sigma_rule, configuration)
            host_requirements = telemetry_requirements(sigma_rule, configuration)
        except ValueError as e:
            parser.error(f'Unsupported live logsource: {e}')

    if args.session is not None:
        events_path = args.session / 'events.json'

        with events_path.open('r', encoding='utf-8') as file:
            events = json.load(file)

        if not isinstance(events, list):
            parser.error('Session events must be a JSON array')

        seen_record_ids = set()

        for number, event in enumerate(events, start=1):
            if not isinstance(event, dict):
                parser.error(f'Session event #{number} must be a JSON object')

            record_id = event.get('record_id')

            if not isinstance(record_id, str) or not record_id.strip():
                parser.error(f'Session event #{number} must include a non-empty record_id')

            if record_id in seen_record_ids:
                parser.error(f'Session event #{number} has duplicate record_id: {record_id!r}')

            seen_record_ids.add(record_id)

            if session_metadata is None:
                event['source'] = config_handler(event['channel'], event['provider'], configuration, event['event_id'])
            else:
                source = event.get('source')

                if not isinstance(source, dict) or not source:
                    parser.error(f'Session event #{number} must include a non-empty saved source object')

                for field in ('channel', 'provider', 'event_id'):
                    value = event.get(field)

                    if not isinstance(value, str) or not value.strip():
                        parser.error(f'Session event #{number}: {field} must be a non-empty string')

                expected_source = config_handler(
                    event['channel'],
                    event['provider'],
                    session_metadata['profiles_snapshot'],
                    event['event_id'],
                )

                if source != expected_source:
                    parser.error(f'Session event #{number}: saved source does not match profiles_snapshot')

        scenario_path = args.session / 'scenario.json'

        if not scenario_path.is_file():
            parser.error(f'Session scenario file not found: {scenario_path}')

        with scenario_path.open('r', encoding='utf-8') as file:
            scenario = json.load(file)

        if not isinstance(scenario, dict):
            parser.error('Session scenario must be a JSON object')

        session_mode = scenario.get('mode', 'auto')

        if session_mode not in ('auto', 'manual'):
            parser.error(f'Unsupported session mode: {session_mode!r}')

        if session_metadata is not None:
            metadata_mode = session_metadata['mode']

            if session_mode != metadata_mode:
                parser.error(
                    f'Session mode mismatch: session.json={metadata_mode!r}, scenario.json={session_mode!r}',
                )

        manual_session = session_mode == 'manual'

        if manual_session:
            if args.execution_log is not None:
                parser.error('--execution-log is not applicable to a manual session')

            if scenario.get('status') != 'succeeded':
                parser.error('Manual session collection was not completed successfully')

            linked_runs = []
        else:
            if args.execution_log is not None:
                execution_log_path = args.execution_log
            else:
                execution_log_path = Path(scenario['execution_log'])
                execution_log_base = scenario.get('execution_log_base')

                if execution_log_base == 'session':
                    if execution_log_path.is_absolute() or '..' in execution_log_path.parts:
                        parser.error("Session execution_log must be a relative path without '..'")

                    execution_log_path = args.session / execution_log_path
                elif execution_log_base is not None:
                    parser.error(f'Unsupported execution_log_base: {execution_log_base!r}')

            if not execution_log_path.is_file():
                parser.error(
                    f'Execution log not found: {execution_log_path}. Use --execution-log to specify its current location.',
                )

            execution_rows = load_csv_file(execution_log_path)
            matching_runs = []

            for row in execution_rows:
                same_technique = row.get('Technique') == scenario['technique']
                same_test = row.get('GUID') == scenario['test_guid']

                if same_technique and same_test:
                    matching_runs.append(row)

            if len(matching_runs) != 1:
                parser.error(f'Expected one matching execution record; found {len(matching_runs)}')

            at_run = matching_runs[0]
            correlation = correlate_processes(at_run, events)
    elif args.manual:
        try:
            live_session = run_live_session(
                manual=True,
                test_context=test_context,
                host_requirements=host_requirements,
            )
        except TelemetryNotReady as exc:
            print(
                json.dumps(
                    {'status': 'blocked', 'stage': 'telemetry_preflight', 'telemetry': exc.report},
                    ensure_ascii=False,
                    indent=2,
                ),
            )
            raise SystemExit(1)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({'status': 'error', 'stage': 'live_collection', 'reason': str(exc)}))
            raise SystemExit(2)

        session_metadata = live_session['session_metadata']
        events = live_session['events']
        scenario = live_session['scenario']
        linked_runs = []
        print(f"Session saved: {live_session['session_dir']}")
    elif args.auto:
        try:
            plan = build_plan(
                configuration,
                technique,
                test_number,
                inputs=parse_inputs(args.input),
                timeout=args.atomic_timeout,
                cleanup=args.cleanup,
                prepare=args.prepare_prereqs,
            )
            print(json.dumps(public_plan(plan), ensure_ascii=False, indent=2))

            if not confirm(
                'Execute prerequisite checks and the selected Atomic plan?',
                args.approve_atomic,
            ):
                print('Atomic execution cancelled. No test commands were executed.')
                raise SystemExit(1)

            live_session = run_live_session(
                technique,
                test_number,
                atomic_plan=plan,
                approved=True,
                host_requirements=host_requirements,
            )
        except TelemetryNotReady as exc:
            print(
                json.dumps(
                    {'status': 'blocked', 'stage': 'telemetry_preflight', 'telemetry': exc.report},
                    ensure_ascii=False,
                    indent=2,
                ),
            )
            raise SystemExit(1)
        except ResourcesNotReady as exc:
            print(
                json.dumps({'status': 'blocked', 'stage': 'atomic_resources', 'reason': str(exc)}),
            )
            raise SystemExit(1)
        except LifecycleError as exc:
            print(json.dumps(exc.report, ensure_ascii=False, indent=2))
            raise SystemExit(status_code(exc.report['status']))
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            print(json.dumps({'status': 'error', 'stage': 'atomic_lifecycle', 'reason': str(exc)}))
            raise SystemExit(2)

        session_metadata = live_session['session_metadata']
        events = live_session['events']
        scenario = live_session['scenario']
        at_run = live_session['atomic_run']
        correlation = live_session['correlation']
    else:
        raw_xml = load_xml_file(str(project_dir / configuration['events']['file_path']))
        events = process_events(raw_xml, configuration)
        atomic_log = load_csv_file(str(project_dir / configuration['atomic']['log_path']))
        linked_runs = link_atomic_runs(atomic_log, events, configuration['correlation'])

    if (args.session is not None or args.auto) and (not manual_session):
        if correlation is None or at_run is None or scenario is None:
            raise ValueError('Automatic session is missing its scenario or correlation result')

        correlation_status = correlation['correlation_status']
        root_candidates = correlation['root_candidates']
        root_evidence = correlation['root_evidence']
        process_candidates = correlation['process_candidates']
        process_evidence = correlation['process_evidence']

        if args.show_correlation:
            print('Correlation')
            print('Process links:', len(process_evidence))
            print('Correlation status:', correlation_status)
            print('Process candidates:', len(process_candidates))
            print('Root candidates:', len(root_candidates))
            print('Atomic test:', at_run['Test Name'])
            print('Run ID:', scenario['run_id'])
            print('Scenario status:', scenario['status'])

        linked_runs = [
            {
                'run_reference': scenario['run_id'],
                'atomic_run': at_run,
                'candidate_events': process_candidates,
                'root_candidate_ids': [event['record_id'] for event in root_candidates],
                'root_evidence': root_evidence,
                'process_evidence': process_evidence,
                'correlation_status': correlation_status,
                'correlation_issues': [],
            },
        ]

    if test_case is not None:
        try:
            resolve_test_evidence(test_case, session_metadata, events)
        except ValueError as error:
            parser.error(f'Cannot resolve test evidence: {error}')

    event_results = report_handler(events, sigma_rule)
    report = build_rule_report(sigma_rule, event_results, linked_runs)

    if test_case is not None:
        try:
            case_evaluation = evaluate_test_case(test_case, session_metadata, events, event_results)
        except ValueError as e:
            parser.error(f'Cannot evaluate test case: {e}')

        report['Test Case'] = deepcopy(test_case)
        case_evaluation['rule_sha256'] = rule_snapshot['sha256']
        report['Test Case Evaluation'] = case_evaluation

    if args.session is not None:
        analysis_mode = 'replay'
    elif args.manual or args.auto:
        analysis_mode = 'live'
    else:
        analysis_mode = 'file'

    if session_metadata is not None:
        analysis_session_id = session_metadata['session_id']
        profile_basis = 'saved_event_sources' if analysis_mode == 'replay' else 'live_profiles'
        analysis_profiles = deepcopy(session_metadata['profiles_snapshot'])
    else:
        analysis_session_id = scenario.get('session_id') if analysis_mode == 'replay' and scenario is not None else None
        profile_basis = 'legacy_current_config' if analysis_mode == 'replay' else 'file_current_config'
        analysis_profiles = deepcopy({'defaults': configuration['defaults'], 'sources': configuration['sources']})

    report['Analysis'] = {
        'schema_version': 1,
        'analysis_id': report['Report ID'],
        'session_id': analysis_session_id,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'status': 'completed',
        'mode': analysis_mode,
        'engine_version': 1,
        'build_id': None,
        'profile_basis': profile_basis,
        'profiles_snapshot': analysis_profiles,
    }
    report['Session Snapshot'] = deepcopy(session_metadata)
    report['Rule Snapshot'] = deepcopy(rule_snapshot)
    report['Event Evidence'] = {event['record_id']: deepcopy(event) for event in events}
    report['Detection Context'] = build_detection_context(
        events,
        {'rule': {result['Log Record ID']: result['Selection'] for result in event_results}},
    )

    if manual_session:
        if scenario is None:
            raise ValueError('Manual session is missing its scenario result')

        saved_test_context = scenario.get('test_context')

        if saved_test_context is not None and (not isinstance(saved_test_context, dict)):
            parser.error('Manual scenario test_context must be a JSON object or null')

        report['Manual Test Context'] = deepcopy(saved_test_context)
        collection_status = session_metadata['collection']['status'] if session_metadata is not None else None
        report['Expectation Evaluation'] = evaluate_manual_expectation(
            saved_test_context,
            report['Events Summary'],
            rule_sha256=rule_snapshot['sha256'],
            collection_status=collection_status,
        )
        report['Session'] = {
            'Session ID': scenario.get('session_id'),
            'Mode': 'manual',
            'Collection Status': collection_status if collection_status is not None else 'unknown',
            'Configured Channels': scenario.get('channels', []),
            'Events by Channel': summarize_channels(events, scenario.get('channels', [])),
            'Stop Reason': scenario.get('stop_reason'),
            'Analysis Mode': 'replay' if args.session is not None else 'live',
            'Ready Received At UTC': scenario.get('ready_received_at'),
            'Finished At UTC': scenario.get('finished_at'),
        }

    if (
        (args.auto or args.session)
        and (not manual_session)
        and (scenario is not None)
        and scenario.get('atomic_lifecycle')
    ):
        if correlation is None:
            raise ValueError('Atomic lifecycle report requires correlation data')

        report['Atomic Lifecycle'] = deepcopy(scenario['atomic_lifecycle'])
        report['Atomic Lifecycle']['detection'] = detection_outcome(
            correlation,
            event_results,
            session_metadata.get('collection', {}).get('status') if session_metadata else None,
        )

        if args.auto:
            if live_session is None:
                raise ValueError('Live session is missing its evidence directory')

            save_lifecycle_report(
                Path(live_session['session_dir']) / 'atomic',
                report['Atomic Lifecycle'],
            )
            scenario['atomic_lifecycle'] = report['Atomic Lifecycle']
            (Path(live_session['session_dir']) / 'scenario.json').write_text(
                json.dumps(scenario, ensure_ascii=False, indent=2),
                encoding='utf-8',
            )

    if session_metadata and session_metadata.get('telemetry_readiness'):
        report['Telemetry Readiness'] = deepcopy(session_metadata['telemetry_readiness'])

    reports_dir = project_dir / configuration['paths']['reports_dir']
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / f"{report['Report ID']}.json"
    save_report_json(report, output_path)
    html_output_path = output_path.with_suffix('.html')
    save_report_html(report, html_output_path)
    show_correlation = args.show_correlation and (not manual_session)
    metadata_view = build_report_metadata_view(report, show_correlation=show_correlation)
    evidence_view = build_event_review_view(report)
    views: list[RenderableType] = [metadata_view]

    if show_correlation:
        atomic_runs_view = build_atomic_runs_view(report, show_correlation=True)
        views.append(atomic_runs_view)

    graph_view = build_detection_graph(report.get('Detection Context'))
    views.append(graph_view)
    views.append(evidence_view)
    console = create_console()

    if report.get('Atomic Lifecycle'):
        summary, chain = lifecycle_summary(report['Atomic Lifecycle'])
        console.print(Text(summary))
        console.print(Text(chain))

    console.print(Group(*views))
    console.print(f'JSON report saved: {output_path}', markup=False)
    console.print(f'HTML report saved: {html_output_path}', markup=False)

    if args.auto and report.get('Atomic Lifecycle'):
        lifecycle = report['Atomic Lifecycle']

        if (
            (lifecycle['status'] != 'passed')
            or (lifecycle['detection']['status'] == 'insufficient_data')
        ):
            raise SystemExit(3)

    return report

if __name__ == '__main__':
    raise SystemExit(run_cli(main))
