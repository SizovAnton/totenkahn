"""Збої, переривання та gates на інертних даних; без Windows/Atomic змін."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).parent))
from handlers.cli_result import run_cli, status_code
from handlers import process_control
from handlers.atomic_lifecycle import AtomicLifecycle, LifecycleError
from scripts import check_live_run as live
from check_atomic_lifecycle import AtomicLifecycleTests
from check_quality import validate_type_report, validate_ps_report
from check_release_acceptance import AcceptanceTests
from build_windows_acceptance import package_release, run_step


class StabilityTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='dvp-stability-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def atomic_fixture(self):
        case=AtomicLifecycleTests();case.setUp();self.addCleanup(case.doCleanups)
        return case

    def test_missing_override_uses_default_configuration(self):
        from handlers.file_handlers import load_configuration
        config=load_configuration(ROOT/'config/default.config',self.root/'absent.json')
        self.assertEqual(config,json.loads((ROOT/'config/default.config').read_text()))

    def test_invalid_override_is_not_ignored(self):
        from handlers.file_handlers import load_configuration
        path=self.root/'invalid-config.json';path.write_text('{invalid')
        with self.assertRaises(ValueError):load_configuration(ROOT/'config/default.config',path)

    def test_missing_default_is_not_ignored(self):
        from handlers.file_handlers import load_configuration
        with self.assertRaises(FileNotFoundError):load_configuration(self.root/'absent-default',self.root/'absent-override')

    def test_cli_interrupt_has_distinct_code_and_json(self):
        def entry():raise KeyboardInterrupt()
        output=io.StringIO()
        with redirect_stdout(output):code=run_cli(entry)
        self.assertEqual(code,130);self.assertEqual(json.loads(output.getvalue())['status'],'interrupted')

    def test_cli_failure_never_returns_success(self):
        output=io.StringIO()
        with redirect_stdout(output):
            code=run_cli(lambda: (_ for _ in ()).throw(OSError('disk fixture')))
        self.assertEqual(code,2);self.assertEqual(json.loads(output.getvalue())['error_type'],'OSError')
        self.assertEqual(run_cli(lambda:{'status':'unexpected'}),2)
        self.assertEqual(status_code('failed'),2)
        self.assertEqual(run_cli(lambda:{'status':'completed'}),0)

    def test_explicit_cli_exit_is_preserved(self):
        def entry():raise SystemExit(3)
        with self.assertRaises(SystemExit) as result:run_cli(entry)
        self.assertEqual(result.exception.code,3)

    def test_failed_json_write_preserves_previous_evidence(self):
        path=self.root/'session.json';path.write_text('{"original":true}')
        with self.assertRaises(ValueError):live.write_session_json(path,{'value':float('nan')})
        self.assertEqual(json.loads(path.read_text()),{'original':True})

    def test_partial_artifacts_attempt_both_files(self):
        original=live.write_session_json
        def writer(path,value):
            if path.name=='events.json':raise OSError('events disk fixture')
            return original(path,value)
        with patch.object(live,'write_session_json',side_effect=writer):
            with self.assertRaises(OSError):live.save_session_files(self.root,[],{'status':'incomplete'})
        self.assertEqual(json.loads((self.root/'scenario.json').read_text())['status'],'incomplete')

    def test_evidence_failure_does_not_mask_execution_failure(self):
        case=self.atomic_fixture()
        with patch.object(live,'save_session_files',side_effect=OSError('disk fixture')):
            with self.assertRaises(LifecycleError) as failed:case.live_fixture(execution='failed')
        self.assertEqual(failed.exception.report['execution']['status'],'failed')
        session=next((case.root/'runs').iterdir())
        metadata=json.loads((session/'session.json').read_text())
        self.assertEqual(metadata['collection']['status'],'incomplete')
        self.assertTrue(any(e.get('stage')=='saving_partial_evidence' for e in metadata['collection']['errors']))
        self.assertEqual(failed.exception.report['cleanup']['status'],'passed')

    def test_keyboard_interrupt_persists_incomplete_session(self):
        case=self.atomic_fixture()
        with patch.object(AtomicLifecycle,'execute',side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):case.live_fixture()
        session=next((case.root/'runs').iterdir())
        self.assertEqual(json.loads((session/'session.json').read_text())['collection']['stop_reason'],'interrupt')
        self.assertEqual(json.loads((session/'scenario.json').read_text())['status'],'incomplete')
        self.assertEqual(json.loads((session/'atomic/lifecycle.json').read_text())['cleanup']['status'],'not_started')

    def test_cleanup_write_failure_does_not_mask_primary_failure(self):
        case=self.atomic_fixture()
        with patch.object(AtomicLifecycle,'cleanup',side_effect=OSError('cleanup disk fixture')):
            with self.assertRaises(LifecycleError) as failed:case.live_fixture(execution='failed')
        self.assertEqual(failed.exception.report['execution']['status'],'failed')
        self.assertEqual(failed.exception.report['cleanup']['status'],'error')

    def test_failure_journal_error_preserves_keyboard_interrupt(self):
        case=self.atomic_fixture();life=case.lifecycle(['passed']);life.prepare()
        def interrupted(*args):raise KeyboardInterrupt()
        life.runner=interrupted
        # execution start і pending step пишуться; тільки failure journal відмовляє.
        real_save=life.save;writes=0
        def save():
            nonlocal writes
            writes+=1
            if writes>=3:raise OSError('journal fixture')
            real_save()
        with patch.object(life,'save',side_effect=save),redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):life.execute()
        self.assertEqual(life.report['execution']['status'],'interrupted')
        self.assertTrue(life.report['persistence_errors'])

    def test_installation_failure_save_does_not_mask_original(self):
        from handlers import installation
        with patch.object(installation,'save_state',side_effect=OSError('journal fixture')),redirect_stderr(io.StringIO()):
            error=installation.save_state_after_error(self.root,{})
        self.assertEqual(error,'journal fixture')

    def test_dependency_interrupt_survives_journal_failure(self):
        from check_dependencies import DependencyTests
        from handlers import dependencies,installation
        case=DependencyTests();case.setUp();self.addCleanup(case.doCleanups)
        real_save=installation.save_state
        def save(target,state):
            if state['status']=='interrupted':raise OSError('journal fixture')
            return real_save(target,state)
        with patch.object(dependencies,'obtain_package',side_effect=KeyboardInterrupt()), \
                patch.object(installation,'save_state',side_effect=save),redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):case.prepare()

    def test_telemetry_interrupt_survives_journal_failure(self):
        from check_telemetry import TelemetryTests
        from handlers import telemetry
        case=TelemetryTests();case.setUp();self.addCleanup(case.doCleanups)
        proposal=case.plan();real_save=telemetry.save_ledger
        def save(root,ledger):
            if any(op['state']=='interrupted' for op in ledger['operations']):raise OSError('journal fixture')
            return real_save(root,ledger)
        def backend(project,request):
            if request['action']=='set':raise KeyboardInterrupt()
            return case.backend(project,request)
        with patch.object(telemetry,'save_ledger',side_effect=save),redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                telemetry.prepare(ROOT,proposal,approved=True,root=case.root,probe=backend)

    def test_failed_execution_status_survives_failed_journal(self):
        case=self.atomic_fixture();life=case.lifecycle(['passed','failed']);life.prepare()
        real_save=life.save
        def save():
            if life.report['steps'][-1].get('status')=='failed':raise OSError('journal fixture')
            real_save()
        with patch.object(life,'save',side_effect=save),redirect_stderr(io.StringIO()):
            with self.assertRaises(LifecycleError) as failed:life.execute()
        self.assertEqual(failed.exception.report['execution']['status'],'failed')
        self.assertTrue(failed.exception.report['persistence_errors'])

    def test_collector_readiness_has_deadline_without_messages(self):
        collector=Mock(stdout=io.StringIO(''))
        with patch.object(live.time,'monotonic',side_effect=[0,61]):
            with self.assertRaises(TimeoutError):list(live.collector_lines(collector,lambda:False,timeout=120))

    def test_windows_termination_requests_tree_and_waits(self):
        process=Mock(pid=123);process.poll.return_value=None
        with patch.object(process_control.sys,'platform','win32'),patch.object(process_control.subprocess,'run') as run:
            process_control.terminate_process(process)
        self.assertEqual(run.call_args.args[0],['taskkill.exe','/PID','123','/T','/F'])
        process.kill.assert_called_once();process.wait.assert_called_once_with(timeout=15)

    def test_builder_timeout_stops_child_process(self):
        process=Mock();process.poll.return_value=None
        with patch('build_windows_acceptance.subprocess.Popen',return_value=process),\
             patch('build_windows_acceptance.time.monotonic',side_effect=[0,2]),\
             patch('build_windows_acceptance.terminate_process') as stop:
            with self.assertRaises(TimeoutError):run_step(['inert'],self.root/'build.log',self.root,timeout=1)
        stop.assert_called_once_with(process)

    def type_report(self):
        return {'version':'1.1.414','summary':{'filesAnalyzed':2,'errorCount':0,'warningCount':0},'generalDiagnostics':[]}

    def test_quality_rejects_warnings_even_with_zero_exit(self):
        report=self.type_report();report['summary']['warningCount']=1
        with self.assertRaises(ValueError):validate_type_report(report,0,2)

    def test_quality_rejects_incomplete_source_coverage(self):
        with self.assertRaises(ValueError):validate_type_report(self.type_report(),0,3)
        with self.assertRaises(ValueError):validate_type_report(self.type_report(),1,2)

    def test_quality_rejects_diagnostics_and_version_drift(self):
        report=self.type_report();report['generalDiagnostics']=[{'severity':'error'}]
        with self.assertRaises(ValueError):validate_type_report(report,0,2)
        report=self.type_report();report['version']='other'
        with self.assertRaises(ValueError):validate_type_report(report,0,2)

    def test_powershell_gate_rejects_missing_or_broken_scripts(self):
        with self.assertRaises(ValueError):validate_ps_report({'files':[]},['a.ps1'],0)
        with self.assertRaises(ValueError):validate_ps_report({'files':[{'file':'a.ps1','errors':['syntax']}]},['a.ps1'],0)
        validate_ps_report({'files':[{'file':'a.ps1','errors':[]}]},['a.ps1'],0)

    def test_packaging_requires_both_build_gates(self):
        case=AcceptanceTests();case.setUp();self.addCleanup(case.doCleanups)
        build,_=case.fixture()
        (build/'quality/report.json').write_text(json.dumps({'status':'failed'}))
        with self.assertRaises(ValueError):package_release(case.root,build,'1'*40)
        self.assertFalse((build/'release').exists())


if __name__=='__main__':unittest.main()
