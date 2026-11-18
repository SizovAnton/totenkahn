"""Негативні перевірки оркестрації збірки та приймання звітів."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_acceptance import validate_html, report_fingerprints, verify_preserved, validate_regression
from build_windows_acceptance import snapshot, package_release
from handlers.release_manifest import verify_release


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='dvp-build-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_old_html_is_rejected(self):
        p = self.root/'old.html'; p.write_text('<html>Old report</html>')
        with self.assertRaises(ValueError): validate_html(p)

    def test_new_html_classes_are_required(self):
        p = self.root/'new.html'; p.write_text('<div class="decision-explanation decision-chain recorded-evaluation"></div>')
        validate_html(p)

    def test_report_preservation_checks_content(self):
        p = self.root/'evidence.json';p.write_text('original')
        expected = report_fingerprints(self.root)
        verify_preserved(self.root, expected)
        p.write_text('changed')
        with self.assertRaises(ValueError): verify_preserved(self.root, expected)

    def test_missing_report_is_rejected(self):
        p = self.root/'evidence.json';p.write_text('original')
        expected = report_fingerprints(self.root);p.unlink()
        with self.assertRaises(ValueError): verify_preserved(self.root, expected)

    def test_wrong_regression_outcome_is_rejected(self):
        with self.assertRaises(ValueError): validate_regression({'cases': []}, 'Baseline rule evaluation Candidate rule evaluation')

    def portable_fixture(self, *, preparation='needs_verification', replay_failure=False):
        import check_setup_stage as stage
        release=self.root/'release';release.mkdir()
        work=self.root/'acceptance';work.mkdir()
        from types import SimpleNamespace
        def run(command,**kwargs):
            if command[1:3]==['dependencies','prepare']:
                result={'status':preparation,'reason':'fixture module unavailable'}
            else:result={'status':'passed'}
            from handlers.cli_result import status_code
            return SimpleNamespace(returncode=status_code(result['status']),stdout=json.dumps(result).encode(),stderr=b'')
        replay=RuntimeError('Core replay failed') if replay_failure else None
        with patch.object(stage,'verify_release',return_value={'status':'passed'}), \
             patch.object(stage.subprocess,'run',side_effect=run), \
             patch.object(stage,'run_application_reports',side_effect=replay,return_value={'status':'passed','report_fingerprints':{}}), \
             patch.object(stage,'verify_preserved'):
            return stage.portable_acceptance(release,self.root/'cache',work,60)

    def test_module_block_is_warning_after_core_acceptance(self):
        result=self.portable_fixture(preparation='blocked')
        self.assertEqual(result['status'],'passed_with_warnings')
        self.assertEqual(result['core_status'],'passed')
        self.assertEqual(result['limitations'][0]['report']['status'],'blocked')
        self.assertTrue(any(step['step']=='remove' for step in result['steps']))

    def test_module_error_is_not_reported_as_installed(self):
        result=self.portable_fixture(preparation='error')
        self.assertEqual(result['status'],'passed_with_warnings')
        self.assertTrue(any(step['step']=='repeat-prepare' and step.get('status')=='skipped' for step in result['steps']))

    def test_core_replay_failure_still_fails_acceptance(self):
        with self.assertRaisesRegex(RuntimeError,'Core replay failed'):self.portable_fixture(replay_failure=True)

    def test_interrupt_is_not_converted_to_warning(self):
        with self.assertRaises(KeyboardInterrupt):self.portable_fixture(preparation='interrupted')

    def fixture(self):
        root = self.root
        for name in ('main.py','dvp_setup.py','validation.py','prepare_acceptance_release.py','pyrightconfig.json','requirements-quality.txt','README.md','LICENSE','config/default.config',
                     'config/components.json','config/dependencies.lock.json','examples/demo.json',
                     'scripts/invoke_atomic.ps1','scripts/watch_windows_events.ps1'):
            p=root/name;p.parent.mkdir(parents=True, exist_ok=True);p.write_text('fixture')
        build=root/'build';build.mkdir();(build/'build-environment.txt').write_text('fixture')
        for name, internal in [('dvp','_internal-app'),('dvp-setup','_internal-setup')]:
            p=build/'dist'/name;p.mkdir(parents=True)
            (p/(name+'.exe')).write_bytes(b'fixture')
            (p/internal).mkdir();(p/internal/'fixture.dll').write_bytes(b'fixture')
        (build/'source-inputs.json').write_text(json.dumps(snapshot(root)))
        for name in ('quality','source-checks'):
            (build/name).mkdir();(build/name/'report.json').write_text(json.dumps({'status':'passed','scope':'inert_fixture'}))
        python=root/'python';python.mkdir();(python/'LICENSE.txt').write_text('fixture license')
        return build,python

    def test_source_change_prevents_packaging(self):
        build,_=self.fixture();(self.root/'main.py').write_text('changed')
        with self.assertRaises(ValueError): package_release(self.root,build,'1'*40)
        self.assertFalse((build/'release').exists())

    def test_bundles_and_manifest_are_complete(self):
        build,python=self.fixture()
        with patch('importlib.metadata.distributions',return_value=[]),patch.object(sys,'base_prefix',str(python)):
            release=package_release(self.root,build,'1'*40)
        self.assertEqual(verify_release(release)['status'],'passed')
        self.assertEqual(json.loads((release/'config/config.json').read_text()),{})
        self.assertTrue((release/'_internal-app/fixture.dll').exists())
        self.assertTrue((release/'_internal-setup/fixture.dll').exists())

    def test_bundle_collision_is_rejected(self):
        build,python=self.fixture()
        (build/'dist/dvp/shared.txt').write_text('one')
        (build/'dist/dvp-setup/shared.txt').write_text('two')
        with self.assertRaises(ValueError): package_release(self.root,build,'1'*40)


if __name__ == '__main__':
    unittest.main(verbosity=2)
