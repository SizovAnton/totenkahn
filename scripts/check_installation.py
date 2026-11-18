"""Offline lifecycle regression tests; fixtures are NOT a Windows release.

Run: python -B scripts/check_installation.py
No network, Atomic execution, policy changes or third-party dependencies.
"""
from http.client import IncompleteRead
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import zipfile

ROOT = Path(os.environ.get('DVP_TEST_ROOT', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
from handlers import installation as setup
from handlers.release_manifest import REQUIRED_FILES, build_manifest, write_manifest, describe_file, verify_release
from handlers.package_cache import obtain_package
from dvp_setup import run_doctor


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dvp-lifecycle-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / 'release'
        self.target = self.root / 'installed'
        self.cache = self.root / 'cache'
        self.release.mkdir()
        self.cache.mkdir()
        self.packages = []
        for key, (_, manifest) in setup.MODULES.items():
            archive = self.root / (key + '.zip')
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr(manifest, "@{ ModuleVersion = '1.0.0' }")
                z.writestr('module.psm1', '# inert test fixture')
            descriptor = {'component_id': key, 'version': '1.0.0',
                          'url': 'https://example.invalid/' + key, **describe_file(archive)}
            archive.rename(self.cache / (descriptor['sha256'] + '.package'))
            self.packages.append(descriptor)
        for relative in REQUIRED_FILES | {'examples/example.json'}:
            p = self.release / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('fixture only', encoding='utf-8')
        for name in ('default.config', 'config.json'):
            (self.release / 'config' / name).write_text('{}', encoding='utf-8')
        (self.release / 'config/dependencies.lock.json').write_text(
            json.dumps({'schema_version': 1, 'packages': self.packages}), encoding='utf-8')
        self.manifest()
        quiet = patch.object(setup, 'progress')
        quiet.start()
        self.addCleanup(quiet.stop)

    def manifest(self):
        (self.release / 'release-manifest.json').unlink(missing_ok=True)
        write_manifest(self.release, build_manifest(self.release, version='test', source_commit='1' * 40))

    def install(self, **kwargs):
        kwargs.setdefault('_verifier', lambda target, state, timeout: setup.inspect_installation(target, state))
        return setup.install_release(self.release, self.target, self.cache, offline=True, **kwargs)

    def state(self):
        return setup.load_state(self.target)

    def cli(self, *args):
        completed = subprocess.run([sys.executable, '-B', str(ROOT / 'dvp_setup.py'), *args, '--json'],
                                   capture_output=True, text=True, timeout=30)
        return completed.returncode, json.loads(completed.stdout)

    def doctor(self):
        with patch('dvp_setup.check_environment', return_value={'status': 'passed'}), \
             patch('dvp_setup.load_configuration', return_value={}):
            return run_doctor(self.target, mode='replay')

    def test_install_repeat_and_generated_paths(self):
        self.assertEqual(self.install()['status'], 'passed')
        before = self.state()
        self.assertTrue(self.install()['repeated'])
        self.assertEqual(before['inventory']['installation_id'], self.state()['inventory']['installation_id'])
        self.assertEqual(len(before['inventory']['operations']), len(self.state()['inventory']['operations']))
        config = json.loads((self.target / 'config/config.json').read_text())
        self.assertEqual(config['atomic']['module_path'], self.state()['module_paths']['invoke_atomic_red_team'])
        self.assertFalse((self.target / 'managed/atomics').exists())

    def test_dry_run_and_remove_preserve_evidence(self):
        self.install()
        evidence = self.target / 'runs/evidence.json'
        evidence.parent.mkdir()
        evidence.write_text('keep')
        before = setup.state_path(self.target).read_bytes()
        self.assertTrue(setup.uninstall_release(self.target, dry_run=True)['dry_run'])
        self.assertEqual(before, setup.state_path(self.target).read_bytes())
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'passed')
        self.assertFalse((self.target / 'dvp.exe').exists())
        self.assertEqual(evidence.read_text(), 'keep')
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'passed')
        self.assertTrue(setup.state_path(self.target).exists())
        self.assertTrue(list(self.cache.iterdir()))

    def test_modified_file_blocks_repeat_and_survives_removal(self):
        self.install()
        p = self.target / 'config/config.json'
        p.write_text('changed')
        with self.assertRaises(ValueError): self.install()
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'needs_verification')
        self.assertEqual(p.read_text(), 'changed')

    def test_missing_owned_file_restored(self):
        self.install()
        p = self.target / 'dvp.exe'
        p.unlink()
        self.assertEqual(self.install()['status'], 'passed')
        self.assertEqual(p.read_text(), 'fixture only')

    def test_nonempty_target_rejected(self):
        self.target.mkdir()
        (self.target / 'personal').write_text('keep')
        with self.assertRaises(ValueError): self.install()
        self.assertFalse(setup.state_path(self.target).exists())

    def test_changed_release_rejected_before_target_created(self):
        (self.release / 'dvp.exe').write_text('changed')
        with self.assertRaises(ValueError): self.install()
        self.assertFalse(self.target.exists())

    def test_unexpected_release_file_rejected(self):
        (self.release / 'extra').write_text('extra')
        self.assertEqual(verify_release(self.release)['status'], 'failed')
        with self.assertRaises(ValueError): self.install()

    def test_reserved_release_directory_rejected(self):
        (self.release / 'runs').mkdir()
        (self.release / 'runs/example').write_text('test')
        self.manifest()
        with self.assertRaises(ValueError): self.install()

    def test_nested_target_rejected(self):
        self.target = self.release / 'nested'
        with self.assertRaises(ValueError): self.install()

    def test_lock_excludes_other_operations(self):
        with setup.installation_lock(self.target):
            with self.assertRaises(RuntimeError): self.install()

    def test_offline_cache_missing_and_recovery(self):
        p = next(self.cache.iterdir())
        saved = p.read_bytes()
        p.unlink()
        with self.assertRaises((OSError, ValueError)): self.install()
        self.assertEqual(self.state()['status'], 'interrupted')
        p.write_bytes(saved)
        self.assertEqual(self.install()['status'], 'passed')

    def test_corrupt_cache_rejected(self):
        next(self.cache.iterdir()).write_bytes(b'corrupt')
        with self.assertRaises((OSError, ValueError)): self.install()
        self.assertFalse((self.target / 'dvp.exe').exists())

    def test_partial_write_is_not_claimed(self):
        def partial(source, dest):
            dest.write_bytes(b'partial')
            raise OSError('simulated disk error')
        with patch.object(setup, 'copy_exclusive', side_effect=partial):
            with self.assertRaises(OSError): self.install()
        relative = next(iter(self.state()['files']))
        with self.assertRaises(ValueError): self.install()
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'needs_verification')
        self.assertEqual((self.target / relative).read_bytes(), b'partial')

    def test_prewrite_failure_can_be_removed(self):
        with patch.object(setup, 'copy_exclusive', side_effect=OSError('no space')):
            with self.assertRaises(OSError): self.install()
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'passed')
        self.assertTrue(all(r['state'] == 'abandoned' for r in self.state()['files'].values()))

    def test_failed_runtime_is_not_installed(self):
        result = self.install(_verifier=lambda *args: {'status': 'blocked'})
        self.assertEqual(result['status'], 'needs_verification')
        self.assertEqual(self.state()['status'], 'verification_failed')

    def test_doctor_exposes_failed_verification(self):
        self.install(_verifier=lambda *args: {'status': 'blocked'})
        self.assertEqual(self.doctor()['status'], 'needs_verification')
        self.assertEqual(self.doctor()['installation']['installation_status'], 'verification_failed')

    def test_doctor_exposes_removed_state(self):
        self.install()
        setup.uninstall_release(self.target)
        self.assertEqual(self.doctor()['status'], 'blocked')

    def test_doctor_detects_tampered_file(self):
        self.install()
        (self.target / 'dvp.exe').write_text('tampered')
        self.assertEqual(self.doctor()['status'], 'blocked')

    def test_reverification_exception_drops_installed_status(self):
        self.install()
        def fail(*args): raise subprocess.TimeoutExpired('probe', 1)
        with self.assertRaises(subprocess.TimeoutExpired): self.install(_verifier=fail)
        self.assertEqual(self.state()['status'], 'verification_failed')

    def test_external_modules_not_owned_or_removed(self):
        yaml = self.root / 'external-yaml.psd1'
        art = self.root / 'external-art.psd1'
        yaml.write_text('external'); art.write_text('external')
        self.assertEqual(self.install(external_yaml=yaml, external_art=art)['status'], 'passed')
        self.assertFalse((self.target / 'managed/modules').exists())
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'passed')
        self.assertEqual(yaml.read_text(), 'external')
        self.assertEqual(art.read_text(), 'external')

    def test_external_verification_retry_updates_presence(self):
        yaml = self.root / 'external-yaml.psd1'; yaml.write_text('fixture')
        art = self.root / 'external-art.psd1'; art.write_text('fixture')
        self.install(external_yaml=yaml, external_art=art, _verifier=lambda *args: {'status': 'blocked'})
        self.install(external_yaml=yaml, external_art=art)
        for c in self.state()['inventory']['components']:
            self.assertEqual(c['presence'], 'present')

    def test_cache_inside_target_rejected_before_writes(self):
        self.cache = self.target / 'cache'
        with self.assertRaises(ValueError): self.install()
        self.assertFalse(self.target.exists())

    def test_shared_owned_file_preserved(self):
        self.install()
        state = self.state()
        state['files']['dvp.exe']['shared'] = True
        setup.save_state(self.target, state)
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'needs_verification')
        self.assertTrue((self.target / 'dvp.exe').exists())

    def test_path_traversal_state_rejected(self):
        self.install()
        state = self.state()
        state['files']['../outside'] = state['files'].pop('dvp.exe')
        with self.assertRaises(ValueError): setup.save_state(self.target, state)

    def test_symlink_target_rejected(self):
        actual = self.root / 'outside'; actual.mkdir()
        try: self.target.symlink_to(actual, target_is_directory=True)
        except OSError as exc: self.skipTest(f'Symlinks unavailable: {exc}')
        with self.assertRaises(ValueError): self.install()

    def test_linked_file_not_deleted(self):
        self.install()
        outside = self.root / 'outside'; outside.write_text('keep')
        p = self.target / 'dvp.exe'; p.unlink()
        try: p.symlink_to(outside)
        except OSError as exc: self.skipTest(f'Symlinks unavailable: {exc}')
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'needs_verification')
        self.assertEqual(outside.read_text(), 'keep')
        self.assertTrue(p.is_symlink())

    def test_cli_requires_explicit_noninteractive_removal(self):
        self.install()
        code, report = self.cli('uninstall', '--target-dir', str(self.target))
        self.assertEqual(code, 2)
        self.assertTrue((self.target / 'dvp.exe').exists())
        code, report = self.cli('uninstall', '--target-dir', str(self.target), '--dry-run')
        self.assertEqual(code, 0)
        code, report = self.cli('uninstall', '--target-dir', str(self.target), '--yes')
        self.assertEqual(code, 0)
        self.assertEqual(report['installation_status'], 'removed')

    def test_removed_target_cannot_be_reused(self):
        self.install(); setup.uninstall_release(self.target)
        with self.assertRaises(ValueError): self.install()


    def test_download_incomplete_read_cleans_partial_file(self):
        package = self.packages[0]
        (self.cache / (package['sha256'] + '.package')).unlink()
        response = MagicMock()
        response.__enter__.return_value = response
        response.getcode.return_value = 200
        response.geturl.return_value = package['url']
        response.read1.side_effect = IncompleteRead(b'partial')
        with patch('handlers.package_cache.build_opener') as opener:
            opener.return_value.open.return_value = response
            with self.assertRaises(OSError): obtain_package(package, self.cache)
        self.assertFalse(list(self.cache.glob('*.part')))
        self.assertFalse((self.cache / (package['sha256'] + '.package')).exists())

    def test_download_validates_bytes_and_publishes_cache(self):
        package = self.packages[0]
        path = self.cache / (package['sha256'] + '.package')
        content = path.read_bytes(); path.unlink()
        response = MagicMock()
        response.__enter__.return_value = response
        response.getcode.return_value = 200
        response.geturl.return_value = package['url']
        response.read1.side_effect = [content[:10], content[10:], b'']
        with patch('handlers.package_cache.build_opener') as opener:
            opener.return_value.open.return_value = response
            self.assertEqual(obtain_package(package, self.cache)['source'], 'download')
        self.assertEqual(path.read_bytes(), content)
        self.assertFalse(list(self.cache.glob('*.part')))

    def test_removal_rechecks_content_after_plan(self):
        self.install()
        original = setup.removal_plan
        def changed(target, state=None):
            result = original(target, state)
            (target / 'dvp.exe').write_text('changed after preview')
            return result
        with patch.object(setup, 'removal_plan', side_effect=changed):
            self.assertEqual(setup.uninstall_release(self.target)['status'], 'needs_verification')
        self.assertEqual((self.target / 'dvp.exe').read_text(), 'changed after preview')

    def test_startup_failure_does_not_probe_modules(self):
        self.install()
        with patch.object(setup.sys, 'platform', 'win32'), \
             patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'failed')), \
             patch.object(setup, 'check_module_paths') as probe:
            result = setup.verify_installed(self.target, self.state())
        self.assertEqual(result['status'], 'failed')
        probe.assert_not_called()

    def test_startup_success_uses_installed_module_paths(self):
        self.install()
        state = self.state()
        with patch.object(setup.sys, 'platform', 'win32'), \
             patch.object(setup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
             patch.object(setup, 'check_module_paths', return_value={'status': 'passed'}) as probe:
            result = setup.verify_installed(self.target, state)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(probe.call_args.args[0], Path(state['module_paths']['powershell_yaml']))

    def test_release_upgrade_rejected(self):
        self.install()
        (self.release / 'README.md').write_text('new release')
        self.manifest()
        with self.assertRaises(ValueError): self.install()
        self.assertEqual((self.target / 'README.md').read_text(), 'fixture only')

    def test_untracked_directory_preserved(self):
        self.install()
        (self.target / 'personal-empty').mkdir()
        self.assertEqual(setup.uninstall_release(self.target)['status'], 'passed')
        self.assertTrue((self.target / 'personal-empty').is_dir())


if __name__ == '__main__':
    unittest.main(verbosity=2)
