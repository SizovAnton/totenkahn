import io
import json
import os
import runpy
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers import dependencies as deps
from handlers.installation import load_state
from handlers.release_manifest import describe_file
from handlers.runtime_paths import read_settings, runtime_config
from handlers.dependency_cli import ensure_ready, dispatch


class DependencyTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="totenkahn-first-run-test-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.project / "config").mkdir()
        (self.project / "config/default.config").write_bytes(
            (ROOT / "config/default.config").read_bytes(),
        )
        (self.project / "config/config.json").write_text("{}")
        self.home = self.base / "data"
        self.cache = self.base / "cache"
        self.cache.mkdir()
        self.contents = {
            "powershell_yaml": {
                "powershell-yaml.psd1": "fixture",
                "private/code.ps1": "# inert fixture",
            },
            "invoke_atomic_red_team": {
                "Invoke-AtomicRedTeam.psd1": "fixture",
                "Public/code.ps1": "# inert fixture",
            },
            "atomic_definitions": {
                "T0001/T0001.yaml": "attack_technique: T0001\natomic_tests: []\n",
                "T0001/src/fixture.txt": "fixture",
            },
        }
        self.lock = []

        for key, files in self.contents.items():
            buf = io.BytesIO()

            with zipfile.ZipFile(buf, "w") as z:
                for name, content in files.items():
                    z.writestr(
                        "atomic-repo/atomics/" + name if key == "atomic_definitions" else name,
                        content,
                    )

                if key == "atomic_definitions":
                    z.writestr("atomic-repo/README.md", "Not part of the atomics tree")
                else:
                    z.writestr("fixture.nuspec", "NuGet metadata")

            path = self.base / (key + ".zip")
            path.write_bytes(buf.getvalue())
            package = {
                "component_id": key,
                "version": "test",
                "url": "https://example.invalid/" + key,
                **describe_file(path),
            }
            self.lock.append(package)
            path.rename(self.cache / (package["sha256"] + ".package"))

        (self.project / "config/dependencies.lock.json").write_text(
            json.dumps({"schema_version": 1, "packages": self.lock}),
        )
        env = patch.dict(os.environ, {"TOTENKAHN_HOME": str(self.home), "PSModulePath": ""})
        env.start()
        self.addCleanup(env.stop)

    def prepare(self, **kwargs):
        return deps.prepare(
            self.project,
            approved=True,
            offline=True,
            root=self.home,
            cache=self.cache,
            _probe=kwargs.pop("_probe", lambda *args: {"status": "passed"}),
            **kwargs,
        )

    def external(self):
        atomic = {}

        for key, files in self.contents.items():
            root = self.base / "external" / key

            for relative, content in files.items():
                p = root / relative
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(content.encode("utf-8"))

            field = {
                "powershell_yaml": "yaml_module_path",
                "invoke_atomic_red_team": "module_path",
                "atomic_definitions": "atomics_path",
            }[key]
            filename = deps.COMPONENTS[key][1]
            atomic[field] = str(root / filename if filename else root)

        (self.project / "config/config.json").write_text(json.dumps({"atomic": atomic}))

        return atomic

    def test_no_consent_no_writes(self):
        self.assertEqual(deps.prepare(self.project, root=self.home)["status"], "blocked")
        self.assertFalse(self.home.exists())

    def test_plan_discovers_before_download(self):
        paths = self.external()

        with patch.object(deps, "obtain_package") as download:
            plan = deps.plan(self.project, root=self.home)

        download.assert_not_called()
        self.assertFalse(self.home.exists())
        self.assertIn(
            paths["module_path"],
            plan["discovery"]["candidates"]["invoke_atomic_red_team"],
        )

    def test_private_base_modules_ready_without_definitions(self):
        result = self.prepare()
        self.assertEqual(result["status"], "passed")
        state = load_state(Path(result["generation"]))
        self.assertEqual(set(state["module_paths"]), set(deps.BASE_COMPONENTS))
        self.assertTrue(
            all(
                (c["origin"] == "installed_by_totenkahn" for c in state["inventory"]["components"])
            ),
        )
        cfg = runtime_config(self.project, root=self.home)
        self.assertEqual(cfg["paths"]["reports_dir"], str(self.home / "reports"))
        self.assertFalse(Path(cfg["atomic"]["atomics_path"]).exists())
        self.assertFalse(any(("README.md" in p for p in state["files"])))
        self.assertEqual(state["verification"]["definitions"]["status"], "not_requested")

    def test_atomic_archive_missing_does_not_affect_base_setup(self):
        package = next((p for p in self.lock if p["component_id"] == "atomic_definitions"))
        (self.cache / (package["sha256"] + ".package")).unlink()

        with patch.object(deps, "obtain_package", wraps=deps.obtain_package) as obtain:
            result = self.prepare()

        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            {call.args[0]["component_id"] for call in obtain.call_args_list},
            set(deps.BASE_COMPONENTS),
        )

    def test_one_blocked_module_does_not_skip_other_module(self):
        real = deps.stage_package

        def stage(archive, package, work):
            if package["component_id"] == "powershell_yaml":
                exc = OSError("blocked fixture")
                setattr(exc, "winerror", 225)

                raise exc

            return real(archive, package, work)

        with patch.object(deps, "stage_package", side_effect=stage):
            result = self.prepare()

        self.assertEqual(result["status"], "needs_verification")
        state = load_state(Path(result["generation"]))
        self.assertIn("invoke_atomic_red_team", state["module_paths"])
        self.assertEqual(result["failures"][0]["component_id"], "powershell_yaml")
        self.assertEqual(result["failures"][0]["category"], "protection_block")
        self.assertIsNotNone(deps.status(self.project)["last_attempt"])

    def test_generic_errno_is_not_claimed_as_antivirus(self):
        report = deps.failure_details(
            OSError(22, "fixture"), component_id="fixture", operation="copy"
        )
        self.assertEqual(report["category"], "operation_failed_cause_not_confirmed")
        self.assertEqual(report["errno"], 22)

    def test_replay_continues_after_failed_base_preparation(self):
        self.prepare(_probe=lambda *args: {"status": "blocked", "reason": "fixture policy"})
        argv = [
            "totenkahn",
            "--rule",
            str(ROOT / "examples/regression/candidate.yaml"),
            "--session",
            str(ROOT / "examples/regression/session"),
            "--test-case",
            str(ROOT / "examples/regression/positive.json"),
        ]

        with (
            patch.object(sys, "platform", "win32"),
            patch.object(sys, "argv", argv),
            patch(
                "handlers.dependency_cli.ensure_ready",
                return_value={"status": "needs_verification", "reason": "fixture module blocked"},
            ),
            patch("sys.stdout", io.StringIO()),
            patch("sys.stderr", io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / "main.py"), run_name="__main__")

        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(len(list((self.home / "reports").glob("*.json"))), 1)

    def test_repeat_is_idempotent(self):
        self.prepare()
        before = read_settings(self.home)

        with patch.object(deps, "obtain_package") as download:
            self.assertEqual(self.prepare()["status"], "passed")

        download.assert_not_called()
        self.assertEqual(before, read_settings(self.home))

    def test_external_exact_matches_reused_and_retained(self):
        paths = self.external()
        result = self.prepare()
        state = load_state(Path(result["generation"]))
        self.assertFalse(state["files"])
        self.assertTrue(
            all(
                (
                    c["origin"] == "preexisting" and c["shared"]
                    for c in state["inventory"]["components"]
                ),
            ),
        )
        self.assertEqual(deps.remove(root=self.home, approved=True)["status"], "passed")
        self.assertTrue(Path(paths["module_path"]).exists())
        self.assertTrue(Path(paths["atomics_path"]).exists())

    def test_incompatible_external_is_not_overwritten(self):
        paths = self.external()
        p = Path(paths["module_path"])
        p.write_text("modified external")
        result = self.prepare()
        state = load_state(Path(result["generation"]))
        self.assertNotEqual(state["module_paths"]["invoke_atomic_red_team"], str(p))
        self.assertEqual(p.read_text(), "modified external")

    def test_external_modification_blocks_readiness(self):
        paths = self.external()
        self.prepare()
        Path(paths["module_path"]).write_text("changed")
        self.assertEqual(deps.status(self.project, root=self.home)["status"], "blocked")

    def test_modified_owned_dependency_retained_on_remove(self):
        result = self.prepare()
        state = load_state(Path(result["generation"]))
        p = Path(state["module_paths"]["powershell_yaml"])
        p.write_text("user modification")
        self.assertEqual(deps.status(self.project, root=self.home)["status"], "blocked")
        self.assertEqual(
            deps.remove(root=self.home, approved=True)["status"],
            "needs_verification",
        )
        self.assertEqual(p.read_text(), "user modification")

    def test_reports_and_cache_survive_remove(self):
        self.prepare()
        p = self.home / "reports/evidence.json"
        p.parent.mkdir()
        p.write_text("keep")
        before = (self.home / "settings.json").read_bytes()
        self.assertTrue(deps.remove(root=self.home, dry_run=True)["dry_run"])
        self.assertEqual(before, (self.home / "settings.json").read_bytes())
        self.assertEqual(deps.remove(root=self.home, approved=True)["status"], "passed")
        self.assertEqual(p.read_text(), "keep")
        self.assertEqual(len(list(self.cache.iterdir())), 3)
        self.assertEqual(deps.remove(root=self.home, approved=True)["status"], "passed")

    def test_runtime_block_does_not_activate(self):
        result = self.prepare(_probe=lambda *args: {"status": "blocked"})
        self.assertEqual(result["status"], "blocked")
        self.assertIsNone(read_settings(self.home)["active"])
        self.assertEqual(
            deps.status(self.project, root=self.home)["status"],
            "needs_verification",
        )

    def test_missing_offline_package_not_success(self):
        package = next((p for p in self.lock if p["component_id"] == "powershell_yaml"))
        (self.cache / (package["sha256"] + ".package")).unlink()
        self.assertEqual(self.prepare()["status"], "needs_verification")
        self.assertIsNone(read_settings(self.home)["active"])

    def test_security_block_is_reported_without_bypass(self):
        failure = OSError("Security product blocked extraction")
        setattr(failure, "winerror", 225)

        with patch.object(deps, "stage_package", side_effect=failure):
            result = self.prepare()

        self.assertEqual(result["status"], "needs_verification")
        self.assertTrue(all((f["category"] == "protection_block" for f in result["failures"])))

    def test_reprepare_after_remove_uses_new_generation(self):
        first = self.prepare()["generation"]
        deps.remove(root=self.home, approved=True)
        second = self.prepare()["generation"]
        self.assertNotEqual(first, second)
        self.assertEqual(len(read_settings(self.home)["generations"]), 2)

    def test_interrupted_copy_is_not_claimed(self):

        def partial(src, dst):
            dst.write_text("partial")

            raise OSError("Interrupted")

        with patch("handlers.installation.copy_exclusive", side_effect=partial):
            result = self.prepare()

        self.assertEqual(result["status"], "needs_verification")
        self.assertEqual(
            deps.remove(root=self.home, approved=True)["status"],
            "needs_verification",
        )

    def test_first_launch_decline_does_not_write(self):
        with patch("handlers.dependency_cli.confirm", return_value=False):
            result = ensure_ready(self.project, offline=True, cache=self.cache)

        self.assertEqual(result["status"], "blocked")
        self.assertFalse(self.home.exists())

    def test_json_management_has_single_stdout_document(self):
        out = io.StringIO()
        err = io.StringIO()

        with (
            patch("sys.stdout", out),
            patch("sys.stderr", err),
            patch.object(deps, "prepare", return_value={"status": "passed"}),
        ):
            code = dispatch(self.project, ["dependencies", "prepare", "--yes", "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue()), {"status": "passed"})
        self.assertIn("Pinned package:", err.getvalue())

    def test_live_bypass_is_rejected(self):
        done = subprocess.run(
            [sys.executable, "-B", str(ROOT / "main.py"), "--auto", "--skip-dependencies"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(done.returncode, 2)
        self.assertIn("not available for live modes", done.stderr)
        self.assertFalse(self.home.exists())

    def test_help_does_not_prepare_dependencies(self):
        with (
            patch.object(sys, "argv", ["totenkahn", "--help"]),
            patch("handlers.dependency_cli.ensure_ready") as prepare,
            patch("sys.stdout", io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / "main.py"), run_name="__main__")

        self.assertEqual(stopped.exception.code, 0)
        prepare.assert_not_called()

    def test_first_windows_launch_invokes_gate(self):
        with (
            patch.object(sys, "platform", "win32"),
            patch.object(sys, "argv", ["totenkahn"]),
            patch("sys.stdout", io.StringIO()),
            patch(
                "handlers.dependency_cli.ensure_ready", return_value={"status": "blocked"}
            ) as prepare,
        ):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / "main.py"), run_name="__main__")

        self.assertEqual(stopped.exception.code, 1)
        prepare.assert_called_once()

    def test_file_link_is_not_claimed_or_removed(self):
        result = self.prepare()
        state = load_state(Path(result["generation"]))
        path = Path(state["module_paths"]["powershell_yaml"])
        path.unlink()
        outside = self.base / "outside"
        outside.write_text("keep")

        try:
            path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(str(exc))

        self.assertEqual(deps.status(self.project, root=self.home)["status"], "blocked")
        self.assertEqual(
            deps.remove(root=self.home, approved=True)["status"],
            "needs_verification",
        )
        self.assertEqual(outside.read_text(), "keep")

    def test_management_dispatch_and_help_do_not_install(self):
        with patch.object(deps, "prepare") as preparation:
            self.assertEqual(dispatch(self.project, ["dependencies", "status"]), 3)

        preparation.assert_not_called()
        self.assertFalse(self.home.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
