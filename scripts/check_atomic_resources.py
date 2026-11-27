import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import zipfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.check_dependencies import DependencyTests
from handlers import dependencies as deps
from handlers.atomic_resources import resource_plan, prepare_resources
from handlers.atomic_lifecycle import build_plan
from handlers.runtime_paths import runtime_config
from handlers.release_manifest import describe_file
from handlers.installation import load_state
from handlers.dependency_cli import dispatch


class ResourceTests(unittest.TestCase):

    def setUp(self):
        self.fixture = DependencyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        test = {
            "name": "inert",
            "auto_generated_guid": "11111111-1111-4111-8111-111111111111",
            "supported_platforms": ["windows"],
            "executor": {
                "name": "powershell",
                "command": 'Write-Output "PathToAtomicsFolder/T0001/bin/inert.exe"',
            },
        }
        self.f.contents["atomic_definitions"] = {
            "T0001/T0001.yaml": yaml.safe_dump(
                {"attack_technique": "T0001", "atomic_tests": [test]}
            ),
            "T0001/bin/inert.exe": "NOT AN EXECUTABLE",
            "T0001/src/inert.ps1": "# no code",
            "T0002/T0002.yaml": "attack_technique: T0002\natomic_tests: []\n",
            "T0002/bin/other.exe": "NOT AN EXECUTABLE",
        }
        p = self.f.base / "atomic.zip"

        with zipfile.ZipFile(p, "w") as z:
            for name, value in self.f.contents["atomic_definitions"].items():
                z.writestr("repo/atomics/" + name, value)

        package = next((p for p in self.f.lock if p["component_id"] == "atomic_definitions"))
        package.update(describe_file(p))
        p.rename(self.f.cache / (package["sha256"] + ".package"))
        (self.f.project / "config/dependencies.lock.json").write_text(
            json.dumps({"schema_version": 1, "packages": self.f.lock}),
        )

    def proposal(self, **kwargs):
        return resource_plan(
            self.f.project,
            "T0001",
            1,
            root=self.f.home,
            cache=self.f.cache,
            offline=True,
            **kwargs,
        )

    def install(self, proposal=None):
        return prepare_resources(
            self.f.project,
            proposal or self.proposal(),
            approved=True,
            root=self.f.home,
        )

    def resource_path(self, result):
        resources = result.get("resources")

        if not isinstance(resources, dict):
            raise AssertionError(
                "Successful preparation must return resource details: " + str(result)
            )

        return Path(resources["atomics_path"])

    def selective_catalog(self):
        import hashlib

        package = next(p for p in self.f.lock if p["component_id"] == "atomic_definitions")
        files = {
            name: {
                "size": len(value.encode("utf-8")),
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
            for name, value in self.f.contents["atomic_definitions"].items()
        }
        (self.f.project / "config/atomic-files.lock.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "revision": package["version"],
                    "archive_sha256": package["sha256"],
                    "files": files,
                }
            )
        )
        (self.f.cache / (package["sha256"] + ".package")).unlink()

        return files

    def cached_definition(self, files):
        name = "T0001/T0001.yaml"
        (self.f.cache / (files[name]["sha256"] + ".package")).write_bytes(
            self.f.contents["atomic_definitions"][name].encode("utf-8")
        )

    def test_selective_plan_reads_only_definition(self):
        self.f.prepare()
        files = self.selective_catalog()
        self.cached_definition(files)

        with patch("handlers.package_cache.build_opener") as network:
            plan = self.proposal()

        network.assert_not_called()
        self.assertIsNone(plan["archive"])
        self.assertEqual(
            plan["files"],
            {name: files[name] for name in ("T0001/T0001.yaml", "T0001/bin/inert.exe")},
        )
        self.assertEqual(plan["transfer"], "pinned_individual_files")

    def test_selective_offline_missing_resource_recorded(self):
        self.f.prepare()
        files = self.selective_catalog()
        self.cached_definition(files)
        result = self.install()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["failures"][0]["path"], "T0001/bin/inert.exe")
        self.assertTrue((self.resource_path(result) / "T0001/T0001.yaml").exists())

    def test_selective_install_repeat_and_remove(self):
        self.f.prepare()
        files = self.selective_catalog()

        for name in ("T0001/T0001.yaml", "T0001/bin/inert.exe"):
            (self.f.cache / (files[name]["sha256"] + ".package")).write_bytes(
                self.f.contents["atomic_definitions"][name].encode("utf-8")
            )

        proposal = self.proposal()
        result = self.install(proposal)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(self.install(proposal)["repeated"])
        self.assertFalse((self.resource_path(result) / "T0002").exists())
        self.assertEqual(deps.remove(root=self.f.home, approved=True)["status"], "passed")

    def test_selective_catalog_revision_mismatch_rejected(self):
        self.f.prepare()
        self.selective_catalog()
        path = self.f.project / "config/atomic-files.lock.json"
        catalog = json.loads(path.read_text())
        catalog["revision"] = "wrong"
        path.write_text(json.dumps(catalog))

        with self.assertRaisesRegex(ValueError, "does not match"):
            self.proposal()

    def test_selective_corrupt_definition_rejected(self):
        self.f.prepare()
        files = self.selective_catalog()
        self.cached_definition(files)
        (self.f.cache / (files["T0001/T0001.yaml"]["sha256"] + ".package")).write_text("changed")

        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.proposal()

    def test_selective_changed_proposal_rejected(self):
        self.f.prepare()
        files = self.selective_catalog()
        self.cached_definition(files)
        proposal = self.proposal()
        proposal["files"]["T0001/bin/inert.exe"]["sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "pinned catalog"):
            self.install(proposal)

    def test_real_whoami_plan_never_requests_archive_or_payload(self):
        import hashlib
        import shutil

        package = json.loads((ROOT / "config/dependencies.lock.json").read_text())["packages"][-1]
        packages = [p for p in self.f.lock if p["component_id"] != "atomic_definitions"] + [package]
        (self.f.project / "config/dependencies.lock.json").write_text(
            json.dumps({"schema_version": 1, "packages": packages})
        )
        self.f.prepare()
        shutil.copyfile(
            ROOT / "config/atomic-files.lock.json", self.f.project / "config/atomic-files.lock.json"
        )
        fixture = (ROOT / "scripts/fixtures/atomic-T1033.yaml").read_bytes()
        self.assertEqual(
            hashlib.sha256(fixture).hexdigest(),
            json.loads((ROOT / "config/atomic-files.lock.json").read_text())["files"][
                "T1033/T1033.yaml"
            ]["sha256"],
        )
        calls = []

        def obtain(locked, cache, **kwargs):
            calls.append(locked["component_id"])
            self.assertEqual(locked["component_id"], "atomic_file:T1033/T1033.yaml")
            path = cache / (locked["sha256"] + ".package")
            path.write_bytes(fixture)

            return {"path": str(path)}

        with patch("handlers.atomic_source.obtain_package", side_effect=obtain):
            plan = resource_plan(
                self.f.project,
                "T1033",
                8,
                root=self.f.home,
                cache=self.f.cache,
                inputs={"whoami_args": "/all"},
            )

        self.assertEqual(calls, ["atomic_file:T1033/T1033.yaml"])
        self.assertEqual(set(plan["files"]), {"T1033/T1033.yaml"})
        self.assertEqual(sum(f["size"] for f in plan["files"].values()), 5740)

    def test_base_does_not_extract_definitions(self):
        self.assertEqual(self.f.prepare()["status"], "passed")
        root = Path(runtime_config(self.f.project)["atomic"]["atomics_path"])
        self.assertFalse(root.exists())

    def test_external_catalog_discovered_without_installing_it(self):
        paths = self.f.external()
        result = self.f.prepare()
        state = load_state(Path(result["generation"]))
        self.assertIn(
            paths["atomics_path"],
            state["discovery"]["candidates"]["atomic_definitions"],
        )
        self.assertNotIn("atomic_definitions", state["module_paths"])

    def test_plan_does_not_extract_or_execute(self):
        self.f.prepare()

        with (
            patch("handlers.atomic_resources.extract_files") as extract,
            patch("subprocess.Popen") as run,
        ):
            plan = self.proposal()

        extract.assert_not_called()
        run.assert_not_called()
        self.assertEqual(plan["asset_techniques"], ["T0001"])
        self.assertFalse(any((p.startswith("T0002/") for p in plan["files"])))

    def test_no_consent_no_selected_files(self):
        self.f.prepare()
        proposal = self.proposal()
        before = set(self.f.home.rglob("*"))
        self.assertEqual(
            prepare_resources(self.f.project, proposal, root=self.f.home)["status"],
            "blocked",
        )
        self.assertEqual(before, set(self.f.home.rglob("*")))

    def test_resources_install_repeat_and_remove(self):
        self.f.prepare()
        proposal = self.proposal()
        result = self.install(proposal)
        self.assertEqual(result["status"], "passed")
        path = self.resource_path(result)
        self.assertTrue((path / "T0001/bin/inert.exe").is_file())
        self.assertFalse((path / "T0002").exists())
        self.assertTrue(self.install(proposal)["repeated"])
        plan = build_plan(runtime_config(self.f.project), "T0001", 1)
        self.assertIn("inert.exe", " ".join(plan["pins"]))
        self.assertEqual(deps.remove(root=self.f.home, approved=True)["status"], "passed")
        self.assertFalse((path / "T0001/bin/inert.exe").exists())

    def test_unprepared_test_blocked_before_execution(self):
        self.f.prepare()

        with self.assertRaisesRegex(ValueError, "prepare-test"):
            build_plan(runtime_config(self.f.project), "T0001", 1)

    def test_additional_reviewed_technique_is_listed(self):
        self.f.prepare()
        proposal = self.proposal(asset_techniques=["T0002"])
        self.assertEqual(proposal["asset_techniques"], ["T0001", "T0002"])
        self.assertEqual(self.install(proposal)["status"], "passed")
        plan = build_plan(runtime_config(self.f.project), "T0001", 1)
        self.assertIn("other.exe", " ".join(plan["pins"]))

    def test_invalid_selection_does_not_materialize(self):
        self.f.prepare()

        for technique, number in [("../T0001", 1), ("T0001", 2)]:
            with self.assertRaises(ValueError):
                resource_plan(
                    self.f.project,
                    technique,
                    number,
                    root=self.f.home,
                    cache=self.f.cache,
                    offline=True,
                )

        with self.assertRaises(ValueError):
            self.proposal(asset_techniques=["../T0002"])

    def test_changed_archive_rejected(self):
        self.f.prepare()
        proposal = self.proposal()
        Path(proposal["archive"]).write_bytes(b"changed")

        with self.assertRaises(ValueError):
            self.install(proposal)

    def test_changed_resource_preserved_on_remove(self):
        self.f.prepare()
        result = self.install()
        path = self.resource_path(result) / "T0001/bin/inert.exe"
        path.write_text("changed")
        self.assertEqual(deps.status(self.f.project)["status"], "passed")
        self.assertEqual(
            deps.remove(root=self.f.home, approved=True)["status"],
            "needs_verification",
        )
        self.assertEqual(path.read_text(), "changed")

    def test_protection_block_retains_failure_journal(self):
        self.f.prepare()
        proposal = self.proposal()
        failure = OSError("fixture protection block")
        setattr(failure, "winerror", 225)

        with patch("handlers.atomic_resources.extract_files", side_effect=failure):
            result = self.install(proposal)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["failures"][0]["winerror"], 225)

        with self.assertRaisesRegex(ValueError, "prepare-test"):
            build_plan(runtime_config(self.f.project), "T0001", 1)

    def test_modified_resource_cannot_be_reapproved_as_original(self):
        self.f.prepare()
        result = self.install()
        (self.resource_path(result) / "T0001/bin/inert.exe").write_text("changed")

        with self.assertRaisesRegex(ValueError, "missing or modified"):
            build_plan(runtime_config(self.f.project), "T0001", 1)

    def test_prerequisite_created_files_not_claimed_by_uninstall(self):
        self.f.prepare()
        result = self.install()
        file = self.resource_path(result) / "T0001/downloaded.txt"
        file.write_text("preserve")
        deps.remove(root=self.f.home, approved=True)
        self.assertEqual(file.read_text(), "preserve")

    def test_interrupted_resource_write_does_not_claim_partial_file(self):
        self.f.prepare()
        proposal = self.proposal()

        def partial(source, destination):
            destination.write_text("partial")

            raise KeyboardInterrupt()

        with patch("handlers.installation.copy_exclusive", side_effect=partial):
            with self.assertRaises(KeyboardInterrupt):
                self.install(proposal)

        self.assertEqual(deps.status(self.f.project)["status"], "passed")
        self.assertEqual(
            deps.remove(root=self.f.home, approved=True)["status"],
            "needs_verification",
        )

    def test_sibling_resources_are_not_selected(self):
        self.f.prepare()
        plan = self.proposal()
        self.assertEqual(set(plan["files"]), {"T0001/T0001.yaml", "T0001/bin/inert.exe"})
        self.assertFalse(any(("inert.ps1" in name for name in plan["files"])))

    def test_explicit_file_is_listed(self):
        self.f.prepare()
        plan = self.proposal(asset_files=["T0001/src/inert.ps1"])
        self.assertIn("T0001/src/inert.ps1", plan["files"])

        with self.assertRaises(ValueError):
            self.proposal(asset_files=["../outside"])

    def test_preview_cannot_be_executed(self):
        from handlers.atomic_lifecycle import verify_plan

        self.f.prepare()
        plan = self.proposal()["atomic_plan"]

        with self.assertRaisesRegex(ValueError, "Preview"):
            verify_plan(plan)

    def test_file_block_does_not_skip_independent_files_or_block_base(self):
        import handlers.atomic_resources as resources

        self.f.prepare()
        plan = self.proposal()
        original = resources.extract_files

        def extract(archive, entries, destination, **kwargs):
            if entries[0][1].endswith(".yaml"):
                exc = OSError("fixture YAML quarantined")
                setattr(exc, "winerror", 225)

                raise exc

            return original(archive, entries, destination, **kwargs)

        with patch.object(resources, "extract_files", side_effect=extract):
            result = self.install(plan)

        self.assertEqual(result["status"], "blocked")
        self.assertTrue((self.resource_path(result) / "T0001/bin/inert.exe").is_file())
        self.assertEqual(deps.status(self.f.project)["status"], "passed")
        self.assertEqual(result["failures"][0]["path"], "T0001/T0001.yaml")

        with self.assertRaises(ValueError):
            build_plan(runtime_config(self.f.project), "T0001", 1)

        retried = self.install(plan)
        self.assertEqual(retried["status"], "passed")
        self.assertNotEqual(self.resource_path(result), self.resource_path(retried))

    def test_final_journal_failure_preserves_primary_error(self):
        import handlers.atomic_resources as resources

        self.f.prepare()
        plan = self.proposal()
        original = resources.save_state

        def save(target, state):
            if any(
                (
                    record["status"] == "passed"
                    for record in state.get("selected_tests", {}).values()
                ),
            ):
                raise OSError("final journal fixture")

            return original(target, state)

        with patch.object(resources, "save_state", side_effect=save):
            result = self.install(plan)

        self.assertEqual(result["status"], "error")
        self.assertIn("final journal fixture", result["reason"])

    def test_unprepared_atomic_plan_cli_is_blocked_not_execution_error(self):
        import runpy

        self.f.prepare()
        out = io.StringIO()

        with (
            patch.object(
                sys,
                "argv",
                ["totenkahn", "--auto", "--atomic-test", "T0001", "1", "--atomic-plan"],
            ),
            patch("sys.stdout", out),
        ):
            with self.assertRaises(SystemExit) as stopped:
                runpy.run_path(str(ROOT / "main.py"), run_name="__main__")

        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(json.loads(out.getvalue())["stage"], "atomic_resources")

    def test_plan_cli_technique_accepts_two_values(self):
        self.f.prepare()
        out = io.StringIO()

        with patch("sys.stdout", out):
            code = dispatch(
                self.f.project,
                [
                    "dependencies",
                    "plan-test",
                    "--technique",
                    "T0001",
                    "1",
                    "--cache",
                    str(self.f.cache),
                    "--offline",
                    "--json",
                ],
            )

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["test_number"], 1)

    def test_json_plan_cli_single_document(self):
        self.f.prepare()
        out = io.StringIO()

        with patch("sys.stdout", out):
            code = dispatch(
                self.f.project,
                [
                    "dependencies",
                    "plan-test",
                    "--technique",
                    "T0001",
                    "--test-number",
                    "1",
                    "--cache",
                    str(self.f.cache),
                    "--offline",
                    "--json",
                ],
            )

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["status"], "planned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
