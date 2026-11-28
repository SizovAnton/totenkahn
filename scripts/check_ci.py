import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.ci import run_ci, load_config
from handlers.release_manifest import REQUIRED_FILES, build_manifest, write_manifest
from scripts.package_ci_release import package


class CITests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="totenkahn-ci-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = self.root / "pipeline.json"
        self.data = {
            "schema_version": 1,
            "gates": {},
            "jobs": [
                {
                    "id": "smoke",
                    "suite": str(ROOT / "examples/ci/suite.json"),
                    "baseline": str(ROOT / "examples/regression/baseline.yaml"),
                    "candidate": str(ROOT / "examples/ci/candidate.yaml"),
                },
            ],
        }

    def run_pipeline(self):
        self.config.write_text(json.dumps(self.data), encoding="utf-8")

        return run_ci(self.config, self.root / "out")

    def test_positive_negative_and_evidence_links(self):
        report = self.run_pipeline()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["jobs"][0]["counts"]["cases"], 2)
        self.assertTrue((self.root / "out" / report["jobs"][0]["html"]).is_file())
        junit = ET.parse(self.root / "out/junit.xml").getroot()
        self.assertEqual(junit.get("failures"), "0")
        self.assertEqual(junit.get("tests"), "3")

    def test_regression_and_insufficient_are_not_success(self):
        self.data["jobs"][0]["suite"] = str(ROOT / "examples/regression/suite.json")
        self.data["jobs"][0]["candidate"] = str(ROOT / "examples/regression/candidate.yaml")
        report = self.run_pipeline()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["jobs"][0]["counts"]["regressed"], 1)
        junit = ET.parse(self.root / "out/junit.xml").getroot()
        self.assertEqual(junit.get("skipped"), "1")
        self.assertGreater(int(junit.get("failures", "0")), 0)

    def test_thresholds_keep_raw_case_failures_visible(self):
        self.data["jobs"][0]["candidate"] = str(ROOT / "examples/regression/candidate.yaml")
        self.data["gates"] = {"max_not_met": 1, "max_regressed": 1}
        self.assertEqual(self.run_pipeline()["status"], "passed")
        self.assertEqual(ET.parse(self.root / "out/junit.xml").getroot().get("failures"), "1")

    def test_bad_job_does_not_hide_other_jobs(self):
        self.data["jobs"].insert(
            0,
            {**self.data["jobs"][0], "id": "broken", "suite": "missing.json"},
        )
        report = self.run_pipeline()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["jobs"][1]["status"], "passed")
        self.assertEqual(ET.parse(self.root / "out/junit.xml").getroot().get("errors"), "1")

    def test_invalid_config_produces_error_reports(self):
        self.data["gates"] = {"max_not_met": True}
        self.assertEqual(self.run_pipeline()["status"], "error")
        self.assertTrue((self.root / "out/report.html").is_file())

    def test_empty_jobs_and_unknown_gates_rejected(self):
        for data in (
            {**self.data, "jobs": []},
            {**self.data, "gates": {"typo": 0}},
            {**self.data, "gates": {"min_cases": 0}},
        ):
            self.config.write_text(json.dumps(data))

            with self.assertRaises(ValueError):
                load_config(self.config)

    def test_duplicate_json_keys_rejected(self):
        self.config.write_text('{"jobs": [], "jobs": []}')

        with self.assertRaises(ValueError):
            load_config(self.config)

    def test_existing_evidence_never_overwritten(self):
        self.run_pipeline()
        before = (self.root / "out/report.json").read_bytes()

        with self.assertRaises(FileExistsError):
            run_ci(self.config, self.root / "out")

        self.assertEqual(before, (self.root / "out/report.json").read_bytes())

    def test_cli_codes_and_no_dependency_setup(self):
        self.config.write_text(json.dumps(self.data))
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "main.py"),
                "ci",
                "--config",
                str(self.config),
                "--output-dir",
                str(self.root / "cli"),
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "passed")
        self.data["jobs"][0]["candidate"] = str(ROOT / "examples/regression/candidate.yaml")
        self.config.write_text(json.dumps(self.data))
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "main.py"),
                "ci",
                "--config",
                str(self.config),
                "--output-dir",
                str(self.root / "failed"),
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_interrupt_not_success_and_xml_invalid_characters(self):
        self.config.write_text(json.dumps(self.data))

        with patch("handlers.ci.run_regression", side_effect=KeyboardInterrupt):
            report = run_ci(self.config, self.root / "out")

        self.assertEqual(report["status"], "interrupted")
        from handlers.ci import xml_text

        self.assertEqual(xml_text("a\x00b"), "a�b")

    def test_banner_is_compact_and_machine_output_is_silent(self):
        import io
        from displaying.console import show_startup_banner

        class Terminal(io.StringIO):

            def isatty(self):
                return True

        stream = Terminal()

        with patch("sys.stdout", stream):
            show_startup_banner([], stream)

        self.assertIn("T  O  T  E  N  K  A  H  N", stream.getvalue())
        self.assertRegex(stream.getvalue(), r"v\d+\.\d+\.\d+")
        self.assertLessEqual(len(stream.getvalue().splitlines()), 6)

        for arguments in (["ci"], ["doctor", "--json"], ["--atomic-plan"]):
            stream = Terminal()
            show_startup_banner(arguments, stream)
            self.assertEqual(stream.getvalue(), "")

        redirected = io.StringIO()
        show_startup_banner([], redirected)
        self.assertEqual(redirected.getvalue(), "")

    def test_new_default_data_root_and_override(self):
        from handlers.runtime_paths import data_root
        import os

        with patch(
            "handlers.runtime_paths.Path.home", side_effect=RuntimeError("No home directory")
        ) as home:
            with patch.dict(os.environ, {"LOCALAPPDATA": str(self.root)}, clear=True):
                self.assertEqual(data_root(), self.root / "totenkahn")

            with patch.dict(os.environ, {"TOTENKAHN_HOME": str(self.root / "custom")}, clear=True):
                self.assertEqual(data_root(), self.root / "custom")

            with patch.dict(
                os.environ,
                {"TOTENKAHN_HOME": str(self.root / "custom"), "LOCALAPPDATA": str(self.root)},
                clear=True,
            ):
                self.assertEqual(data_root(), self.root / "custom")

            home.assert_not_called()

        with patch.dict(os.environ, {}, clear=True):
            with patch("handlers.runtime_paths.Path.home", return_value=self.root) as home:
                self.assertEqual(data_root(), self.root / ".local/share/totenkahn")
                home.assert_called_once_with()

    def prepare_build(self, status="passed"):
        build = self.root / "build"
        release = build / "release"
        release.mkdir(parents=True)

        for name in REQUIRED_FILES | {"examples/fixture.json"}:
            path = release / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("inert fixture")

        write_manifest(
            release,
            build_manifest(release, version="fixture", source_commit="1" * 40),
        )
        (build / "acceptance").mkdir()
        (build / "ci").mkdir()
        (build / "acceptance/report.json").write_text(json.dumps({"status": status}))
        (build / "ci/report.json").write_text('{"status":"passed"}')
        (build / "build-report.json").write_text(
            json.dumps({"status": status, "build_status": "passed", "acceptance_status": status}),
        )

        return build

    def test_candidate_archive_and_optional_limitations(self):
        build = self.prepare_build("passed_with_warnings")
        archive = package(build, self.root / "delivery")

        with zipfile.ZipFile(archive) as bundle:
            self.assertIn("totenkahn.exe", bundle.namelist())
            self.assertIn("release-manifest.json", bundle.namelist())

        self.assertTrue((archive.parent / "SHA256SUMS").is_file())
        self.assertEqual(
            json.loads((archive.parent / "build-report.json").read_text())["status"],
            "passed_with_warnings",
        )

    def test_candidate_rejects_modified_release(self):
        build = self.prepare_build()
        (build / "release/totenkahn.exe").write_text("changed")

        with self.assertRaises(ValueError):
            package(build, self.root / "delivery")

        self.assertFalse((self.root / "delivery").exists())

    def test_candidate_rejects_failed_core_or_ci(self):
        build = self.prepare_build("error")

        with self.assertRaises(ValueError):
            package(build, self.root / "delivery")

        (build / "build-report.json").write_text(
            '{"status":"passed","build_status":"passed","acceptance_status":"passed"}',
        )
        (build / "acceptance/report.json").write_text('{"status":"passed"}')
        (build / "ci/report.json").write_text('{"status":"failed"}')

        with self.assertRaises(ValueError):
            package(build, self.root / "delivery")


if __name__ == "__main__":
    unittest.main()
