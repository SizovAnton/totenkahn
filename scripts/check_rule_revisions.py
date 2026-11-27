import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers.git_rule_ci import evaluate_revisions


class RuleRevisionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="totenkahn-revision-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.autocrlf", "false")
        shutil.copytree(ROOT / "examples/rule-ci", self.repo / "examples/rule-ci")
        self.baseline = self.commit()
        self.counter = 0

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.STDOUT).decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def run_gate(self, candidate=None):
        self.counter += 1
        return evaluate_revisions(self.repo, self.baseline, candidate or self.baseline,
                                  "examples/rule-ci/contract.json", self.root / str(self.counter))

    def rule(self, old, new):
        path = self.repo / "examples/rule-ci/rule.yaml"
        path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
        return self.commit()

    def test_unchanged_rule_passes_and_records_hashes(self):
        result = self.run_gate()
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["counts"], {"cases": 2, "regressed": 0, "not_met": 0, "insufficient": 0})
        self.assertEqual(result["baseline_commit"], self.baseline)
        self.assertTrue(result["engine_files_sha256"])
        bundle = self.root / "1/live-bundle"
        self.assertTrue((bundle / "manifest.json").is_file())

    def test_lost_positive_is_rejected(self):
        result = self.run_gate(self.rule("_POSITIVE", "_NEVER_EXECUTED"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["counts"]["regressed"], 1)
        self.assertFalse((self.root / "1/live-bundle").exists())

    def test_false_positive_is_rejected(self):
        result = self.run_gate(self.rule("condition: selection and positive", "condition: selection"))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["counts"]["not_met"], 1)

    def test_candidate_expectations_cannot_hide_regression(self):
        self.rule("_POSITIVE", "_NEVER_EXECUTED")
        path = self.repo / "examples/rule-ci/positive.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["expectation"]["expected_rule_match"] = False
        path.write_text(json.dumps(data), encoding="utf-8")
        result = self.run_gate(self.commit())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["counts"]["regressed"], 1)

    def test_worktree_edits_do_not_change_revision_data(self):
        path = self.repo / "examples/rule-ci/rule.yaml"
        path.write_text("invalid: [", encoding="utf-8")
        self.assertEqual(self.run_gate()["status"], "passed")

    def test_mutable_ref_is_rejected(self):
        result = self.run_gate("HEAD")
        self.assertEqual(result["status"], "error")
        self.assertIn("immutable", result["reason"])

    def test_deleted_rule_is_error_not_pass(self):
        (self.repo / "examples/rule-ci/rule.yaml").unlink()
        self.assertEqual(self.run_gate(self.commit())["status"], "error")

    def test_invalid_yaml_is_execution_error(self):
        (self.repo / "examples/rule-ci/rule.yaml").write_text("[invalid", encoding="utf-8")
        self.assertEqual(self.run_gate(self.commit())["decision"], "execution_error")

    def test_missing_field_cannot_be_a_pass(self):
        result = self.run_gate(self.rule("CommandLine|contains", "MissingField|contains"))
        self.assertEqual(result["status"], "needs_verification")

    def test_unknown_source_is_not_a_confirmed_negative(self):
        result = self.run_gate(self.rule("category: process_creation", "category: process_creation\n  service: powershell"))
        self.assertEqual(result["status"], "needs_verification")

    def test_unaccepted_baseline_cannot_be_a_pass(self):
        self.baseline = self.rule("_POSITIVE", "_NEVER_EXECUTED")
        result = self.run_gate()
        self.assertEqual(result["decision"], "baseline_not_accepted")

    def test_suite_escape_is_rejected(self):
        path = self.repo / "examples/rule-ci/suite.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["cases"][0]["session"] = "../../../outside"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.baseline = self.commit()
        self.assertEqual(self.run_gate()["status"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
