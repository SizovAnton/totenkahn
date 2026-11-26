import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from displaying.preflight import (
    preflight_summary,
    execution_summary,
    execution_prompt,
    emit_preflight,
)
from displaying.results import render_result
from rich.console import Console
from handlers.test_cli import parser_for_tests


class PreflightDisplayTests(unittest.TestCase):

    def plan(self):
        return {
            "technique": "T1033",
            "test_number": 8,
            "name": "whoami",
            "command": "whoami /all",
            "executor": "command_prompt",
            "elevation_required": False,
            "timeout_seconds": 120,
            "dependencies": [],
            "prepare_requested": False,
            "cleanup_requested": False,
            "cleanup_command": "",
            "definition_sha256": "a" * 64,
        }

    def test_short_plan_and_contextual_prompt(self):
        plan = self.plan()
        summary = execution_summary(plan)
        self.assertEqual(summary["command"], "whoami /all")
        self.assertEqual(summary["prerequisites"], "none")
        self.assertEqual(summary["cleanup"], "not defined")
        self.assertNotIn("definition_sha256", summary)
        self.assertNotIn("prerequisite", execution_prompt(plan))
        self.assertNotIn("cleanup", execution_prompt(plan))

    def test_checks_and_authorized_mutations_are_visible(self):
        plan = self.plan()
        plan.update(
            dependencies=[{"number": 1, "check": "check fixture", "prepare": "install fixture"}],
            prepare_requested=True,
            cleanup_requested=True,
            cleanup_command="cleanup fixture",
        )
        summary = execution_summary(plan)
        self.assertEqual(summary["prerequisites"][0]["check"], "check fixture")
        self.assertEqual(summary["prerequisites"][0]["prepare_if_missing"], "install fixture")
        self.assertEqual(summary["cleanup"], "cleanup fixture")

        for part in ("prerequisite", "prepare", "cleanup"):
            self.assertIn(part, execution_prompt(plan))

        plan["prepare_requested"] = False
        self.assertNotIn("prepare_if_missing", execution_summary(plan)["prerequisites"][0])
        self.assertNotIn("prepare missing", execution_prompt(plan))

    def test_full_payload_unchanged_and_all_levels_show_command(self):
        plan = self.plan()
        before = copy.deepcopy(plan)

        for level in (0, 1, 2):
            self.assertEqual(
                preflight_summary(plan, "Execution / preflight", level)["command"], plan["command"]
            )

        self.assertEqual(preflight_summary(plan, "Execution / preflight", 2), plan)
        self.assertEqual(before, plan)
        self.assertIn("definition_sha256", execution_summary(plan, 1))

    def test_base_inventory_only_full_at_vv(self):
        payload = {
            "status": "passed",
            "components": [{"component_key": "ART", "resources": list(range(40))}],
            "verification": {"status": "passed"},
        }
        self.assertNotIn("components", preflight_summary(payload, "Base dependencies"))
        detailed = preflight_summary(payload, "Base dependencies", 1)
        self.assertNotIn("resources", detailed["components"][0])
        self.assertIn("saved_verification", detailed)
        self.assertEqual(preflight_summary(payload, "Base dependencies", 2), payload)

    def test_resource_reuse_and_preparation_distinct(self):
        payload = {
            "status": "passed",
            "readiness": "already verified",
            "files": {"T1033.yaml": {"size": 5740}},
        }
        summary = preflight_summary(payload, "Selected resources")
        self.assertEqual(summary["resources"], "already verified")
        self.assertNotIn("files", summary)
        payload.update(status="planned", readiness="preparation requires consent")
        self.assertEqual(preflight_summary(payload, "Selected resources")["files"], ["T1033.yaml"])

    def test_unrelated_sysmon_is_full_diagnostic_not_blocker(self):
        payload = {
            "status": "passed",
            "requirements": {"channels": ["Security"], "sysmon": False},
            "actions": [],
            "blockers": [],
            "impact": "May install driver",
            "observation": {"errors": {"sysmon": "signature unavailable"}},
        }
        short = preflight_summary(payload, "Telemetry readiness")
        self.assertNotIn("impact", short)
        self.assertNotIn("signature", str(short))
        self.assertIn("diagnostic_note", preflight_summary(payload, "Telemetry readiness", 1))
        self.assertEqual(preflight_summary(payload, "Telemetry readiness", 2), payload)

    def test_blockers_errors_and_consent_actions_not_hidden(self):
        for status in ("blocked", "error", "needs_verification"):
            payload = {"status": status, "reason": "fixture failure", "failures": list(range(20))}
            self.assertEqual(preflight_summary(payload, "Telemetry readiness"), payload)

        payload = {
            "status": "needs_action",
            "actions": [{"key": "audit", "before": 0, "desired": 1}],
            "impact": "Change host audit",
        }
        self.assertEqual(
            preflight_summary(payload, "Host changes requiring consent")["actions"],
            payload["actions"],
        )

    def test_full_render_does_not_truncate_lists_or_values(self):
        out = io.StringIO()
        value = "x" * 1500 + "END_OF_VALUE"
        payload = {"items": [{"message": value} for _ in range(25)]}
        render_result(
            payload,
            "full",
            Console(file=out, width=180, color_system=None),
            full=True,
            legend=False,
        )
        text = out.getvalue()
        self.assertEqual(text.count("END_OF_VALUE"), 25)
        self.assertNotIn("more entries", text)
        self.assertNotIn("Summary view is limited", text)
        self.assertNotIn("MATCH / NO MATCH", text)

    def test_redirected_output_retains_complete_json(self):
        payload = {"status": "passed", "components": list(range(40))}
        out = io.StringIO()
        emit_preflight(payload, "Base dependencies", stream=out)
        self.assertEqual(json.loads(out.getvalue()), payload)

    def test_interactive_short_has_no_legend_or_empty_reason(self):
        out = io.StringIO()

        with patch("displaying.results.interactive", return_value=True):
            emit_preflight(
                {"status": "planned", "files": {}, "reason": None}, "Selected resources", stream=out
            )

        text = out.getvalue()
        self.assertNotIn("unknown / not available", text)
        self.assertNotIn("MATCH / NO MATCH", text)

    def test_parser_v_and_vv_for_all_modes(self):
        parser = parser_for_tests()

        for mode, required in [
            ("auto", ["--technique", "T1033", "8"]),
            ("manual", []),
            ("replay", ["--session", "session"]),
        ]:
            for flag, count in [("-v", 1), ("-vv", 2)]:
                args = parser.parse_args([mode, "--rule", "rule.yaml", *required, flag])
                self.assertEqual(args.verbose, count)


if __name__ == "__main__":
    unittest.main(verbosity=2)
