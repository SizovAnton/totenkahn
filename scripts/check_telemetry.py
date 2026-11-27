import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from handlers import telemetry as t
from handlers.telemetry_cli import dispatch


class TelemetryTests(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="totenkahn-telemetry-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "host"
        self.config = json.loads((ROOT / "config/default.config").read_text())
        self.rule = {
            "logsource": {
                "product": "windows",
                "category": "process_creation",
                "service": "security",
            },
        }
        self.req = t.requirements(self.rule, self.config)
        self.state = {
            "host_id": "fixture-host",
            "elevated": True,
            "native_sysmon": "Absent",
            "sysmon": None,
            "audit": 0,
            "command_line": {"exists": False},
            "channels": {
                "Security": {"enabled": True, "readable": True},
                t.SYSMON: {"enabled": None, "readable": False},
            },
            "errors": {},
        }
        self.calls = []
        self.failing_key = None
        self.sysmon = {
            "state": "Running",
            "binary_sha256": "a" * 64,
            "config_sha256": "b" * 64,
            "name": "Sysmon64",
        }

    def backend(self, project, request):
        self.calls.append(copy.deepcopy(request))

        if request["action"] == "observe":
            return copy.deepcopy(self.state)

        if request["action"] == "verify_package":
            return {"executable": "fixture.exe", "sha256": "a" * 64}

        if request["key"] == self.failing_key:
            raise OSError("simulated failure")

        self.assertEqual(t.resource(self.state, request["key"]), request["before"])
        key = request["key"]
        value = request["desired"]

        if key == "sysmon":
            self.state[key] = copy.deepcopy(self.sysmon) if value is not None else None
            self.state["channels"][t.SYSMON] = {
                "enabled": value is not None,
                "readable": value is not None,
            }
        elif key.startswith("channel:"):
            self.state["channels"][key[8:]] = {"enabled": value, "readable": value}
        else:
            self.state[key] = copy.deepcopy(value)

        return copy.deepcopy(self.state)

    def plan(self):
        return t.inspect(ROOT, self.req, probe=self.backend, root=self.root)

    def prepare(self, **kw):
        return t.prepare(ROOT, self.plan(), approved=True, probe=self.backend, root=self.root, **kw)

    def restore(self, **kw):
        return t.restore(ROOT, approved=True, probe=self.backend, root=self.root, **kw)

    def mutations(self):
        return [call for call in self.calls if call["action"] == "set"]

    def use_sysmon(self):
        self.rule["logsource"]["service"] = "sysmon"
        self.req = t.requirements(self.rule, self.config)

    def test_supported_requirements_follow_rule_service(self):
        self.assertEqual(self.req["channels"], ["Security"])
        self.assertFalse(self.req["sysmon"])
        self.use_sysmon()
        self.assertEqual(self.req["channels"], [t.SYSMON])
        self.assertFalse(self.req["audit_process_creation"])

    def test_unknown_category_is_not_certified(self):
        self.rule["logsource"]["category"] = "invented"

        with self.assertRaises(ValueError):
            t.requirements(self.rule, self.config)

    def test_foreign_host_receipt_cannot_restore_settings(self):
        self.prepare()
        state = copy.deepcopy(self.state)
        self.state["host_id"] = "another-host"
        count = len(self.mutations())
        self.assertEqual(self.restore()["status"], "needs_verification")
        self.assertEqual(len(self.mutations()), count)
        self.assertEqual(self.state["audit"], state["audit"])
        self.assertEqual(self.plan()["status"], "blocked")

    def test_unknown_host_identity_blocks_preparation(self):
        self.state.pop("host_id")
        self.assertEqual(self.prepare()["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_powershell_syntax_and_snapshot_comparison(self):
        import shutil, subprocess

        shell = shutil.which("pwsh") or shutil.which("powershell.exe")

        if shell is None:
            self.skipTest("PowerShell parser unavailable")

        code = """param($file)
        $errorsFound=$null;$tokensFound=$null
        $tree=[System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokensFound,[ref]$errorsFound)
        if ($errorsFound.Count) {throw ($errorsFound | Out-String)}
        $interop=$tree.Find({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq \'Add-Type\'},$true)
        . ([scriptblock]::Create($interop.Extent.Text))
        $fn=$tree.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq \'Same\'},$true)
        . ([scriptblock]::Create($fn.Extent.Text))
        $expected=\'{"value":1,"exists":true,"kind":"DWord"}\'|ConvertFrom-Json
        if (-not (Same @{kind=\'DWord\';exists=$true;value=1} $expected)) {throw \'Equal snapshots rejected\'}
        if (Same @{kind=\'DWord\';exists=$true;value=0} $expected) {throw \'Different snapshots accepted\'}
        if (Same $null $false) {throw \'Missing state confused with disabled\'}
        \'Pure adapter checks passed\'
        """
        script = self.root.parent / "check.ps1"
        script.write_text(code, encoding="utf-8")
        result = subprocess.run(
            [
                shell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script),
                str(ROOT / "scripts/host_telemetry.ps1"),
            ],
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))

    def test_plan_and_decline_make_no_writes(self):
        proposal = self.plan()
        self.assertFalse(self.root.exists())
        report = t.prepare(ROOT, proposal, probe=self.backend, root=self.root)
        self.assertEqual(report["status"], "blocked")
        self.assertFalse(self.root.exists())
        self.assertEqual(self.mutations(), [])

    def test_audit_preserves_failure_flag_and_commandline_absence(self):
        self.state["audit"] = 2
        self.assertEqual(self.prepare()["status"], "passed")
        self.assertEqual(self.state["audit"], 3)
        self.assertEqual(self.restore()["status"], "passed")
        self.assertEqual(self.state["audit"], 2)
        self.assertEqual(self.state["command_line"], {"exists": False})

    def test_preexisting_audit_is_not_owned(self):
        self.state.update(audit=1, command_line={"exists": True, "kind": "DWord", "value": 1})
        self.assertEqual(self.prepare()["status"], "passed")
        self.assertEqual(self.mutations(), [])
        self.assertEqual(t.read_ledger(self.root)["operations"], [])

    def test_repeat_prepare_and_restore_are_idempotent(self):
        self.prepare()
        count = len(self.mutations())
        self.prepare()
        self.assertEqual(len(self.mutations()), count)
        self.restore()
        count = len(self.mutations())
        self.restore()
        self.assertEqual(len(self.mutations()), count)

    def test_external_change_is_retained(self):
        self.prepare()
        self.state["audit"] = 3
        report = self.restore()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(self.state["audit"], 3)

    def test_dry_run_preserves_ledger_and_host(self):
        self.prepare()
        raw = (self.root / "ledger.json").read_bytes()
        state = copy.deepcopy(self.state)
        report = self.restore(dry_run=True)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(raw, (self.root / "ledger.json").read_bytes())
        self.assertEqual(state, self.state)

    def test_failed_change_is_not_automatically_owned(self):
        self.failing_key = "command_line"
        report = self.prepare()
        self.assertEqual(report["status"], "error")
        ops = t.read_ledger(self.root)["operations"]
        self.assertEqual(ops[-1]["state"], "interrupted")
        self.failing_key = None
        report = self.restore()
        self.assertEqual(report["status"], "needs_verification")
        self.assertEqual(self.state["audit"], 0)

    def test_ledger_exists_before_backend_mutation(self):
        original = self.backend

        def checked(project, request):
            if request["action"] == "set":
                self.assertEqual(t.read_ledger(self.root)["operations"][-1]["state"], "planned")

            return original(project, request)

        report = t.prepare(ROOT, self.plan(), approved=True, root=self.root, probe=checked)
        self.assertEqual(report["status"], "passed")

    def test_stale_plan_blocks_changes(self):
        plan = self.plan()
        self.state["audit"] = 2
        result = t.prepare(ROOT, plan, approved=True, root=self.root, probe=self.backend)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_unknown_registry_type_blocks_all_changes(self):
        self.state["command_line"] = {"exists": True, "kind": "String", "value": "1"}
        self.assertEqual(self.plan()["status"], "blocked")
        self.assertEqual(self.prepare()["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_nonadmin_is_blocked_before_preparation(self):
        self.state["elevated"] = False
        self.assertEqual(self.prepare()["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_unknown_audit_policy_does_not_mean_disabled(self):
        self.state["audit"] = None
        self.assertEqual(self.plan()["status"], "blocked")

    def test_disabled_channel_is_recorded_and_restored(self):
        self.state["channels"]["Security"] = {"enabled": False, "readable": False}
        self.prepare()
        self.assertTrue(self.state["channels"]["Security"]["enabled"])
        self.restore()
        self.assertFalse(self.state["channels"]["Security"]["enabled"])

    def test_inaccessible_enabled_channel_is_not_ready(self):
        self.state["channels"]["Security"]["readable"] = False
        self.assertEqual(self.plan()["status"], "blocked")

    def test_native_sysmon_conflict_blocks_standalone(self):
        self.use_sysmon()

        for state in ["Enabled", "EnablePending", "Unknown"]:
            self.state["native_sysmon"] = state
            self.assertEqual(self.plan()["status"], "blocked")

    def test_existing_sysmon_is_never_overwritten(self):
        self.use_sysmon()
        self.state["sysmon"] = self.sysmon
        report = self.prepare(accept_eula=True)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_failed_sysmon_discovery_is_not_absence(self):
        self.use_sysmon()
        self.state["errors"]["sysmon"] = "Access denied"
        self.assertEqual(self.plan()["status"], "blocked")

    def test_eula_required_before_download_or_mutation(self):
        self.use_sysmon()

        with patch.object(t, "acquire_sysmon") as acquire:
            report = self.prepare()

        acquire.assert_not_called()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(self.mutations(), [])

    def test_sysmon_install_proof_repeat_and_restore(self):
        self.use_sysmon()
        kwargs = {"accept_eula": True, "acquire": lambda *a, **kw: {"directory": "fixture"}}
        self.assertEqual(self.prepare(**kwargs)["status"], "passed")
        self.assertEqual(self.plan()["status"], "passed")
        count = len(self.mutations())
        self.prepare(**kwargs)
        self.assertEqual(len(self.mutations()), count)
        self.assertEqual(self.restore()["status"], "passed")
        self.assertIsNone(self.state["sysmon"])

    def test_changed_sysmon_filters_prevent_removal(self):
        self.use_sysmon()
        self.prepare(accept_eula=True, acquire=lambda *a, **kw: {"directory": "fixture"})
        self.state["sysmon"]["config_sha256"] = "c" * 64
        self.assertEqual(self.restore()["status"], "needs_verification")
        self.assertIsNotNone(self.state["sysmon"])

    def test_signature_rejection_prevents_installation(self):
        self.use_sysmon()
        original = self.backend

        def rejected(project, request):
            if request["action"] == "verify_package":
                raise ValueError("Invalid signature")

            return original(project, request)

        report = t.prepare(
            ROOT,
            self.plan(),
            approved=True,
            accept_eula=True,
            root=self.root,
            probe=rejected,
            acquire=lambda *a, **kw: {"directory": "fixture"},
        )
        self.assertEqual(report["status"], "error")
        self.assertEqual(self.mutations(), [])

    def test_archive_traversal_rejected(self):
        source = Path(self.root.parent / "bad.zip")

        with zipfile.ZipFile(source, "w") as z:
            z.writestr("../outside.exe", "fixture")

        self.root.mkdir()

        with self.assertRaises(ValueError):
            t.acquire_sysmon(self.root, archive=source)

        self.assertFalse((self.root.parent / "outside.exe").exists())

    def test_offline_archive_extraction_does_not_execute(self):
        source = Path(self.root.parent / "inert.zip")

        with zipfile.ZipFile(source, "w") as z:
            z.writestr("Sysmon64.exe", "inert, not executable")

        self.root.mkdir()
        result = t.acquire_sysmon(self.root, archive=source)
        self.assertEqual(
            (Path(result["directory"]) / "Sysmon64.exe").read_text(),
            "inert, not executable",
        )

    def test_cli_json_is_one_document_and_plan_is_read_only(self):
        rule = self.root.parent / "rule.json"
        rule.write_text(json.dumps(self.rule))
        output = io.StringIO()

        with (
            patch("handlers.telemetry_cli.runtime_config", return_value=self.config),
            patch.object(t, "inspect", return_value=self.plan()),
            redirect_stdout(output),
        ):
            code = dispatch(ROOT, ["telemetry", "plan", "--rule", str(rule), "--json"])

        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "needs_action")
        self.assertFalse(self.root.exists())

    def test_prepared_scope_does_not_certify_delivery(self):
        report = self.prepare()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope"], "configuration_only_not_event_delivery")
        self.assertIn("still be verified", report["requirements"]["limitations"])

    def test_live_gate_prevents_prereqs_and_collector(self):
        from scripts import check_live_run as live

        with (
            patch.object(live.sys, "platform", "win32"),
            patch.object(live, "runtime_config", return_value=self.config),
            patch.object(live, "inspect_telemetry", return_value={"status": "blocked"}),
            patch.object(live.subprocess, "Popen") as launch,
        ):
            with self.assertRaises(ValueError):
                live.run_live_session(
                    "T0001",
                    1,
                    approved=True,
                    atomic_plan={"technique": "T0001", "test_number": 1},
                    host_requirements=self.req,
                )

        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
