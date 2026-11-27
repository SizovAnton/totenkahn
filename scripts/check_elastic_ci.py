from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ElasticCIContractTests(unittest.TestCase):
    def test_workflow_uses_shared_validator_and_manual_lab_boundary(self):
        import yaml

        live = yaml.load((ROOT / "examples/ci-workflows/elastic-live-revisions.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        self.assertEqual(set(live["on"]), {"workflow_dispatch"})
        job = live["jobs"]["acceptance"]
        self.assertEqual(job["needs"], "reviewed-rules")
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("return Read-ElasticSearchResponse", commands)
        self.assertIn("Select-ElasticEvidence $response", commands)
        self.assertIn("rule-revisions.json", commands)
        self.assertNotIn('WriteAllText("$inputs\\baseline.yaml"', commands)
        offline = yaml.load((ROOT / "examples/ci-workflows/rule-revisions.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        self.assertNotIn("pull_request_target", offline["on"])
        self.assertEqual(offline["jobs"]["rule-gate"]["runs-on"], "ubuntu-24.04")

    def test_live_validator_rejects_transport_and_evidence_failures(self):
        shell = shutil.which("pwsh") or shutil.which("powershell.exe")
        if shell is None:
            self.fail("PowerShell is required for live contract validation")
        prefix = "TOTENKAHN_LIVE_" + "a" * 32
        actions = [{"marker": prefix + "_" + label, "pid": pid, "exit_code": 0}
                   for label, pid in (("NEGATIVE", 11), ("POSITIVE", 12))]
        docs = [{"_id": str(a["pid"]), "_index": "process-index", "fields": {
            "process.command_line": ["cmd.exe /d /c echo " + a["marker"]], "process.pid": [a["pid"]],
            "host.id": ["fixture-host"], "host.os.type": ["windows"], "event.category": ["process"],
            "event.type": ["start"], "event.dataset": ["endpoint.events.process"],
            "@timestamp": ["2026-11-27T00:00:01Z"],
        }} for a in actions]
        response = {"timed_out": False, "_shards": {"failed": 0, "total": 1},
                    "hits": {"total": {"value": 2, "relation": "eq"}, "hits": docs}}
        base = {"curl": 0, "http": "200", "body": response, "actions": actions,
                "host": "fixture-host", "start": "2026-11-27T00:00:00Z", "end": "2026-11-27T00:01:00Z"}
        cases = []

        def add(name, expected, change):
            item = deepcopy(base)
            change(item)
            item.update(name=name, expected=expected)
            cases.append(item)

        add("valid", "passed", lambda c: None)
        for code, expected in (("401", "authentication_failed"), ("403", "authorization_failed"), ("503", "http_error")):
            add(code, expected, lambda c, code=code: c.update(http=code))
        add("timeout", "transport_timeout", lambda c: c.update(curl=28))
        add("connection", "transport_error", lambda c: c.update(curl=7))
        add("tls", "transport_error", lambda c: c.update(curl=60))
        add("invalid_json", "invalid_response", lambda c: c.update(raw="not-json"))
        add("partial", "partial_response", lambda c: c["body"].update(timed_out=True))
        add("failed_shard", "partial_response", lambda c: c["body"]["_shards"].update(failed=1))
        add("inexact", "inexact_count", lambda c: c["body"]["hits"]["total"].update(relation="gte"))
        add("truncated", "truncated_response", lambda c: c["body"]["hits"]["total"].update(value=3))
        def missing(c):
            c["body"]["hits"]["hits"].pop()
            c["body"]["hits"]["total"]["value"] = 1
        add("missing", "missing_events", missing)
        def extra(c):
            c["body"]["hits"]["hits"].append(deepcopy(docs[0]))
            c["body"]["hits"]["total"]["value"] = 3
        add("extra", "extra_events", extra)
        def field(c, name, value):
            c["body"]["hits"]["hits"][0]["fields"][name] = value
        add("wrong_pid", "pid_mismatch", lambda c: field(c, "process.pid", [999]))
        add("wrong_host", "source_mismatch", lambda c: field(c, "host.id", ["another-host"]))
        add("wrong_source", "source_mismatch", lambda c: field(c, "event.type", ["end"]))
        add("missing_field", "missing_or_ambiguous_field", lambda c: field(c, "process.command_line", []))
        add("ambiguous", "missing_or_ambiguous_field", lambda c: field(c, "process.pid", [11, 12]))
        add("stale", "stale_event", lambda c: field(c, "@timestamp", ["2020-01-01T00:00:00Z"]))
        add("bad_time", "invalid_time", lambda c: field(c, "@timestamp", ["invalid"]))
        add("wrong_marker", "marker_mismatch", lambda c: field(c, "process.command_line", ["echo different"]))
        add("duplicate", "duplicate_identity", lambda c: c["body"]["hits"]["hits"][1].update(_id="11"))
        add("no_id", "missing_identity", lambda c: c["body"]["hits"]["hits"][0].update(_id=""))
        add("action_failed", "invalid_actions", lambda c: c["actions"][0].update(exit_code=1))
        script = r'''
param([string]$Helper, [string]$Cases)
$ErrorActionPreference = 'Stop'
. $Helper
$tests = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Cases, [Text.Encoding]::UTF8))
$results = @(foreach ($test in $tests) {
    try {
        $body = if ($null -ne $test.raw) { $test.raw } else { ConvertTo-Json -InputObject $test.body -Depth 30 }
        $response = Read-ElasticSearchResponse $test.curl $test.http $body
        $selected = Select-ElasticEvidence $response $test.actions $test.host $test.start $test.end
        if ($selected.documents.Count -ne 2) { throw 'Invalid success result' }
        @{name=$test.name; category='passed'}
    }
    catch { @{name=$test.name; category=$_.Exception.Data['category']; reason=$_.Exception.Message} }
})
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject $results -Depth 10 -Compress
'''
        with tempfile.TemporaryDirectory(prefix="totenkahn-elastic-contract-") as folder:
            path = Path(folder)
            (path / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
            (path / "run.ps1").write_text(script, encoding="utf-8")
            result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(path / "run.ps1"),
                                     "-Helper", str(ROOT / "scripts/elastic_ci_contract.ps1"), "-Cases", str(path / "cases.json")],
                                    capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        results = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertEqual(len(results), len(cases))
        for case, observed in zip(cases, results):
            with self.subTest(scenario=case["name"]):
                self.assertEqual(observed["category"], case["expected"], observed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
