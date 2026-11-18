# DVP

A clean source delivery does not require `config/config.json`: missing user overrides
use `config/default.config`. Invalid overrides and missing defaults remain errors.
Verified on the clean source snapshot with 217 tests, without a local override.

## Base modules and on-demand Atomic — 2026-11-18

This replaces the previous full-catalog and definitions-only bootstrap profiles.
First launch prepares only `powershell-yaml` and `Invoke-AtomicRedTeam`, after
checking existing components and asking for consent. Python/application libraries
are included in the release. Atomic definitions, payloads and test prerequisites
are not downloaded or extracted during base preparation. The builder does not
require an Atomic cache to create the executables.

Selected tests are prepared explicitly:

```powershell
.\dvp.exe dependencies prepare
.\dvp.exe dependencies plan-test --technique T1059.003 --test-number 2
.\dvp.exe dependencies prepare-test --technique T1059.003 --test-number 2
```

Planning may download the pinned Atomic archive into cache. It reads the selected
technique YAML without extracting the full catalog. The plan lists that YAML and
literal referenced files/directories in the selected test's commands. The upstream
YAML itself contains other tests from the same technique; only the selected test
is authorized for subsequent execution. `--asset-file RELATIVE_PATH` adds an exact
reviewed file; `--asset-technique T1234` explicitly adds an entire reviewed folder.
Dynamic references require review and explicit resources. Missing archive paths
are reported as prerequisite/external paths; resource installation alone does not
certify that these paths or prerequisites exist. `--input NAME=VALUE`, `--offline`
and `--cache PATH` are supported. No commands from YAML run during plan/prepare.

`prepare-test` displays the file plan and asks for consent (`--yes` only authorizes
this operation). Files are copied into a separate owned catalog with hashes and
ownership records. Failed files include component/selection, operation, path,
errno/winerror and reason. Independent files are still attempted; the selected test
remains blocked/error if any required file fails. Failed attempts can be retried
in a new catalog while previous journals and ambiguous files remain preserved.

WinError 225/226 identifies a protection block; other errors, including errno 22,
are not attributed to antivirus without evidence. Protection settings and
Execution Policy are not changed. YAML/archives can still be quarantined.
Base-module readiness ignores selected-test failures. `dependencies status` shows
selected readiness separately. Existing successful full/definitions-only installs
are preserved; new generations use `modules_only`.

Prerequisite checks/preparation and test execution retain their own Atomic consent.
`--prepare-prereqs` attempts missing prerequisites and rechecks them. An unprepared
selection returns `blocked` at stage `atomic_resources`; it is never executed as
ready. Approved existing code stays pinned; newly created prerequisite files are
journaled but not claimed for automatic deletion. `dependencies remove` removes
only confirmed unchanged owned files; external/modified/ambiguous files and reports
are preserved.

If base modules are unavailable, first-run preparation explains the failure and
continues independent component attempts. Replay/regression/manual collection can
continue independently (manual still requires telemetry readiness). Auto execution
requires modules and selected resources. `--skip-dependencies` bypasses preparation
explicitly for saved-data modes; it is not available for live modes.

Build output separates `build_status`, `acceptance_status` and `limitations`.
Compilation, source gates, executable startup, release integrity and core replay
remain mandatory. Portable acceptance runs synthetic executable replay without
Atomic, then reports module preparation/import/removal availability separately.
`passed_with_warnings` exits 0 only when mandatory core checks passed; unavailable
components are listed with their actual blocked/error/not-ready results. A module
failure is not installation success or full live acceptance. Interrupts retain
exit 130; malformed CLI responses, status/code disagreement and core failures
remain errors. Explicit dependency preparation can still return nonzero when
incomplete. Selected test preparation/execution is not part of the default build.

Local checks: 217 inert source tests, 62 Python modules for Linux/Windows without
errors/warnings, five PowerShell parse checks, and ordinary/regression replay
without Atomic. A read-only plan against the real pinned archive for T1059.003
number 2 selects only its technique YAML. No real Atomic execution or Windows
host changes were performed; new Windows acceptance remains required.

Reference: [upstream framework-only and selected-test installation](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam).

## Release stabilization — 2026-11-17

The Windows builder now requires static analysis and inert source tests before
building executables. Packaging also requires both successful gate reports.
Pyright 1.1.414 checks all 62 Python modules against Python 3.12 for both Linux
and Windows; warnings fail the gate. PowerShell parses all five scripts without
executing them. Build-only tooling is in `requirements-quality.txt`; it is not
an application runtime requirement. The builder installs it automatically.

Developer checks (from the source directory):

```powershell
python -m pip install -r requirements-quality.txt
python -B scripts/check_quality.py
python -B scripts/check_setup_stage.py --source-only
```

Use a development environment with the application dependencies installed and
PowerShell available. `--source-only` does not install real components or run
Atomic tests. Current local verification: 217 tests passed without skips, both
static targets passed, and ordinary/regression synthetic replay JSON and HTML
reports passed validation. This does not certify a Windows executable or live
collection; those require a new Windows build and acceptance.

CLI operational statuses use exit codes 0 (passed/completed), 1 (blocked),
2 (error/failed/unknown), 3 (needs action/verification), and 130 (interrupted).
Argument-parser errors retain their normal exit codes. Detection decisions
remain separate from operational status. On interruption or failure, partial
evidence files are saved independently and replaced atomically. A secondary
journal-write error is reported without masking the original failure. Disk
failure can still prevent evidence persistence. Child-process termination is
best effort and does not guarantee removal of detached processes or rollback
of changes made by an Atomic definition.

## Windows host telemetry preparation — 2026-11-17

The next release adds a separate, explicit host configuration workflow:

```powershell
.\dvp.exe telemetry plan --rule .\rules\selected-rule.yaml
.\dvp.exe telemetry prepare --rule .\rules\selected-rule.yaml
.\dvp.exe telemetry check --rule .\rules\selected-rule.yaml
.\dvp.exe telemetry restore --dry-run
.\dvp.exe telemetry restore
```

The rule is user-provided. Managed paths are automatic. `plan` and `check` only
inspect; `prepare` and `restore` display a plan and request consent. `--yes`
permits noninteractive confirmation **for this command**, not for an Atomic test.
`--json` keeps stdout machine-readable. `prepare --dry-run` displays the plan.

Supported coverage is explicit: Windows `process_creation`, `network_connection`,
`image_load`, `file_event` (FileCreate), `registry_event`, and `dns_query` from
Sysmon; Security coverage is Process Creation (4688). Required channels are the
configured supported sources matching the rule logsource. A generic category
without `service` can select both sources. Other categories and service-only
rules without a category are blocked, not guessed from arbitrary selectors.
The live collector uses the resulting channel list rather than every channel
in the global configuration.

For Security process creation, preparation preserves the current Failure audit
bit while enabling Success, and enables the DWORD policy for command-line
recording. Command lines are recorded host-wide and may include sensitive data.
Existing values and missing-value state are journaled separately. Disabled
supported channels can be enabled; inaccessible channels block readiness.
Administrative rights are required for changes. Group Policy can reapply
settings later; DVP does not modify domain policy and rechecks before each run.

If standalone Sysmon is absent, preparation can download the official Sysinternals
ZIP, safely extract it, choose the host architecture and verify a **valid
Microsoft Authenticode signature** before execution. The archive and executable
hashes, signer and version are recorded. This URL is a rolling Microsoft release,
not a pre-pinned Sysmon version. `--sysmon-archive PATH` uses an offline ZIP with
the same signature checks. Installation requires `--accept-sysmon-eula` in
addition to confirmation. The displayed XML profile enables all six supported
event types without exclusions and SHA-256 image hashing; this may increase
host-wide event volume. No installer is executed during source development tests.

DVP detects existing Sysmon services/drivers and the built-in Sysmon optional
feature. It does **not** install standalone Sysmon alongside an enabled or
unverified native feature. Existing unowned configurations are preserved and
reported as requiring verification; arbitrary Sysmon filter rules cannot be
certified by this implementation. Built-in Sysmon provisioning, conversion of
external configurations and automatic repair of stopped/drifted installations
are not performed. A previously DVP-installed service is trusted only while its
service identity, binary and observed configuration fingerprint still match its
confirmed installation record.

`%LOCALAPPDATA%\DVP\telemetry\ledger.json` binds operations to the host identity.
The journal is written before each change. Restore works in reverse order only
for confirmed operations whose current values still match DVP's recorded result.
Changed settings, interrupted operations and foreign-host receipts are retained
for review. Sysmon is uninstalled only if DVP has a matching confirmed installation
record. Event logs, sessions, reports, package cache and journals remain. A newly
created empty registry key may remain after restoring an originally absent value.
Do not remove the ledger before restoration. `dependencies remove` remains a
separate operation and does not restore host policies or remove the Sysmon service.

Every manual/automatic live run rechecks rule-specific readiness **before**
Atomic prerequisite commands or starting the collector. The readiness snapshot
is included in session metadata and the HTML/JSON report. `passed` here means
**configuration checks passed**, not that a specific event arrived. Collector
subscription readiness and experiment evidence remain separate checks.

Local validation uses a fake host backend plus PowerShell syntax, interop
compilation and pure snapshot-comparison tests. No Windows service, policy,
registry value or real Sysmon installation was changed during development.
A new Windows build and real host acceptance are still required.

Implementation references: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon),
[built-in Sysmon coexistence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon),
[command-line auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing),
[AuditQuerySystemPolicy](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy).

## Managed selected-test lifecycle — 2026-11-17

After base dependency preparation, select one Windows Atomic test by technique
and number. Inspect its definition-derived plan without running any checks:

```powershell
.\dvp.exe --auto --atomic-test T1059.001 1 --atomic-plan
```

For the **selected and reviewed** test, use the ordinary rule argument and add
lifecycle options as needed:

```powershell
.\dvp.exe --auto --atomic-test T1059.001 1 --rule .\rules\selected-rule.yaml --prepare-prereqs --cleanup
```

`selected-rule.yaml` is a user-provided rule, not a bundled fixture. Runtime
module/catalog/report paths remain automatic. `--input NAME=VALUE` can be
repeated for test inputs; unknown or duplicate names are rejected. The plan
shows the resolved commands, required elevation, prerequisite checks and
preparation commands, requested cleanup and timeout. Inputs are substituted
into definition code, as Atomic expects; they are not shell-escaped literals.
Plans and logs retain these values, so do not use secret credentials as inputs.

An explicit confirmation precedes **any definition command**, including
prerequisite checks. `--approve-atomic` approves that plan for noninteractive
execution. The existing `--yes` only approves base dependency preparation.
Checks may execute code and are not a read-only inspection; `--atomic-plan`
is the read-only option. Definitions/modules are fingerprinted before consent
and checked again before every step; changed file inventories block execution.

Only missing prerequisites are prepared, and only with `--prepare-prereqs`.
Each successful preparation is followed by a fresh check. Failed checks,
missing permissions, unsupported executors and timeouts stop the workflow.
Already satisfied prerequisites are recorded as preexisting and are not
reinstalled or automatically removed. Preparation actions have unknown
host-wide ownership and are recorded for review, not claimed as reversible.

The collector must confirm every configured channel before test execution.
Readiness has a 60-second deadline. `--atomic-timeout` sets each definition
command's deadline (default 120 seconds, range 1–3600); the process wrapper and
automatic collection have bounded overhead allowances. On cancellation/timeouts,
DVP requests process-tree termination; it does not certify absence of detached
processes or persistent side effects. Partial session events and diagnostics
are retained on execution/collection failure.

`--cleanup` authorizes the definition's cleanup command after collection stops,
including after an attempted test fails. It is not invoked when the test never
started. Cleanup may itself change external resources, so review that command
in the plan. It is **not** an ownership-based uninstall or verified restoration
of the host. Prerequisite changes and unverified leftovers remain in the report.
The existing `dependencies remove` command still removes only DVP-owned unchanged
base files; it does not roll back arbitrary test prerequisites.

Each run records `atomic/lifecycle.json`, `atomic/lifecycle.html`, per-step request,
stdout/stderr and timestamps under the session directory. The main HTML/JSON
report and CLI show a short recorded chain plus distinct execution, collection,
cleanup and rule results. Missing/ambiguous process candidates or unevaluated
candidate events give `insufficient_data`; `no_match` means no rule match on
recorded candidate events, not proof of complete telemetry or causal attribution.
Failed setup/execution produces its lifecycle report without inventing a
negative detection result. Exit 1 denotes blocked/cancelled setup, exit 2 an
execution/lifecycle error, exit 3 incomplete evidence or unsuccessful cleanup.
Exit 0 means completed analysis, not necessarily a positive rule match.

This adapter uses the pinned ART command executor and records its numeric exit
code, timeout flag and PID; it does not infer success from console prose. It
supports Windows `powershell` and `command_prompt` tests, no manual/cloud/shell
executors and no implicit hook execution. No automatic security-policy changes
or elevation are performed. Source tests use inert definitions and a fake
PowerShell executor; real Windows Atomic execution/collection remains unverified.

## Portable bundle and first-run preparation — 2026-11-17

This is the default workflow for the next Windows build. Extract the **complete**
release ZIP, keeping `dvp.exe`, its runtime libraries and configuration together.
Python, PyYAML and Rich are bundled; users do not install Python or edit code.
From that directory, run:

```powershell
.\dvp.exe
```

The first operational launch checks known Atomic locations, configured paths and
`PSModulePath`, explains the preparation, and requests consent. It then prepares
**both base modules**: powershell-yaml and Invoke-AtomicRedTeam. Atomic YAML
and resources are prepared separately for a selected test. Missing
packages are downloaded with locked size/hash verification. Existing candidates
are compared against the pinned package contents before reuse. Different or
modified installations are preserved; DVP installs its own compatible copy.
Discovery is limited to known/configured paths, not an exhaustive disk search.
Use `dependencies prepare --atomic-dir PATH` for an unusual existing location.
Verification may still need the pinned archive even when a candidate exists.

Data and managed dependencies go under `%LOCALAPPDATA%\DVP`. `settings.json`
selects an active dependency generation; its ledger records paths, ownership,
versions, hashes and external components. The runtime uses these recorded paths.
Reports and collected runs go into this user-data directory. The release itself
is not copied or modified. Preserve the ledger when moving/updating the bundle.

Common commands from the extracted release directory:

```powershell
.\dvp.exe dependencies plan
.\dvp.exe dependencies prepare
.\dvp.exe dependencies status
.\dvp.exe doctor --mode replay
.\dvp.exe reports --open
.\dvp.exe dependencies remove
```

`prepare` and `remove` ask for confirmation. `--yes` supports automation;
`--json` produces a single JSON document on stdout with progress on stderr.
`remove --dry-run` previews removal. Only unchanged files created and recorded
by DVP are removed; preexisting/shared components, modified files, reports,
runs, cache and journals remain. Repeat preparation/removal is supported.
For an already populated cache, use `dependencies prepare --offline`; an
optional `--cache PATH` selects a transferred cache. Ordinary users need no
path variables. `DVP_HOME` is an advanced isolation override used by acceptance.
The portable program folder can be deleted separately after dependency removal.

`--help`, management inspection and report browsing do not trigger installation.
Normal Windows launches offer base preparation; unavailability is reported
without blocking independent replay/regression/manual modes.
`--skip-dependencies` is an explicit exception for saved-session replay or
regression only; live modes reject it. Linux source runs do not install Windows
components automatically.

Base preparation verifies module imports using synthetic YAML; **it does not execute Atomic tests**. Test-specific
prerequisites, collector readiness and live acceptance remain separate. Windows
PowerShell must already be available. Execution Policy, Defender, services and
audit policies are not changed. A protection/policy block is reported; incomplete
resources stay journaled for inspection and safe removal, not marked ready.

Historical validation of the superseded definitions-only profile: 104 source tests passed on Linux. The real pinned archive was
hash-checked and 353 definitions containing 1,950 test declarations were parsed
without extraction or execution. The updated builder selects portable lifecycle
acceptance (prepare/repeat, doctor, synthetic executable reports, removal and
preservation checks). **This new Windows executable workflow is not yet accepted.**
The legacy commands below remain available and prepare only the two modules;
they are not the default portable first-run interface.


Detection Validation Platform for testing Sigma rules using Atomic Red Team and collected Windows events.


## Legacy managed setup (optional, modules-only workflow)

End users use a complete Windows release, not a Python environment. The setup
implementation now supports `install`, `uninstall`, and `doctor`. The previous managed workflow passed the user-reported Windows acceptance on
2026-11-15. This does not certify the new portable dependency workflow.
The commands below describe that release interface. Developers can invoke the
same CLI with `.venv-win\Scripts\python.exe -B dvp_setup.py`.

### Install

From the **original, pristine release directory**, run:

```powershell
.\dvp-setup.exe install
```

The default target is `%LOCALAPPDATA%\DVP`; use `--target-dir` to choose another
empty directory whose parent already exists. The release must contain its
`release-manifest.json`, both `dvp.exe` and `dvp-setup.exe`, runtime libraries,
configuration, examples, scripts, licenses, `config/components.json`, and
`config/dependencies.lock.json`. Generate the manifest only after assembling
all files. Do not put the package cache or runtime reports inside the source
release: integrity verification rejects unexpected files.

```powershell
.\dvp-setup.exe install --target-dir C:\Tools\DVP --cache C:\DVP-Packages --offline
```

The offline cache contains `<sha256>.package` files from the lock. Online mode
fetches missing packages. Only the pinned YAML and Invoke-AtomicRedTeam modules
are prepared; the full atomics archive is **not** fetched or unpacked by install.
Modules are private under `managed/modules`. System-wide modules are not
changed, removed, or silently adopted. To reuse explicit preexisting module
manifests, supply **both** `--external-yaml PATH` and `--external-art PATH`.
Their versions must match the lock; they remain external/shared and are never
removed by DVP. No automatic search or upgrade of global modules is performed.

Setup generates the module paths in `config/config.json`, copies files without
overwriting existing resources, checks `dvp.exe --help`, and verifies imports from the installed paths
with a synthetic manual-executor YAML document. It never executes Atomic tests,
installs Sysmon, changes audit settings, disables Defender, or changes execution
policy. A policy or protection block is reported and must be resolved through
the environment's approved administration process.

`passed` means release files, executable startup (`--help`), and module imports were verified. It does not mean
live event collection or a selected Atomic test is ready. `managed/atomics` is
reserved for future selected-test preparation and is not populated in this
package. Test prerequisites, Sysmon setup and live collection acceptance remain
separate work.

### Recovery and ownership

`.dvp-state/installation.json` contains a versioned installation ledger, the
component inventory, operation history, package provenance, and per-file
fingerprints. Do not delete it before uninstalling. The inventory describes
ownership; it is not a cryptographically authenticated record against a local
administrator who can alter both state and files.

A persistent sibling `.DVP.dvp.lock` is used for OS-level process locking; the
lock releases when the process exits. The empty lock file is intentionally
retained to avoid splitting locks between concurrent processes. The default
package cache is a separate sibling `.DVP.dvp-package-cache` and is retained.

Repeating install with the same release and module selection verifies an
existing installation. Missing owned files can be restored; modified files are
preserved and block automatic repair. Interrupted operations remain recorded.
A file left between the journaled intent and confirmed completion is ambiguous:
setup neither adopts nor overwrites it. Inspect it and move it aside manually
if appropriate before retrying. No blanket rollback or automatic deletion of
ambiguous resources is attempted. Upgrades and relocation require a new target.
A previously removed installation is not reused, to preserve its evidence.

### Uninstall

Run setup **from the original release, outside the installed target**, because
Windows may keep the running executable locked:

```powershell
.\dvp-setup.exe uninstall --target-dir C:\Tools\DVP --dry-run
.\dvp-setup.exe uninstall --target-dir C:\Tools\DVP
```

The second command previews and asks for confirmation. For automation, inspect
the dry run and pass `--yes --json`. Preview is advisory; actual removal acquires
the lock and recomputes/rechecks ownership and hashes. It removes only confirmed,
unchanged, unshared files and empty owned directories. Modified files, external
modules, untracked resources, reports and evidence are preserved and listed.
No recursive deletion of the installation root is performed. State and operation
history remain. File locks and other errors are reported; rerunning uninstall
can continue an interrupted removal.

### Results and diagnostics

All setup commands support `--json` and `--output NEW_FILE.json`; output files
are not overwritten. Progress goes to stderr. Exit codes: `0` completed requested
checks/actions, `1` blocked, `2` error, `3` further verification or retained owned
resources require attention. Preserving unrelated evidence alone is not an error.
An installed setup executable must be uninstalled using an external release copy.

```powershell
.\dvp-setup.exe doctor --mode replay --project-dir C:\Tools\DVP
.\dvp-setup.exe doctor --mode auto --project-dir C:\Tools\DVP --plan --json
```

Doctor also inspects the installed file ledger when present. Windows execution
policy is observed, not modified. File availability is distinct from module
compatibility, collector readiness, and selected-test prerequisites.

Validation so far: synthetic release lifecycle and fault-injection checks on
Linux, real pinned module import/synthetic parsing with PowerShell Core on Linux.
The earlier standalone module check also passed on Windows PowerShell 5.1; this
new complete installer/uninstaller still requires Windows acceptance and a real
built release. No Atomic tests were run during these checks.

## Automated Testing

On Windows, run the following command in PowerShell as Administrator:

```powershell
.\dvp.exe `
    --rule .\test_rule.yaml `
    --auto `
    --atomic-test T1087.001 8
```

- `--rule` specifies the Sigma rule to evaluate.
- `--auto` starts an automated test and event collection.
- `--atomic-test` specifies the Atomic Red Team technique and test number.
- `--show-correlation` displays detailed correlation information in the console.

Running an automated test requires configured installations of Atomic Red Team and Invoke-AtomicRedTeam, along with the event source specified in the configuration.

Live collection subscribes to all configured channels in `events.channels`; readiness requires all subscriptions.

The `sources` profiles define the channel, provider, product, service, and Event ID-to-category mappings in `event_categories`.

The report evaluates all collected events. A rule match among candidate events does not prove that the Atomic test caused those events.

## Saved Session Analysis

```bash
.venv/bin/python -B main.py \
    --rule test_rule.yaml \
    --session runs/SESSION_ID \
    --execution-log runs/SESSION_ID/execution.csv
```

Replace `SESSION_ID` with the saved session directory name.

This mode generates a report without running the Atomic test again.


## Selected Evidence and Telemetry Requirements

Use `--test-case` with `--session` to evaluate an explicitly selected set of saved
`record_id` values. The session passport is required. The case session ID must
match it; unknown or duplicate event IDs are rejected. Events outside the
selection remain in the report, but their matches do not satisfy the case.

```powershell
.\dvp.exe --rule .\test_rule.yaml `
    --session .\runs\SESSION_ID `
    --test-case .\test-case.v2.example.json
```

Rebuild the executable after source changes. The example contains the IDs from
the development manual session: use it only with that session, or copy it and
explicitly update the case ID, session ID, evidence IDs, selection reason and
requirements for your experiment. It is never loaded automatically.
`test-case.json` remains the original v1 case.

### Contract versions

- v1: unchanged fields (`schema_version`, `case_id`, `session_id`, `description`,
  `evidence`, `expectation`); telemetry is `not_assessed`.
- v2: the same fields plus a required `telemetry` object with
  `scope: "selected_events"` and a non-empty `requirements` list.
- Unknown fields, versions and unsupported operations are errors. Existing
  contracts and historical reports are not migrated implicitly.

Each telemetry requirement has exactly these fields:

```json
{
  "id": "required-event-context",
  "selector": [{"path": ["source", "category"], "equals": "process_creation"}],
  "min_count": 1,
  "required_fields": [["computer"], ["data_fields", "CommandLine"]]
}
```

Paths are non-empty arrays of exact dictionary keys. Dots are literal key
characters, not path separators. Wildcards, array indexing, XPath, regular
expressions and executable expressions are not supported.

Selector predicates use AND and exact, case-sensitive equality with identical
Python scalar types: `1`, `1.0`, `true` and `"1"` are distinct. Values must be
finite JSON scalars. `equals: null` matches a present null field, never a missing
field. An empty selector explicitly selects all evidence events.

`min_count` is a positive integer counting selector-matching selected events.
Every matching event must contain every required field with a usable value:
missing, null, blank strings and empty lists/objects fail; `false` and `0` pass.
An empty `required_fields` list intentionally checks event count only. Duplicate
requirement IDs, predicate paths and required paths are rejected.

Choose selectors using event/source identity; put fields whose presence must be
checked in `required_fields`. A selector requiring a missing field yields no
matching candidate, rather than a field-presence issue.

### Result semantics

The report retains rule counts, matches outside the selection, missing results,
rule SHA-256 and the exact test-case definition. Telemetry includes per-requirement
status, matching record IDs, field paths and missing/null/empty reasons. HTML
provides links back to the event cards.

The case is `insufficient_data` for incomplete collection, empty evidence,
missing rule results, any skipped selected event, or failed declared telemetry
requirements. Otherwise it is `met` or `not_met` according to whether at least
one selected event matches and whether that agrees with `expected_rule_match`.
Rule results remain visible even when telemetry fails.

`sufficient` means only that the declared requirements pass on prepared event
fields. It does not verify raw XML normalization, unsupported UserData, audit
policy, complete delivery of late events, or causal attribution. A v1 `met`
result still carries `not_assessed`. The original all-session manual expectation
remains separate and retains its rule fingerprint binding.

### Verification performed (2026-11-09)

The change was checked with inline Python fixtures, invalid-contract cases,
HTML parsing and actual CLI replay in an isolated temporary project. Coverage
includes positive/negative rule outcomes, unrelated matches, missing/empty/null
fields, `false`/`0`, missing events, empty evidence, skipped results, incomplete
collection and v1 compatibility. No Atomic test was executed. A rebuilt Windows
executable still needs verification against the real saved session.


### Selector diagnostics (2026-11-10)

The development session predates category mappings and stores `source.category`
as null. Its v2 example now selects the saved channel, provider and string Event
ID instead of assuming `process_creation`. This changes only the example data;
no Sysmon-specific branch was added to the evaluator. Historical session files
and reports are never rewritten to make a requirement pass.

Each requirement now includes `rejected_events`: selected event IDs and all failed
selector predicates, with path, field presence, expected/actual values and Python
type names. Reasons are `field_missing`, `type_mismatch` or `value_mismatch`.
`NoneType` with `field_present: true` means a present JSON null, whereas
`actual_type: missing` means the field path was absent. A present null can match
`equals: null`. A missing path cannot.

HTML shows **Events excluded by selector** with links to the full evidence cards.
Required-field checks run only on selector-matching events; an excluded event is
not evidence that no event was collected. Empty selectors and all existing status
semantics are unchanged. Older reports without this diagnostic list still render.


## Rule Regression Comparison

Regression runs two explicitly chosen rules on each case's same saved events and
profiles, in the same engine process. It does not start the collector, Atomic or
any external command. Cases are evaluated with their own expected outcome; the
old all-session expectation is not rebound to either rule.

```powershell
.\dvp.exe --regression-suite .\regression-suite.example.json `
    --baseline-rule .\baseline.yaml `
    --candidate-rule .\candidate.yaml
```

Create the two rule files deliberately; the command never edits rules. The real
suite example refers to the development manual session and its v2 case. Adjust
paths explicitly if that session is elsewhere. `--output-dir PATH` overrides the
configured reports directory. Each successful run creates a new
`regression-UUID/report.json` and `report.html`; previous reports remain intact.

Regression cannot be combined with `--rule`, `--session`, `--manual`, `--auto`,
`--test-case`, `--test-context`, `--execution-log`, `--atomic-test` or
`--show-correlation`. Ordinary single-rule commands still require `--rule`.
A completed regression exits successfully even if it reports regressions:
inspect the summary; a successful process exit is not a passing test suite.

### Suite contract v1

```json
{
  "schema_version": 1,
  "suite_id": "example-suite",
  "description": "Compare the two supplied rules on saved test evidence.",
  "cases": [
    {"test_case": "cases/positive.json", "session": "sessions/example"}
  ]
}
```

Paths are resolved relative to the suite file, not the shell working directory.
Absolute paths are also accepted. The suite must be non-empty, with unique case
IDs and no duplicate entries. Unknown fields/versions are errors. A completed
session passport and events.json are required. Legacy sessions, unsupported
normalizer versions, unknown evidence IDs and inconsistent saved source profiles
are rejected before reports are written. A scenario.json is not required for
regression: this mode evaluates evidence, not scenario execution or correlation.
All sessions and cases are validated before either rule is evaluated.

### Comparison outcomes

| Outcome | Meaning |
| --- | --- |
| improved | Baseline not_met, candidate met |
| regressed | Baseline met, candidate not_met |
| unchanged_met | Both expectations met |
| unchanged_not_met | Both expectations not met |
| insufficient_data | Either evaluation lacks sufficient data |

If either side is insufficient, it is never labeled an improvement or regression.
Actual per-event decision changes remain visible even when expectation status is
unchanged or insufficient. Events outside selected evidence cannot satisfy a
case, but their changed decisions are shown separately as outside evidence.
V1 cases are supported with explicit not_assessed telemetry; prefer v2 for
telemetry-gated validation.

JSON includes exact rule text and SHA-256, suite and case definitions, canonical
JSON fingerprints of events/profiles/cases, engine/comparison versions, session
passports, all events and full per-rule checks. Cases sharing a session reuse the
same loaded data and per-rule results. Two directories declaring the same session
ID are rejected to avoid ambiguous evidence. Profile/engine changes are not
compared across historical runs by this command; both rules use the same saved
basis within the current run.

HTML preserves the five report sections, adds a case summary, and links selected
and changed events to cards containing both rules' field checks and conditions.
Search filters event cards only. Event anchors include the session ID, so equal
record IDs in different sessions do not collide.

### Executable synthetic example

The bundled files under `examples/regression` are explicitly synthetic; they do
not claim that a real attack or collection occurred. The example candidate
intentionally fixes one positive test and breaks one negative test. A third case
has a missing required telemetry field.

```powershell
.\dvp.exe --regression-suite .\examples\regression\suite.json `
    --baseline-rule .\examples\regression\baseline.yaml `
    --candidate-rule .\examples\regression\candidate.yaml
```

Expected summary: improved=1, regressed=1, insufficient_data=1, both unchanged
counts=0. YAML files in this example use JSON syntax, which is valid YAML.
For Linux use `.venv/bin/python -B main.py` followed by the same options and
forward-slash paths. Rebuild the Windows executable after source changes and
copy the example directory with it. No new Python dependency is required.


### Visual report review

All single-rule HTML reports (manual, automatic and replay) and regression HTML
reports share status badges, muted overview metadata, section headings and an
English legend. Match/Unmatch describe a rule decision; met/not_met describe the
test expectation. A negative test can therefore pass with Unmatch. Skipped and
insufficient_data remain distinct from failure. Labels accompany every color.

Expand **Rule evaluation** to inspect **Evaluation relationships**: actual field
value → expected value/check → check result, followed by named block results →
exact condition → event decision. These are recorded evaluation dependencies,
not causal process relationships. Full field checks and raw evidence remain
available. No external JavaScript, font, graph library or network is required.

Regression reports additionally show summary cards, structured rule differences,
per-case before/after assessments, telemetry status and event links. Each event
has **Baseline → Candidate: evaluation changes**, including changed field checks
when the final event decision stays the same. Paths are arrays of keys, preserving
literal dots in field names; `Absent` differs from JSON null. The console includes
a per-case table. Visual differences do not assert that one changed field alone
caused the final outcome. Existing JSON semantics and saved evidence are unchanged.

Rebuild the executable to distribute these changes. Existing HTML files retain
their original appearance; generate a new report to use the new presentation.


### Detection context and source provenance

New single-rule JSON reports include `Detection Context`; regression sessions
include `detection_context`. Both contain versioned nodes, edges, rule decisions,
source provenance, parent candidates and limitations. HTML section 3 shows only
matched events and their linked context. Regression includes matches from either
rule, including removed detections. Node links open the full evidence cards.

Connections require the same full host (case-insensitive), a valid nonzero GUID,
a unique eligible creation event and valid timestamps with parent no later than
child. Equal short host names in different domains do not establish identity.
PID-only relationships remain unconfirmed candidates, even if only one is found;
PID reuse cannot be excluded. Multiple GUID candidates are ambiguous. Cycles are
reported and the offending edge is omitted. A non-creation event with a configured
process GUID can link to its creation event as `process_event_context`, distinct
from parent ancestry. Missing context is explicitly unavailable. These links do
not prove attack causality or complete collection.

Profiles may declare optional `source_context` with `host_path` (array of keys)
and `ip_fields` (array of `{path, when}`). Each `when` is an AND-list of
`{path, equals}` predicates with exact value and type equality. Mappings must
identify the reporting host's address, not simply a remote endpoint. The bundled
Sysmon mapping reads SourceIp only for network events with Initiated equal to the
string "true". Security has no default IP mapping. No DNS lookup or destination
IP substitution occurs. Invalid addresses are excluded with a diagnostic.

Old sessions keep their saved profiles; new local settings are not retroactively
applied. Without the optional source mapping, the existing normalized `computer`
is shown and IP is unavailable. Without a process profile, no ancestry is guessed.
Original events, rule snapshots and analysis decisions are not rewritten.
Existing HTML reports need regeneration to display the new context.

Run the focused checks from the repository with:

```text
python -B scripts/check_detection_context.py
```

They cover ancestry, source address guards, process-event links, removed matches,
ambiguity, full host identity, time ordering, cycles, escaping, duplicate event IDs
and legacy profiles. No collection or Atomic execution is performed by these checks.


The detection diagram is collapsed behind **View detection graph** in section 3.
It uses an offline SVG with compact nodes and arrowed connections. Select a node
to show its separate details panel, then use **Open full event evidence** or
**Back to graph**. Blue nodes matched at least one rule; labels retain outcomes.
Solid edges show ancestry; dashed edges indicate process-event context. Large
forests scroll inside the diagram. The graph and selection use native HTML/CSS
and SVG links, with no JavaScript dependency. Original evidence is unchanged.


### Repeatable installer acceptance

Run the offline regression suite from the source checkout:

```powershell
.\.venv-win\Scripts\python.exe -B scripts/check_installation.py
```

The suite uses inert synthetic release/package fixtures and temporary targets.
It checks lifecycle behavior, failure recovery and preservation; it does not
build or certify Windows executables, download packages or execute Atomic tests.

On Windows, run regression plus real pinned module imports using the prepared cache:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
.\.venv-win\Scripts\python.exe -u -B scripts/check_setup_stage.py --cache .\.dvp-package-cache
```

The script prints the path to `report.json` and retains detailed logs in a new
`dvp-stage-acceptance-*` temporary directory. It does not alter Execution Policy.
Without a ready release it returns `needs_verification` (exit 3), even when the
regression suite and module imports pass. Skipped platform tests are recorded.

For full executable acceptance, add `--release-dir C:\path\to\ready-release`.
The verified release must contain both real `dvp.exe` and `dvp-setup.exe`.
The script checks install, repeat install, replay doctor, dry-run, uninstall and
repeat uninstall, preserving a synthetic evidence file. Only its newly created
temporary installation is removed. Source regression mocks and the real release
results are reported separately; an existing source tree is not a release.

Cache, release and target must be separate, non-nested directories. Doctor reports
installation lifecycle state separately from file integrity; failed or unfinished
post-install verification cannot be reported as a completed installation.


### Rule decision explanations

HTML event cards now show a short explanation and an expandable evidence chain
before the detailed evaluation tables. The chain reads from the event decision
through the exact condition and AND/OR/NOT nodes to named blocks and field checks.
It describes recorded evaluation dependencies, not process causality or the test
expectation verdict. Baseline and candidate evaluations use the same presentation.

The CLI shows the same model for visible evidence groups, with event IDs. Regression
CLI output includes up to 10 event explanations per rule per session and explicitly
reports omitted entries; all events remain available in HTML and report data.

Explanations use saved matcher results. Missing fields, null/empty values, failed
comparisons and unevaluated logsource mismatches remain distinct. List checks state
whether any or all expected values are required. Missing or inconsistent condition
trees in older reports produce an explicit incomplete-explanation message; the
renderer does not invent a reason or rerun the rule. Long values and large trees
are bounded in the compact view; original details remain available below.

No JSON schema or matching semantics changed. Existing static HTML files and already
built executables do not update automatically: regenerate reports with the updated
source and rebuild Windows executables when distributing the change.

Run the explanation regression tests:

```powershell
.\.venv-win\Scripts\python.exe -B scripts/check_explanations.py
```


### Windows rebuild and report acceptance

From a Windows source checkout, use an existing Python 3.12+ environment to run:

Before building or running Windows source/acceptance tests, run the policy command below in the **same PowerShell window**. Repeat it after opening a new window: `-Scope Process` applies only to that session and its child processes, not persistently to the machine. DVP does not change this setting automatically. Organizational Group Policy can take precedence; if scripts remain blocked, inspect `Get-ExecutionPolicy -List` and resolve the policy with the administrator. The inert source tests also load PowerShell scripts/modules, so they require a compatible policy even though no real Atomic tests run.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
.\.venv-win\Scripts\python.exe -u -B scripts/build_windows_acceptance.py --cache .\.dvp-package-cache --source-commit <reference-commit>
```

Use an administrative test shell to include the symlink tests. The PowerShell
module probe requires a compatible execution policy; the builder does not change
it. The verified cache must contain the two pinned YAML/ART module packages.
Internet access is needed for the separate build environment's pinned direct
PyInstaller/PyYAML/Rich dependencies; platform module preparation remains offline.

Each run creates a new `build/windows-<timestamp>-<suffix>` directory, isolates
build dependencies, records their installed versions, fingerprints source inputs
before building and rejects source changes during packaging. It builds both
executables, checks startup, packages an internal acceptance release and runs the
acceptance suite. The reference commit is a baseline, not a claim that local
changes were committed. This is not yet a fully locked production build.

The suite now includes 83 source tests, actual module imports, installation and
repeat installation, doctor, ordinary replay and regression using the installed
`dvp.exe`, and dry-run/uninstall/repeat uninstall. It validates explanation HTML,
CLI text, JSON decisions, NOT/filter and missing-field behavior, regression case
outcomes, and preservation of all generated report hashes after removal.

The ordinary and regression reports are copied to
`acceptance/application-reports/{ordinary,regression}.{html,json}`. The complete
machine-readable result is `acceptance/report.json`; overall build status is
`build-report.json`. Logs remain beside these artifacts and progress is printed
every 15 seconds during long build steps. A skipped source test results in
`needs_verification`, not a full pass. Live collection, Atomic execution and a
clean-machine online bootstrap are outside this acceptance scope.


CLI output redirected to files or pipes is explicitly configured as UTF-8 before
argument parsing and rendering, including frozen builds. Rich's legacy Windows
renderer is disabled for redirected stdout. Interactive terminal encoding is
preserved, with backslash escapes for unsupported characters. This prevents a
cp1252 UnicodeEncodeError on explanation arrows without changing HTML/JSON data.
The acceptance suite includes four stream/encoding regression tests.
