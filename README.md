# DVP

Detection Validation Platform for testing Sigma rules using Atomic Red Team and collected Windows events.

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

The current version collects events only from the first channel in `events.channels`.

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
