# Versioned rule CI — stage 2

This is a controlled process-marker contract, not a general EDR detection benchmark. It tests a positive and a negative command-line event. The offline evidence is synthetic. The manual live workflow obtains new Elastic Endpoint process-start documents for the same controls.

## What is pinned

Both revisions must be full commit SHAs. `rule.yaml` is read from baseline and candidate Git objects. The suite, test cases, source profiles, mapping and gate limits come exclusively from the baseline commit. Working-tree edits and candidate changes to expectations are ignored. Evidence changes require separate review and promotion to a new baseline.

The offline suite uses already normalized saved-session fields (`data_fields.CommandLine`) and its source-profile snapshot. `mapping.json` is a separate reviewed bridge for live Elastic fields documents; it is validated and hashed, but does not remap the saved-session suite. An unknown source or missing/unsupported rule field produces `needs_verification`; the raw comparison is provisional. This is deliberately conservative even if another branch of the rule could decide the result.

Candidate rules are parsed as YAML data. Candidate Python, PowerShell and workflow files are not executed by the revision gate. The hosted workflow runs the engine from the reviewed baseline. Only a passing gate produces `live-bundle`.

## Run locally

From the source repository, with Git and project Python dependencies installed:

```bash
.venv/bin/python -B scripts/run_rule_ci.py --repo . --baseline BASELINE_FULL_SHA --candidate CANDIDATE_FULL_SHA --output-dir /tmp/totenkahn-rule-check-01
```

Replace both SHA placeholders. Use a new output directory on each run. The same command is available as `totenkahn ci revisions` in a newly built executable; Git is still required for this development operation.

Outputs: `report.json`, `index.html`, immutable `baseline-inputs`, `candidate.yaml`, the existing detailed CI HTML/JSON/JUnit reports under `evaluation`, and a live bundle only on PASS. The top-level report is authoritative when `evaluation_provisional` is true. It contains both commit IDs, Git blob IDs, SHA-256 of inputs, engine source hashes, dependency versions and the detailed evaluation hash. Exit codes follow the platform status table: PASS 0, rejected candidate 1, execution error 2, verification needed 3.

## Bootstrap and activate the PR workflow

1. Merge this infrastructure using the existing source CI first. The new regression tests run in that CI.
2. Record the resulting full main commit SHA. This is the first reviewed baseline containing the engine and the contract.
3. Copy `examples/ci-workflows/rule-revisions.yml` to `.github/workflows/rule-revisions.yml` in the **Totenkahn source repository**, then commit/push it. This sequencing avoids trying to run a baseline engine or contract that does not exist yet.
4. Manually dispatch once with baseline and candidate equal to the reviewed commit. Expect PASS.
5. Create a rule-only PR. The workflow uses `pull_request.base.sha` and `pull_request.head.sha`, not GitHub's temporary merge commit. It runs on a hosted Ubuntu runner without Elastic secrets or endpoint actions.
6. Review actual reports before making this check required in branch protection. Protect changes to the baseline policy/workflow as infrastructure changes; a PR can modify its own workflow definition, so a green check alone is not a substitute for review.

For a controlled failed PR, change `_POSITIVE` to `_NEVER_EXECUTED` in `rule.yaml`: expect one regression. To test a false positive, change the condition to `selection`: the negative control must fail. Restore the rule afterwards. Changes to test expectations in the candidate must not hide either regression.

Do not add `pull_request_target`, repository secrets or a self-hosted runner to this PR workflow.

## Manual live workflow in the existing lab repository

After the infrastructure baseline is merged:

1. Copy `examples/ci-workflows/elastic-live-revisions.yml` to `.github/workflows/elastic-live-revisions.yml` in **SizovAnton/totenkahn-lab-ci**. Keep the existing successful stage-1 workflow for comparison.
2. Preserve the existing Elastic variables, API-key secret, local CA and portable curl paths. No TLS bypass or protection changes are required.
3. `TOTENKAHN_RULE_REPOSITORY` defaults to `SizovAnton/totenkahn`. If that source repository is private, set `TOTENKAHN_RULES_READ_TOKEN` in the lab repository to a fine-grained token with read-only Contents access to that source repository. The lab repository's normal token cannot read an unrelated private repository. No new token is needed for a public source repository.
4. Run the workflow from reviewed `main`, with full baseline and candidate SHAs from the source repository. The baseline supplies executable validator code; review it before authorizing the manual run. Do not use an unreviewed baseline.
5. The hosted job first evaluates frozen evidence and packages only reviewed rules, mapping and the baseline validator. A failed offline gate prevents any lab action.
6. The lab job verifies bundle hashes and uses the existing local `totenkahn.exe`. It creates two bounded `cmd.exe /d /c echo` actions, receives fresh telemetry and runs the five stages. No Atomic commands are involved. A core executable rebuild is not required for this workflow.
7. Download the hosted offline report from Actions. Live telemetry and detailed reports stay in `C:\TotenkahnServer\ci-runs\live-revisions-RUN_ID-ATTEMPT` and the adjacent ZIP; these are not uploaded to GitHub.

The live archive records `rule-revisions.json`, `live-provenance.json`, executable and transport hashes, API requests/responses and decision reports. The validator helper is hashed in the reviewed bundle. On acquisition failure, `acquisition-failure.json` distinguishes authentication, authorization, transport, partial response, missing/ambiguous evidence and identity/time mismatches. Detection is `not_evaluated`, never a false negative. Failures before acquisition starts may have only step logs.

This live contract expects two marked process-start events and a baseline that matches only the positive control. It is not suitable for an arbitrary unrelated rule without a separately reviewed scenario/contract. The original API envelope is preserved; the workflow extracts fields documents for the current executable. Elastic alert firing and deploying rules to SIEM are outside this stage.

## Negative tests

`check_rule_revisions.py` creates isolated Git repositories and verifies immutable snapshots, regressions, false positives, ignored candidate expectations, missing/invalid rules, invalid revisions, unknown fields/sources and invalid evidence paths.

`check_elastic_ci.py` feeds controlled HTTP responses and documents to the exact PowerShell validator used by the live workflow. It covers success, 401/403/503, connection/TLS errors, timeout, malformed JSON, failed shards, inexact/truncated counts, missing/extra events, wrong host/PID/source/marker, ambiguous fields, stale/invalid timestamps, duplicate/missing identities and unsuccessful actions. It does not disable the real Elastic server or revoke a real key. These are validator tests, not a real network-outage drill or proof of Windows performance.

## Completion boundary

Local source/contract checks are development validation. Acceptance requires a hosted PR run with a good and regressed candidate plus a manual Windows live run with the pinned rules. After that stage 2 can be accepted; stage 3 is reviewed delivery/CD, rollback and final acceptance. No push, merge, deployment or live workflow is performed by preparing these files.
