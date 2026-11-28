# Controlled delivery and rollback

This is the third CI/CD stage. It adds operator-controlled delivery of a complete Windows executable release. It does not publish a release, configure a service, deploy Sigma rules to Elastic/Splunk, change protection policies, migrate evidence, or certify live detection readiness.

The chain is: reviewed build run -> ZIP hash -> release manifest hash -> verified staged files -> Windows startup and five-stage offline acceptance -> operator approval -> active version. A failed delivery never automatically activates its candidate. Old versions and test evidence remain on disk.

SHA-256 detects changed bytes. It is not an authenticated publisher signature. Obtain the expected hashes from a reviewed build run, independently of the directory being installed. The local ledger is an operational record, not a tamper-proof chain of custody; users who can rewrite the store can also rewrite its receipts. Limit write access to authorized operators.

## 1. Build and review

Merge the delivery implementation only after source checks pass. Run the existing **TOTENKAHN Windows candidate** workflow from the reviewed source revision. Its artifact contains:

- `totenkahn-windows-candidate.zip`: the entire application release;
- `SHA256SUMS`: ZIP transport checksum;
- `RELEASE_SHA256SUMS`: checksum of `release-manifest.json`, also the delivery release ID;
- `delivery-review.json`: source reference, build/acceptance status and limitations;
- build, executable CI and acceptance reports.

Review warnings and the live test evidence for the intended deployment. `passed_with_warnings` remains a candidate with limitations; delivery does not silently upgrade it to fully accepted. The release manifest's `source_commit` is a reference revision; inspect `build-provenance.json` inside the release for local modifications. An offline receipt does not replace the stage-2 fresh Elastic test.

## 2. Transfer once

Download the candidate artifact. Copy the full extracted artifact directory to `C:\TotenkahnServer\incoming-delivery`. In PowerShell, compare the ZIP hash to the value from the reviewed workflow before extracting it:

```powershell
Get-FileHash -LiteralPath C:\TotenkahnServer\incoming-delivery\totenkahn-windows-candidate.zip -Algorithm SHA256
```

After comparing the hash, extract into a new directory. Do not overlay an older release:

```powershell
Expand-Archive -LiteralPath C:\TotenkahnServer\incoming-delivery\totenkahn-windows-candidate.zip -DestinationPath C:\TotenkahnServer\incoming-delivery\release
```

Provision `C:\TotenkahnServer\delivery-tools` with a **complete reviewed release containing the delivery feature**. This is a stable operator tool, not the active application slot. Keep it separate from the version store and do not overwrite it during promotion. Existing old setup executables do not understand `delivery`.

For the first setup only, when that directory does not already exist:

```powershell
Copy-Item -LiteralPath C:\TotenkahnServer\incoming-delivery\release -Destination C:\TotenkahnServer\delivery-tools -Recurse
```

Do not run any executable before reviewing its build provenance and comparing its trusted transport checksum. The delivery verifier then validates every release file against the expected manifest hash.

## 3. Stage and test

Replace `REVIEWED_MANIFEST_SHA256` with the 64 lowercase hexadecimal characters from the reviewed build's `RELEASE_SHA256SUMS`. It is not the ZIP hash. The examples use a fixed store so the CLI and runner see the same versions; execute both under the intended operator identity and preserve the same application data configuration.

```powershell
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery stage --root C:\TotenkahnServer\delivery-store --release-dir C:\TotenkahnServer\incoming-delivery\release --expected-sha256 REVIEWED_MANIFEST_SHA256
```

The printed `release_id` is that same hash. Stage verifies the source, copies to a unique temporary directory, verifies both source and copy, then renames the copy into `releases/<release_id>`. It never overwrites an existing slot. An interrupted copy may leave a `staging-*` directory for inspection; it is never selected as active.

```powershell
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery test --root C:\TotenkahnServer\delivery-store --release REVIEWED_MANIFEST_SHA256
```

Both executables must start successfully, and all five offline stages and all twenty named checks must pass. The test uses isolated application data. It imports no live data, executes no Atomic tests and makes no audit/protection changes. Logs, offline HTML/JSON and `receipt.json` remain under `delivery-store\tests\<id>`. The five-stage subprocess has a 600-second timeout, adjustable up to 3600 seconds. After an interrupted/timed-out test, inspect retained diagnostics before retrying; activation requires a successful stored receipt.

The verifier hashes the stored receipt, the offline report and command logs. It rechecks the executable release before and after testing. Starting another test invalidates the previous *pending* acceptance pointer; existing active approvals remain bound to their original receipts.

## 4. Explicit activation and ordinary use

Review the build limitations, local offline report and relevant live acceptance evidence, then approve:

```powershell
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery activate --root C:\TotenkahnServer\delivery-store --release REVIEWED_MANIFEST_SHA256 --reviewer Engineer --reason "Reviewed build limitations, offline report and live acceptance evidence" --yes
```

`-y` is equivalent to `--yes`. The approval reason is a human attestation, not an automatically verified live result. Activation atomically changes `state.json`; the previous active slot remains intact. Use the stable launcher to resolve the active release:

```powershell
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery status --root C:\TotenkahnServer\delivery-store
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery run --root C:\TotenkahnServer\delivery-store -- --help
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery run --root C:\TotenkahnServer\delivery-store -- dump profiles
```

The launcher verifies release integrity and accepted receipt before execution. Application arguments after `--` are forwarded unchanged. Existing `TOTENKAHN_HOME` is honored; otherwise the normal current-user data location is used. Data must remain outside the delivery store. Relative rule/input paths remain relative to the operator's current directory. A running command holds the delivery lock, so concurrent activation/rollback is rejected; retry after the command exits.

Running a version's `totenkahn.exe` directly bypasses active-version selection. Use `delivery run` when testing activation or rollback.

## 5. Rollback test

Rollback requires **two distinct accepted release IDs**. First stage, test and activate version A. Then repeat for a distinct reviewed build B. Verify that status reports active B and previous A. A first installation deliberately has no rollback target.

```powershell
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery rollback --root C:\TotenkahnServer\delivery-store --release PREVIOUS_REVIEWED_MANIFEST_SHA256 --reviewer Engineer --reason "Controlled rollback acceptance" --yes
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery status --root C:\TotenkahnServer\delivery-store
C:\TotenkahnServer\delivery-tools\totenkahn-setup.exe delivery run --root C:\TotenkahnServer\delivery-store -- --help
```

Expected: active A, previous B, both directories retained, original user evidence unchanged. Rollback re-verifies A and its original approval evidence. Corruption or missing evidence blocks rollback. A failed candidate test must leave A active.

Rollback only selects an executable version. It cannot undo data format migrations, audit changes, dependency preparation or Atomic effects. Only promote versions compatible with the existing data format; an application upgrade requiring data migration needs a separately reviewed migration/recovery plan. This stage adds no migrations or automatic cleanup of old releases.

## 6. Manual GitHub Actions delivery

Copy `examples/ci-workflows/controlled-delivery.yml` into `.github/workflows/controlled-delivery.yml` in the trusted lab repository. It uses the existing self-hosted runner labels and the fixed paths above. No Elastic secret or extra artifact-download token is required: the operator transfers the reviewed artifact first.

1. Run `stage-test` with the reviewed release ID. This does not activate.
2. Review local reports and build/live limitations.
3. Run `activate` separately with that ID and a meaningful review reason.
4. Once two versions are accepted, run `rollback` with the exact previous version ID.
5. Use `status` and the launcher to confirm the selected version.

The workflow is manual-only. Do not enable pull-request-triggered deployment to the lab runner. The initiating GitHub actor is recorded as reviewer. Repository write/workflow permissions control who can request delivery. The workflow uses a concurrency group and the local store lock. Results stay on the server; only a concise operation summary is written to GitHub.

## Acceptance boundary

Local source tests validate lifecycle behavior with inert executable adapters. The Windows build, actual packaged executable test, two-version activation/rollback, and stage-2 fresh Elastic candidate acceptance must still be performed on the lab server before calling this release-ready. Completion of implementation is not completion of those server tests.
