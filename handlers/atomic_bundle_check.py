import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile

from contextlib import ExitStack
from pathlib import Path

from handlers.component_inventory import (
    reject_duplicate_keys,
    reject_json_constant,
)
from handlers.package_cache import load_dependency_lock, obtain_package
from handlers.package_extract import prepare_zip_package

MODULE_PROBE = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$stage = 'execution_policy'
$policies = @()

try {
    $policies = @(Get-ExecutionPolicy -List | ForEach-Object {
        [pscustomobject]@{
            scope = [string]$_.Scope
            policy = [string]$_.ExecutionPolicy
        }
    })
    if ((Get-ExecutionPolicy) -eq 'Restricted') {
        [pscustomobject]@{
            status = 'blocked'
            scope = 'module_import_and_synthetic_parsing'
            category = 'execution_policy'
            stage = $stage
            reason = 'PowerShell execution policy prohibits module scripts'
            execution_policies = $policies
        } | ConvertTo-Json -Depth 8 -Compress
        exit 3
    }

    $requestJson = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($requestBase64)
    )
    $request = ConvertFrom-Json -InputObject $requestJson

    $stage = 'import_yaml_module'
    $yamlImported = @(
        Import-Module -Name $request.yaml_manifest `
            -PassThru -ErrorAction Stop `
            -WarningAction SilentlyContinue
    )
    $yamlModule = @(
        $yamlImported | Where-Object { $_.Name -eq 'powershell-yaml' }
    )

    if ($yamlModule.Count -ne 1) {
        throw 'Expected exactly one imported powershell-yaml module'
    }

    if ([string]$yamlModule[0].Version -ne $request.yaml_version) {
        throw 'Imported powershell-yaml version differs from the lock'
    }

    $expectedYamlRoot = Split-Path -Parent $request.yaml_manifest
    if ($yamlModule[0].ModuleBase -ine $expectedYamlRoot) {
        throw 'powershell-yaml was imported from an unexpected directory'
    }

    $stage = 'import_atomic_module'
    $artImported = @(
        Import-Module -Name $request.art_manifest `
            -PassThru -ErrorAction Stop `
            -WarningAction SilentlyContinue
    )
    $artModule = @(
        $artImported | Where-Object { $_.Name -eq 'Invoke-AtomicRedTeam' }
    )

    if ($artModule.Count -ne 1) {
        throw 'Expected exactly one imported Invoke-AtomicRedTeam module'
    }

    if ([string]$artModule[0].Version -ne $request.art_version) {
        throw 'Imported Invoke-AtomicRedTeam version differs from the lock'
    }

    $expectedArtRoot = Split-Path -Parent $request.art_manifest
    if ($artModule[0].ModuleBase -ine $expectedArtRoot) {
        throw 'Invoke-AtomicRedTeam was imported from an unexpected directory'
    }

    $invoke = $artModule[0].ExportedCommands['Invoke-AtomicTest']
    $reader = $artModule[0].ExportedCommands['Get-AtomicTechnique']

    if ($null -eq $invoke -or $null -eq $reader) {
        throw 'Required Atomic commands were not exported'
    }

    foreach ($parameter in @(
        'AtomicTechnique',
        'TestNumbers',
        'PathToAtomicsFolder',
        'LoggingModule',
        'ExecutionLogPath',
        'CheckPrereqs',
        'GetPrereqs',
        'Cleanup'
    )) {
        if (-not $invoke.Parameters.ContainsKey($parameter)) {
            throw "Required Invoke-AtomicTest parameter is missing: $parameter"
        }
    }

    if (-not $reader.Parameters.ContainsKey('Yaml')) {
        throw 'Get-AtomicTechnique does not support the Yaml parameter'
    }

    $stage = 'synthetic_yaml_parsing'
    $yamlText = @'
attack_technique: T0000
display_name: DVP synthetic parser fixture
atomic_tests:
  - name: DVP parser smoke check
    auto_generated_guid: 11111111-1111-4111-8111-111111111111
    description: Synthetic data for parser compatibility only.
    supported_platforms:
      - windows
    executor:
      name: manual
      steps: Read this synthetic description. No action is required.
'@
    $parseWarnings = @()
    $parsed = @(
        & $reader -Yaml $yamlText -ErrorAction Stop `
            -WarningAction SilentlyContinue -WarningVariable parseWarnings
    )
    if ($parsed.Count -ne 1 -or @($parsed[0].atomic_tests).Count -ne 1) {
        throw 'Synthetic document did not produce exactly one test'
    }
    if ($parsed[0].atomic_tests[0].executor.name -ne 'manual') {
        throw 'Synthetic executor was not parsed as manual'
    }

    [pscustomobject]@{
        status = 'passed'
        scope = 'module_import_and_synthetic_parsing'
        powershell_version = [string]$PSVersionTable.PSVersion
        yaml_version = [string]$yamlModule[0].Version
        art_version = [string]$artModule[0].Version
        synthetic_documents_checked = 1
        real_definitions_checked = 0
        execution_policies = $policies
        warnings = @($parseWarnings | ForEach-Object { [string]$_ })
    } | ConvertTo-Json -Depth 8 -Compress
    exit 0
}
catch {
    $record = $_
    $category = 'module_check_error'
    $status = 'error'
    $exitCode = 2
    $nativeCode = $record.Exception.HResult -band 65535

    if ($record.FullyQualifiedErrorId -match 'ScriptContainedMaliciousContent' `
        -or $nativeCode -in @(225, 226)) {
        $category = 'security_product_blocked'
        $status = 'blocked'
        $exitCode = 3
    }
    elseif ($record.Exception -is [System.Management.Automation.PSSecurityException]) {
        $category = 'powershell_security_policy'
        $status = 'blocked'
        $exitCode = 3
    }

    [pscustomobject]@{
        status = $status
        scope = 'module_import_and_synthetic_parsing'
        category = $category
        stage = $stage
        reason = [string]$record.Exception.Message
        error_id = [string]$record.FullyQualifiedErrorId
        exception_type = $record.Exception.GetType().FullName
        hresult = $record.Exception.HResult
        execution_policies = $policies
    } | ConvertTo-Json -Depth 8 -Compress
    exit $exitCode
}

"""

def find_single_file(root: Path, name: str) -> Path:
    matches = [
        path
        for path in root.rglob(name)
        if path.is_file()
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one {name}; found {len(matches)}"
        )

    return matches[0].resolve()

def check_atomic_bundle(
    lock_path: Path,
    cache_dir: Path,
    *,
    offline: bool = False,
    timeout_seconds: int = 180,
) -> dict:
    if sys.platform != "win32":
        raise ValueError("Atomic module compatibility check requires Windows")

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")

    powershell = shutil.which("powershell.exe")
    if powershell is None:
        raise ValueError("powershell.exe was not found")

    lock = load_dependency_lock(lock_path)
    packages = {
        package["component_id"]: package
        for package in lock["packages"]
    }

    required_ids = {
        "powershell_yaml",
        "invoke_atomic_red_team",
    }

    missing = required_ids - set(packages)
    if missing:
        raise ValueError(f"Missing locked Atomic packages: {sorted(missing)}")

    with tempfile.TemporaryDirectory(prefix="dvp-bundle-check-") as directory:
        work = Path(directory)

        with ExitStack() as stack:
            roots = {}

            for component_id in sorted(required_ids):
                package = packages[component_id]
                print(
                    f"Preparing package: {component_id}",
                    file=sys.stderr,
                    flush=True,
                )
                obtained = obtain_package(
                    package,
                    cache_dir,
                    offline=offline,
                )

                print(
                    f"Extracting package: {component_id}",
                    file=sys.stderr,
                    flush=True,
                )
                prepared = stack.enter_context(
                    prepare_zip_package(
                        Path(obtained["path"]),
                        package,
                        staging_parent=work,
                    )
                )

                roots[component_id] = Path(prepared["directory"])

            yaml_manifest = find_single_file(
                roots["powershell_yaml"],
                "powershell-yaml.psd1",
            )
            art_manifest = find_single_file(
                roots["invoke_atomic_red_team"],
                "Invoke-AtomicRedTeam.psd1",
            )

            private_config = art_manifest.parent.parent / "privateConfig.ps1"
            if private_config.exists():
                raise ValueError("Unexpected privateConfig.ps1 near staged ART")

            return check_module_paths(
                yaml_manifest, art_manifest, packages,
                timeout_seconds=timeout_seconds,
            )

def check_module_paths(yaml_manifest: Path, art_manifest: Path, packages: dict, *, timeout_seconds: int = 180) -> dict:
    if sys.platform != "win32":
        raise ValueError("Module import verification requires Windows")
    
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    
    powershell = shutil.which("powershell.exe")

    if powershell is None:
        raise ValueError("powershell.exe was not found")
    
    required_ids = {"powershell_yaml", "invoke_atomic_red_team"}

    if not required_ids.issubset(packages):
        raise ValueError("Both pinned modules are required")
    
    yaml_manifest = Path(yaml_manifest).resolve(strict=True)
    art_manifest = Path(art_manifest).resolve(strict=True)

    if (art_manifest.parent.parent / "privateConfig.ps1").exists():
        raise ValueError("Unexpected privateConfig.ps1 near ART module")
    
    request = {
        "yaml_manifest": str(yaml_manifest),
        "yaml_version": packages["powershell_yaml"]["version"],
        "art_manifest": str(art_manifest),
        "art_version": packages["invoke_atomic_red_team"]["version"],
    }

    payload = base64.b64encode(
        json.dumps(request, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")

    script = (
        "$requestBase64 = '" + payload + "'\n" + MODULE_PROBE
    )
    encoded = base64.b64encode(
        script.encode("utf-16le")
    ).decode("ascii")

    print(
        "Checking PowerShell modules and synthetic YAML",
        file=sys.stderr,
        flush=True,
    )
    completed = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )

    try:
        result = json.loads(
            completed.stdout.decode("utf-8-sig"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (ValueError, UnicodeError) as exc:
        stderr = completed.stderr.decode(
            "utf-8", errors="replace"
        ).strip()

        raise ValueError(
            f"Invalid PowerShell probe response: {stderr}"
        ) from exc

    if not isinstance(result, dict):
        raise ValueError("PowerShell probe must return a JSON object")

    expected_codes = {"passed": 0, "failed": 1, "error": 2, "blocked": 3}
    status = result.get("status")

    if not isinstance(status, str) or status not in expected_codes:
        raise ValueError("Unknown PowerShell probe status")

    if completed.returncode != expected_codes[status]:
        raise ValueError("PowerShell status and exit code disagree")

    result["packages"] = [
        {
            "component_id": component_id,
            "version": packages[component_id]["version"],
            "sha256": packages[component_id]["sha256"],
        }
        for component_id in sorted(required_ids)
    ]

    return result

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Check pinned Atomic modules without executing Atomic tests"
    )
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout", type=int, default=180)

    args = parser.parse_args(argv)

    try:
        report = check_atomic_bundle(
            args.lock,
            args.cache,
            offline=args.offline,
            timeout_seconds=args.timeout,
        )
    except (
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as exc:
        report = {
            "status": "error",
            "scope": "module_import_and_synthetic_parsing",
            "reason": str(exc),
            "category": "bundle_check_error",
        }
        
        winerror = getattr(exc, "winerror", None)
        if winerror in {225, 226}:
            report["status"] = "blocked"
            report["category"] = "security_product_blocked"
            report["winerror"] = winerror
        elif isinstance(exc, subprocess.TimeoutExpired):
            report["category"] = "probe_timeout"

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {"passed": 0, "failed": 1, "error": 2, "blocked": 3}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())