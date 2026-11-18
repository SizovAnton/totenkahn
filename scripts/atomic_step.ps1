param([Parameter(Mandatory = $true)][string]$RequestPath)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
try {
    $request = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($request.executor -notin @('powershell','command_prompt')) {
        throw 'Unsupported executor'
    }
    if ($request.timeout_seconds -lt 1 -or $request.timeout_seconds -gt 3600) {
        throw 'Invalid timeout'
    }
    $elevated = $false
    if ($request.elevation_required) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    }
    if ($request.elevation_required -and -not $elevated) {
        [Console]::Out.WriteLine('{"status":"blocked","reason":"Selected test requires elevation","exit_code":null}')
        exit 1

    }
    $privateConfig = Join-Path (Split-Path (Split-Path $request.module_path -Parent) -Parent) 'privateConfig.ps1'
    if (Test-Path -LiteralPath $privateConfig) {
        throw 'Unexpected ART privateConfig.ps1'
    }
    Import-Module -Name $request.yaml_module_path -ErrorAction Stop *> 'yaml-import.log'
    Import-Module -Name $request.module_path -ErrorAction Stop *> 'art-import.log'
    $module = Get-Module | Where-Object {
        $_.Path -eq $request.module_path -or $_.ModuleBase -eq (Split-Path $request.module_path -Parent)
    } | Select-Object -First 1
    if ($null -eq $module) {
        throw 'Imported ART module not found'
    }
    $startedAt = [DateTime]::UtcNow.ToString("o")
    $res = & $module {
        param($r)
        Invoke-ExecuteCommand $r.command $r.executor 'windows' $r.timeout_seconds $null $false

    } $request
    if ($null -eq $res -or $null -eq $res.ExitCode) {
        throw 'Executor did not return an exit code'
    }
    $res.StandardOutput | Out-File -LiteralPath 'command.stdout.txt' -Encoding UTF8
    $res.ErrorOutput | Out-File -LiteralPath 'command.stderr.txt' -Encoding UTF8
    $status = 'failed'
    if ($res.IsTimeout) {
        $status = 'timeout'
    }
    elseif ($res.ExitCode -eq 0) {
        $status = 'passed'
    }
    $result = @{
        status=$status
        exit_code=[int]$res.ExitCode
        process_id=$res.ProcessId
        timed_out=[bool]$res.IsTimeout
        started_at=$startedAt
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
    if ($status -eq 'passed') {
        exit 0
    } else {
        exit 1
    }

}
catch {
    $result = @{
        status='blocked'
        reason=$_.Exception.Message
        exit_code=$null
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
    exit 1

}
