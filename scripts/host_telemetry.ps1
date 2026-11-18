param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$allowedChannels=@('Security','Microsoft-Windows-Sysmon/Operational')
$auditKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$auditValue='ProcessCreationIncludeCmdLine_Enabled'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TotenkahnAudit {
 [StructLayout(LayoutKind.Sequential)] public struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
 [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)]
 public static extern bool AuditQuerySystemPolicy(ref Guid category,uint count,out IntPtr policy);
 [DllImport("advapi32.dll")] public static extern void AuditFree(IntPtr buffer);
 public static uint Read() {
  Guid id=new Guid("0cce922b-69ae-11d9-bed3-505054503030"); IntPtr p;
  if(!AuditQuerySystemPolicy(ref id,1,out p)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  try { return ((Policy)Marshal.PtrToStructure(p,typeof(Policy))).Flags & 3; } finally { AuditFree(p); }
 }
}
'@

function Assert-SignedMicrosoft([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Executable missing'
    }
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)' -or
    $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft (Corporation|Windows)(,|$)') {
        throw 'Expected a valid Microsoft Authenticode signature'

    }
    return @{
        executable=$path
        sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()

        signer=$signature.SignerCertificate.Subject
        certificate=$signature.SignerCertificate.Thumbprint

        version=(Get-Item -LiteralPath $path).VersionInfo.FileVersion
    }

}
function Read-CommandLine {
    $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($auditKey)
    try {
        if ($null -eq $key -or $auditValue -notin $key.GetValueNames()) {
            return @{
                exists=$false
            }
        }
        return @{
            exists=$true
            kind=[string]$key.GetValueKind($auditValue)
            value=$key.GetValue($auditValue)
        }

    } finally {
        if ($key) {
            $key.Dispose()
        }
    }

}
function Get-HostObservation($channels) {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $principal=[Security.Principal.WindowsPrincipal]::new($identity)
    $machineKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Cryptography')
    try {
        $hostId=[string]$machineKey.GetValue('MachineGuid')
    } finally {
        $machineKey.Dispose()
    }
    $result=@{
        host_id=$hostId
        elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        channels=@{
        }
        sysmon=$null
        native_sysmon='Unknown'
        audit=$null
        command_line=$null
        errors=@{
        }
    }
    foreach ($name in $channels) {
        if ($name -notin $allowedChannels) {
            throw 'Unsupported event channel'
        }
        $entry=@{
            enabled=$null
            readable=$false
        }
        $config=$null
        $reader=$null
        $event=$null
        try {
            $config=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($name)
            $entry.enabled=[bool]$config.IsEnabled
            if ($entry.enabled) {
                $query=[Diagnostics.Eventing.Reader.EventLogQuery]::new($name,[Diagnostics.Eventing.Reader.PathType]::LogName,'*')
                $query.ReverseDirection=$true
                $reader=[Diagnostics.Eventing.Reader.EventLogReader]::new($query)
                $event=$reader.ReadEvent([TimeSpan]::FromSeconds(5))
                $entry.readable=$true

            }

        } catch {
            $entry.reason=$_.Exception.Message
        }
        finally {
            if ($event) {
                $event.Dispose()
            }
            if ($reader) {
                $reader.Dispose()
            }
            if ($config) {
                $config.Dispose()
            }
        }
        $result.channels[$name]=$entry

    }
    try {
        $result.audit=[int][TotenkahnAudit]::Read()
    } catch {
        $result.errors.audit=$_.Exception.Message
    }
    try {
        $result.command_line=Read-CommandLine
    } catch {
        $result.errors.command_line=$_.Exception.Message
    }
    try {
        $features=@(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object {
            $_.FeatureName -eq 'Sysmon'
        })
        $result.native_sysmon=if ($features.Count) {
            [string]$features[0].State
        } else {
            'Absent'
        }

    } catch {
        $result.errors.native_sysmon=$_.Exception.Message
    }
    try {
        $services=@(Get-CimInstance Win32_Service | Where-Object {
            $_.Name -like 'Sysmon*' -or $_.DisplayName -like '*Sysmon*' -or $_.PathName -match '(?i)sysmon(?:64a|64)?\.exe'
        })
        $drivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {
            $_.Name -like 'Sysmon*' -or $_.PathName -match '(?i)sysmon.*\.sys'
        })
        if ($services.Count -eq 0 -and $drivers.Count -gt 0) {
            throw 'Existing Sysmon driver without a recognized service must be preserved'
        }
        if ($services.Count -gt 1) {
            throw 'Multiple Sysmon services found'
        }
        if ($services.Count -eq 1) {
            $service=$services[0]
            $binary=$service.PathName.Trim()
            if ($binary.StartsWith('"')) {
                $binary=($binary -split '"')[1]
            }
            elseif ($binary -match '^(.*?\.exe)(?:\s|$)') {
                $binary=$Matches[1]
            }
            else {
                throw 'Unrecognized Sysmon service executable path'
            }
            $verified=Assert-SignedMicrosoft $binary
            $dump=(& $binary -c 2>&1 | ForEach-Object {
                [string]$_
            }) -join "`n"
            if ($LASTEXITCODE -ne 0 -or -not $dump.Trim()) {
                throw 'Cannot inspect active Sysmon configuration'
            }
            $sha=[Security.Cryptography.SHA256]::Create()
            try {
                $configHash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($dump.Trim())))).Replace('-','').ToLowerInvariant()
            }
            finally {
                $sha.Dispose()
            }
            $result.sysmon=@{
                name=$service.Name
                state=$service.State
                start_mode=$service.StartMode

                executable=$binary
                binary_sha256=$verified.sha256
                config_sha256=$configHash
            }

        }

    } catch {
        $result.errors.sysmon=$_.Exception.Message
    }
    return $result

}
function Resource($observation,[string]$key) {
    if ($key.StartsWith('channel:')) {
        return $observation.channels[$key.Substring(8)].enabled
    }
    return $observation[$key]

}
function Same($left,$right) {
    if ($null -eq $left -or $null -eq $right) {
        return $null -eq $left -and $null -eq $right
    }
    if ($left -is [System.Collections.IDictionary]) {
        $properties=@($right.PSObject.Properties.Name)
        if ($left.Count -ne $properties.Count) {
            return $false
        }
        foreach ($key in $left.Keys) {
            if ($key -notin $properties -or -not (Same $left[$key] $right.$key)) {
                return $false
            }
        }
        return $true

    }
    return $left -ceq $right

}
try {
    $request=Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($request.action -eq 'verify_package') {
        $architecture=$env:PROCESSOR_ARCHITEW6432
        if (-not $architecture) {
            $architecture=$env:PROCESSOR_ARCHITECTURE
        }
        $file=switch ($architecture) {
            'AMD64' {
                'Sysmon64.exe'
            } 'ARM64' {
                'Sysmon64a.exe'
            } 'x86' {
                'Sysmon.exe'
            } default {
                throw 'Unsupported architecture'
            }
        }
        $result=Assert-SignedMicrosoft (Join-Path $request.directory $file)
        $result.archive_sha256=$request.archive_sha256

    } elseif ($request.action -eq 'observe') {
        $result=Get-HostObservation $request.channels

    } elseif ($request.action -eq 'set') {
        $before=Get-HostObservation $request.channels
        if (-not $before.elevated) {
            throw 'Host changes require elevation'
        }
        $key=[string]$request.key
        if ($key -notin @('sysmon','audit','command_line','channel:Security','channel:Microsoft-Windows-Sysmon/Operational')) {
            throw 'Unsupported setting'
        }
        if (-not (Same (Resource $before $key) $request.before)) {
            throw 'Host setting changed after plan approval'
        }
        if ($key -eq 'sysmon') {
            if ($before.errors.sysmon) {
                throw 'Cannot establish Sysmon ownership'
            }
            $verified=Assert-SignedMicrosoft $request.executable
            if ($verified.sha256 -cne $request.executable_sha256) {
                throw 'Sysmon binary changed'
            }
            if ($request.desired -eq 'install_owned_profile') {
                if ($null -ne $before.sysmon -or $before.native_sysmon -notin @('Disabled','Absent')) {
                    throw 'Existing/native Sysmon must be preserved'
                }
                if ((Get-FileHash -LiteralPath $request.profile -Algorithm SHA256).Hash.ToLowerInvariant() -cne $request.profile_sha256) {
                    throw 'Sysmon profile changed'
                }
                $output=& $request.executable -accepteula -i $request.profile 2>&1

            } elseif ($null -eq $request.desired) {
                if ($null -eq $before.sysmon -or $before.sysmon.binary_sha256 -cne $verified.sha256) {
                    throw 'Sysmon ownership cannot be verified'
                }
                $output=& $request.executable -u 2>&1

            } else {
                throw 'Unsupported Sysmon change'
            }
            if ($LASTEXITCODE -ne 0) {
                throw "Sysmon operation failed: $output"
            }

        } elseif ($key -eq 'audit') {
            $flags=[int]$request.desired
            if ($flags -lt 0 -or $flags -gt 3) {
                throw 'Invalid audit flags'
            }
            $success=if ($flags -band 1) {
                'enable'
            } else {
                'disable'
            }
            $failure=if ($flags -band 2) {
                'enable'
            } else {
                'disable'
            }
            $output=& auditpol.exe /set '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}' "/success:$success" "/failure:$failure" 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Audit policy update failed: $output"
            }

        } elseif ($key -eq 'command_line') {
            $desired=$request.desired
            if ($desired.exists) {
                if ($desired.kind -cne 'DWord' -or $desired.value -isnot [int]) {
                    throw 'Expected a DWORD registry value'
                }
                $registry=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($auditKey)
                try {
                    $registry.SetValue($auditValue,$desired.value,[Microsoft.Win32.RegistryValueKind]::DWord)
                } finally {
                    $registry.Dispose()
                }

            } else {
                $registry=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($auditKey,$true)
                if ($registry) {
                    try {
                        $registry.DeleteValue($auditValue,$false)
                    } finally {
                        $registry.Dispose()
                    }
                }

            }

        } else {
            if ($request.desired -isnot [bool]) {
                throw 'Expected boolean channel state'
            }
            $config=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($key.Substring(8))
            try {
                $config.IsEnabled=$request.desired
                $config.SaveChanges()
            } finally {
                $config.Dispose()
            }

        }
        $result=Get-HostObservation $request.channels

    } else {
        throw 'Unsupported telemetry action'
    }
    [Console]::Out.WriteLine((@{
        status='passed'
        result=$result
    }|ConvertTo-Json -Depth 15 -Compress))

} catch {
    [Console]::Out.WriteLine((@{
        status='error'
        reason=$_.Exception.Message
    }|ConvertTo-Json -Compress))
    exit 1

}
