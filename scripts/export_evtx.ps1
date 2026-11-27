param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath
)

[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$reader = $null

try {
    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        $InputPath,
        [System.Diagnostics.Eventing.Reader.PathType]::FilePath
    )
    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)

    while ($null -ne ($record = $reader.ReadEvent())) {
        try {
            $row = @{ xml = $record.ToXml() }
            [Console]::Out.WriteLine(($row | ConvertTo-Json -Compress))
        }
        finally {
            $record.Dispose()
        }
    }
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
finally {
    if ($null -ne $reader) {
        $reader.Dispose()
    }
}
