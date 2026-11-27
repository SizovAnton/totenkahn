function Stop-ElasticEvidence {
    param([string]$Category, [string]$Reason)
    $failure = [InvalidOperationException]::new($Reason)
    $failure.Data['category'] = $Category
    $failure.Data['detection'] = 'not_evaluated'
    throw $failure
}

function Read-ElasticSearchResponse {
    param([int]$CurlExit, [string]$HttpCode, [string]$Body)
    if ($CurlExit -eq 28) { Stop-ElasticEvidence 'transport_timeout' 'HTTPS request timed out.' }
    if ($CurlExit -ne 0) { Stop-ElasticEvidence 'transport_error' 'HTTPS transport failed; inspect local diagnostics.' }
    if ($HttpCode -eq '401') { Stop-ElasticEvidence 'authentication_failed' 'API key is invalid or expired.' }
    if ($HttpCode -eq '403') { Stop-ElasticEvidence 'authorization_failed' 'API key cannot read the reviewed index.' }
    if ($HttpCode -ne '200') { Stop-ElasticEvidence 'http_error' ('Unexpected HTTP status: ' + $HttpCode) }
    try { $response = ConvertFrom-Json -InputObject $Body -ErrorAction Stop }
    catch { Stop-ElasticEvidence 'invalid_response' 'Search response is not valid JSON.' }
    if ($null -eq $response -or $response -is [Array] -or $null -eq $response.hits) {
        Stop-ElasticEvidence 'invalid_response' 'Search response has no hits object.'
    }
    if ($response.timed_out -isnot [bool] -or $response.timed_out -or $null -eq $response._shards.failed -or $response._shards.failed -ne 0 -or $response._shards.total -lt 1) {
        Stop-ElasticEvidence 'partial_response' 'Search timed out, is incomplete, or has failed shards.'
    }
    if ($response.hits.total.relation -ne 'eq' -or $null -eq $response.hits.total.value -or $response.hits.total.value -lt 0 -or $response.hits.hits -isnot [Array]) {
        Stop-ElasticEvidence 'inexact_count' 'Exact hit count and a hits array are required.'
    }
    return $response
}

function Get-ElasticScalar {
    param($Document, [string]$Name)
    if ($null -eq $Document.fields) { Stop-ElasticEvidence 'missing_field' 'Document has no fields object.' }
    $values = @($Document.fields.$Name)
    if ($values.Count -ne 1 -or $null -eq $values[0] -or $values[0] -is [Array] -or $values[0] -is [System.Management.Automation.PSCustomObject] -or [string]::IsNullOrWhiteSpace([string]$values[0])) {
        Stop-ElasticEvidence 'missing_or_ambiguous_field' ('Expected one usable value for ' + $Name)
    }
    return $values[0]
}

function Select-ElasticEvidence {
    param($Response, [object[]]$Actions, [string]$HostId, [string]$Start, [string]$End)
    $hits = @($Response.hits.hits)
    if ($Response.hits.total.value -ne $hits.Count) { Stop-ElasticEvidence 'truncated_response' 'Search result was truncated.' }
    if ($hits.Count -lt 2) { Stop-ElasticEvidence 'missing_events' 'Both controlled events are required; detection is not evaluated.' }
    if ($hits.Count -ne 2) { Stop-ElasticEvidence 'extra_events' 'Extra events cannot be silently discarded.' }
    if ($Actions.Count -ne 2 -or $Actions[0].marker -eq $Actions[1].marker) { Stop-ElasticEvidence 'invalid_actions' 'Two distinct reviewed actions are required.' }
    try {
        $startTime = [DateTimeOffset]::Parse($Start)
        $endTime = [DateTimeOffset]::Parse($End)
    }
    catch { Stop-ElasticEvidence 'invalid_window' 'Invalid execution window.' }
    if ($startTime -gt $endTime) { Stop-ElasticEvidence 'invalid_window' 'Execution window is reversed.' }
    $ordered = @()
    $references = @()
    foreach ($action in $Actions) {
        if ($action.exit_code -ne 0 -or $action.marker -notmatch '^TOTENKAHN_LIVE_[a-f0-9]{32}_(POSITIVE|NEGATIVE)$') {
            Stop-ElasticEvidence 'invalid_actions' 'Control action did not succeed or has an invalid marker.'
        }
        $matching = @($hits | Where-Object { ([string](Get-ElasticScalar $_ 'process.command_line')).Contains($action.marker) })
        if ($matching.Count -ne 1) { Stop-ElasticEvidence 'marker_mismatch' 'Marker is missing or ambiguous.' }
        $hit = $matching[0]
        foreach ($pair in @(@('host.id', $HostId), @('host.os.type', 'windows'), @('event.category', 'process'), @('event.type', 'start'), @('event.dataset', 'endpoint.events.process'))) {
            if ((Get-ElasticScalar $hit $pair[0]) -cne $pair[1]) { Stop-ElasticEvidence 'source_mismatch' ('Unexpected source identity: ' + $pair[0]) }
        }
        if ((Get-ElasticScalar $hit 'process.pid') -ne $action.pid) { Stop-ElasticEvidence 'pid_mismatch' 'Event PID does not match the launched process.' }
        $timestamp = Get-ElasticScalar $hit '@timestamp'
        try { $eventTime = [DateTimeOffset]::Parse($timestamp) }
        catch { Stop-ElasticEvidence 'invalid_time' 'Event timestamp is invalid.' }
        if ($eventTime -lt $startTime -or $eventTime -gt $endTime) { Stop-ElasticEvidence 'stale_event' 'Event lies outside the execution window.' }
        if ([string]::IsNullOrWhiteSpace($hit._id) -or [string]::IsNullOrWhiteSpace($hit._index)) { Stop-ElasticEvidence 'missing_identity' 'Document identity is absent.' }
        $ordered += $hit
        $references += @{ imported_row=$ordered.Count; index=$hit._index; document_id=$hit._id; marker=$action.marker; pid=$action.pid }
    }
    if ($ordered[0]._id -eq $ordered[1]._id -and $ordered[0]._index -eq $ordered[1]._index) { Stop-ElasticEvidence 'duplicate_identity' 'Both events reference the same document.' }
    return @{documents=$ordered; references=$references}
}
