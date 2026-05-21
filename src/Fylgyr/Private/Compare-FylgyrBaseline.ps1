function Compare-FylgyrBaseline {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$BaselinePath,

        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [string]$Resource,

        [Parameter(Mandatory)]
        [object]$CurrentSnapshot
    )

    if (-not (Test-Path -Path $BaselinePath -PathType Leaf)) {
        throw "Baseline file not found: $BaselinePath"
    }

    $raw = Get-Content -Path $BaselinePath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Baseline file is empty: $BaselinePath"
    }

    try {
        $parsed = $raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse baseline JSON: $($_.Exception.Message)"
    }

    $baselineResults = if ($parsed -is [System.Array]) {
        @($parsed)
    }
    elseif ($parsed -and $parsed.PSObject.Properties['results']) {
        @($parsed.results)
    }
    elseif ($parsed) {
        @($parsed)
    }
    else {
        @()
    }

    $candidate = $null
    foreach ($result in $baselineResults) {
        if (-not $result) {
            continue
        }

        if (-not $result.PSObject.Properties['CheckName'] -or -not $result.PSObject.Properties['Resource']) {
            continue
        }

        if ($result.CheckName -ne $CheckName -or $result.Resource -ne $Resource) {
            continue
        }

        $candidate = $result
        break
    }

    if (-not $candidate) {
        return [PSCustomObject]@{
            HasBaseline       = $false
            IsChanged         = $true
            BaselineSnapshot  = $null
            CurrentSnapshot   = $CurrentSnapshot
            BaselineFingerprint = $null
            CurrentFingerprint  = $null
        }
    }

    $baselineSnapshot = $null
    if ($candidate.PSObject.Properties['Evidence'] -and $candidate.Evidence) {
        if ($candidate.Evidence.PSObject.Properties['To']) {
            $baselineSnapshot = $candidate.Evidence.To
        }
        elseif ($candidate.Evidence.PSObject.Properties['StateSnapshot']) {
            $baselineSnapshot = $candidate.Evidence.StateSnapshot
        }
        else {
            $baselineSnapshot = $candidate.Evidence
        }
    }

    if ($null -eq $baselineSnapshot) {
        return [PSCustomObject]@{
            HasBaseline       = $true
            IsChanged         = $true
            BaselineSnapshot  = $null
            CurrentSnapshot   = $CurrentSnapshot
            BaselineFingerprint = $null
            CurrentFingerprint  = $null
        }
    }

    $baselineDetail = ($baselineSnapshot | ConvertTo-Json -Depth 25 -Compress)
    $currentDetail = ($CurrentSnapshot | ConvertTo-Json -Depth 25 -Compress)

    $baselineFingerprint = Get-FylgyrFingerprint -Result ([PSCustomObject]@{
        CheckName = $CheckName
        Resource = $Resource
        Detail = $baselineDetail
    })
    $currentFingerprint = Get-FylgyrFingerprint -Result ([PSCustomObject]@{
        CheckName = $CheckName
        Resource = $Resource
        Detail = $currentDetail
    })

    return [PSCustomObject]@{
        HasBaseline         = $true
        IsChanged           = ($baselineFingerprint -ne $currentFingerprint)
        BaselineSnapshot    = $baselineSnapshot
        CurrentSnapshot     = $CurrentSnapshot
        BaselineFingerprint = $baselineFingerprint
        CurrentFingerprint  = $currentFingerprint
    }
}
